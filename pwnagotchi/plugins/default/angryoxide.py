import logging
import os
import re
import subprocess
import signal
import time
import glob
import shutil
from threading import Lock

import pwnagotchi.plugins as plugins
import pwnagotchi.ui.faces as faces
from pwnagotchi.ui.components import LabeledValue
from pwnagotchi.ui.view import BLACK
import pwnagotchi.ui.fonts as fonts


class AngryOxide(plugins.Plugin):
    __author__ = 'pwnagotchi'
    __version__ = '0.3.0'
    __license__ = 'GPL3'
    __description__ = 'Integrates AngryOxide as the attack engine, replacing bettercap deauth/assoc with AO PMKID/CSA/deauth attacks.'
    __name__ = 'angryoxide'
    __help__ = """
    Runs AngryOxide alongside bettercap. Bettercap handles recon (AP/client discovery),
    while AngryOxide handles all active attacks (PMKID, CSA, deauth) on the shared
    monitor interface. Requires a nexmon-patched AO binary for brcmfmac chips.

    When nexmon_mode is enabled (default for brcmfmac), injection is throttled to
    ~2 frames/sec and channel dwell is increased to prevent firmware crashes.
    The plugin can auto-detect brcmfmac and suggest nexmon_mode if not already set.
    """

    # Firmware crash signature: -110 errors from brcmfmac channel set failures
    _FW_CRASH_PATTERN = re.compile(r'brcmf.*Set Channel failed.*-110|brcmf.*firmware has halted', re.IGNORECASE)

    def __init__(self):
        self.options = dict()
        self._lock = Lock()
        self._process = None
        self._running = False
        self._captures = 0
        self._known_files = {}  # {filepath: mtime}
        self._original_deauth = None
        self._original_associate = None
        self._is_brcmfmac = None
        self._fw_crash_count = 0
        self._last_recovery = 0
        # backoff state
        self._crash_count = 0
        self._last_crash_time = 0
        self._stopped_permanently = False
        self._base_backoff_secs = 5
        # adaptive throttle state
        self._current_injection_delay = None
        self._stable_epochs = 0
        # pi_helper firmware hit counters (optional, for smarter adaptive throttle)
        self._last_fatal_errors = 0
        self._last_hard_faults = 0

    def _detect_brcmfmac(self):
        """Check if the wifi interface uses the brcmfmac driver (nexmon-patchable)."""
        iface = self.options.get('interface', 'wlan0mon')
        # strip 'mon' suffix to get base interface
        base_iface = iface.replace('mon', '')
        driver_path = '/sys/class/net/%s/device/driver' % base_iface
        try:
            if os.path.islink(driver_path):
                driver_name = os.path.basename(os.readlink(driver_path))
                self._is_brcmfmac = (driver_name == 'brcmfmac')
                logging.info("[angryoxide] detected driver: %s (brcmfmac=%s)", driver_name, self._is_brcmfmac)
                return self._is_brcmfmac
        except Exception as e:
            logging.debug("[angryoxide] could not detect driver: %s", e)
        # also check the monitor interface directly
        mon_driver_path = '/sys/class/net/%s/device/driver' % iface
        try:
            if os.path.islink(mon_driver_path):
                driver_name = os.path.basename(os.readlink(mon_driver_path))
                self._is_brcmfmac = (driver_name == 'brcmfmac')
                logging.info("[angryoxide] detected driver via mon iface: %s (brcmfmac=%s)", driver_name, self._is_brcmfmac)
                return self._is_brcmfmac
        except Exception as e:
            logging.debug("[angryoxide] could not detect driver via mon iface: %s", e)
        self._is_brcmfmac = False
        return False

    def on_loaded(self):
        binary = self.options.get('binary_path', '/usr/local/bin/angryoxide')
        if not os.path.isfile(binary):
            logging.warning("[angryoxide] binary not found at %s - plugin will not start until binary is installed", binary)
            return

        # auto-detect brcmfmac and warn if nexmon_mode is off
        is_brcm = self._detect_brcmfmac()
        nexmon_mode = self.options.get('nexmon_mode', True)
        if is_brcm and not nexmon_mode:
            logging.warning("[angryoxide] brcmfmac detected but nexmon_mode is disabled! "
                            "This will likely crash the firmware. Enable nexmon_mode in config.")

        logging.info("[angryoxide] plugin loaded, binary found at %s", binary)

    def on_ready(self, agent):
        binary = self.options.get('binary_path', '/usr/local/bin/angryoxide')
        if not os.path.isfile(binary):
            logging.error("[angryoxide] binary not found at %s, cannot start", binary)
            return

        # disable bettercap's attacks — AO takes over
        self._original_deauth = agent._config['personality']['deauth']
        self._original_associate = agent._config['personality']['associate']
        agent._config['personality']['deauth'] = False
        agent._config['personality']['associate'] = False
        logging.info("[angryoxide] disabled bettercap deauth/assoc, AO will handle attacks")

        self._start_ao(agent)

    def _build_cmd(self):
        binary = self.options.get('binary_path', '/usr/local/bin/angryoxide')
        iface = self.options.get('interface', 'wlan0mon')
        output_dir = self.options.get('output_dir', '/etc/pwnagotchi/handshakes/')
        notx = self.options.get('notx', False)
        nexmon_mode = self.options.get('nexmon_mode', True)
        channel_dwell = self.options.get('channel_dwell_ms', 5000)
        extra_args = self.options.get('extra_args', '')

        # adaptive throttle overrides configured injection delay
        if self._current_injection_delay is not None:
            injection_delay = self._current_injection_delay
        else:
            injection_delay = self.options.get('injection_delay_ms', 500)

        cmd = [binary, '--interface', iface, '--headless', '--output', output_dir]

        if notx:
            cmd.append('--notx')

        if nexmon_mode:
            cmd.extend(['--nexmon-mode',
                         '--injection-delay-ms', str(injection_delay),
                         '--channel-dwell-ms', str(channel_dwell)])

        if extra_args:
            cmd.extend(extra_args.split())

        return cmd

    def _start_ao(self, agent):
        with self._lock:
            if self._running:
                return

            output_dir = self.options.get('output_dir', '/etc/pwnagotchi/handshakes/')
            os.makedirs(output_dir, exist_ok=True)

            # snapshot existing pcapng files with mtimes so we don't double-count
            self._known_files = {}
            for f in glob.glob(os.path.join(output_dir, '*.pcapng')):
                try:
                    self._known_files[f] = os.path.getmtime(f)
                except OSError:
                    pass

            cmd = self._build_cmd()
            logging.info("[angryoxide] starting: %s", ' '.join(cmd))

            try:
                self._process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    preexec_fn=os.setsid
                )
                self._running = True
                logging.info("[angryoxide] started with PID %d", self._process.pid)
            except Exception as e:
                logging.error("[angryoxide] failed to start: %s", e)
                self._running = False

    def _stop_ao(self):
        with self._lock:
            if self._process and self._running:
                logging.info("[angryoxide] stopping AO (PID %d)", self._process.pid)
                try:
                    pgid = os.getpgid(self._process.pid)
                    os.killpg(pgid, signal.SIGTERM)
                    self._process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    logging.warning("[angryoxide] AO did not stop gracefully, sending SIGKILL")
                    try:
                        os.killpg(pgid, signal.SIGKILL)
                        self._process.wait(timeout=5)
                    except ProcessLookupError:
                        logging.debug("[angryoxide] process already exited before SIGKILL")
                    except Exception as e:
                        logging.error("[angryoxide] error during SIGKILL: %s", e)
                except ProcessLookupError:
                    logging.debug("[angryoxide] process already exited before SIGTERM")
                except Exception as e:
                    logging.error("[angryoxide] error stopping AO: %s", e)
                finally:
                    self._process = None
                    self._running = False

    def _backoff_seconds(self):
        """Calculate exponential backoff: min(5 * 2^(crashes-1), 300)."""
        return min(self._base_backoff_secs * (2 ** (self._crash_count - 1)), 300)

    def _read_fw_counters(self):
        """Read firmware hit counters from pi_helper (if available on port 8888).
        Returns (fatal_errors_blocked, hard_faults_caught) or None if unavailable.

        Known RAM addresses:
          0x03C094: fatal errors blocked count (4 bytes, little-endian)
          0x03C098: hard faults caught count (4 bytes, little-endian)
        """
        try:
            import urllib.request
            import struct

            base_url = 'http://127.0.0.1:8888/api/v1/memory/read'
            counters = []
            for addr in (0x03C094, 0x03C098):
                url = '%s?addr=0x%06X&size=4' % (base_url, addr)
                req = urllib.request.Request(url, method='GET')
                with urllib.request.urlopen(req, timeout=2) as resp:
                    raw = resp.read()
                    # pi_helper returns raw bytes
                    if len(raw) >= 4:
                        counters.append(struct.unpack('<I', raw[:4])[0])
                    else:
                        return None
            return tuple(counters)
        except Exception:
            return None

    def _check_health(self, agent):
        """Check if AO process is still alive, restart if crashed."""
        needs_restart = False
        with self._lock:
            if not self._running:
                return
            if self._process and self._process.poll() is not None:
                rc = self._process.returncode
                logging.warning("[angryoxide] AO process died with exit code %d", rc)
                self._process = None
                self._running = False
                needs_restart = True

        if needs_restart:
            now = time.time()
            self._crash_count += 1
            self._last_crash_time = now
            self._stable_epochs = 0

            max_crashes = self.options.get('max_crashes', 10)
            if self._crash_count >= max_crashes:
                logging.error("[angryoxide] reached max crash count (%d), stopping permanently. "
                              "Use webhook POST /plugins/angryoxide/reset to retry.", max_crashes)
                self._stopped_permanently = True
                return

            # adaptive throttle: increase delay by 50% on crash
            if self.options.get('adaptive_throttle', False):
                delay_max = self.options.get('delay_max', 2000)
                if self._current_injection_delay is None:
                    self._current_injection_delay = self.options.get('injection_delay_ms', 500)
                self._current_injection_delay = min(int(self._current_injection_delay * 1.5), delay_max)
                logging.info("[angryoxide] adaptive throttle: increased injection delay to %d ms", self._current_injection_delay)

            # check if this looks like a firmware crash before restarting
            recovery_ok = True
            if self._is_brcmfmac:
                recovery_ok = self._try_fw_recovery()

            if not recovery_ok:
                logging.error("[angryoxide] firmware recovery failed, not restarting")
                return

            backoff = self._backoff_seconds()
            logging.info("[angryoxide] restarting after %.1fs backoff (crash %d/%d)", backoff, self._crash_count, max_crashes)
            time.sleep(backoff)
            self._start_ao(agent)

    def _try_fw_recovery(self):
        """Detect and recover from brcmfmac firmware crashes (-110 channel set errors).
        Returns True if recovery succeeded or was not needed, False otherwise."""
        now = time.time()
        # don't attempt recovery more than once per 60 seconds
        if now - self._last_recovery < 60:
            return True

        try:
            result = subprocess.run(
                ['journalctl', '-n', '20', '-k', '--no-pager'],
                capture_output=True, text=True, timeout=5
            )
            if self._FW_CRASH_PATTERN.search(result.stdout):
                self._fw_crash_count += 1
                self._last_recovery = now
                logging.warning("[angryoxide] firmware crash detected (count: %d), attempting brcmfmac recovery",
                                self._fw_crash_count)
                iface = self.options.get('interface', 'wlan0mon')
                try:
                    subprocess.run(['monstop'], timeout=10, capture_output=True)
                    time.sleep(1)
                    subprocess.run(['sudo', 'modprobe', '-r', 'brcmfmac'], timeout=10, capture_output=True)
                    time.sleep(2)
                    subprocess.run(['sudo', 'modprobe', 'brcmfmac'], timeout=10, capture_output=True)
                    time.sleep(3)
                    subprocess.run(['monstart'], timeout=10, capture_output=True)
                    logging.info("[angryoxide] brcmfmac recovery completed, verifying interface")

                    # poll for interface to come back
                    for attempt in range(5):
                        time.sleep(2)
                        if os.path.exists('/sys/class/net/%s' % iface):
                            logging.info("[angryoxide] interface %s is back (attempt %d)", iface, attempt + 1)
                            return True
                    logging.error("[angryoxide] interface %s did not come back after recovery", iface)
                    return False
                except Exception as e:
                    logging.error("[angryoxide] firmware recovery failed: %s", e)
                    return False
        except Exception as e:
            logging.debug("[angryoxide] could not check kernel logs: %s", e)
        return True

    def _is_whitelisted(self, filename, whitelist):
        """Check if a capture filename matches any whitelist entry.
        Mirrors utils.remove_whitelisted normalization: lowercase, alphanumeric-only, substring match."""
        def normalize(name):
            return ''.join(c for c in name if c.isalnum()).lower()

        # strip both .pcapng and .pcap extensions
        base = filename
        if base.endswith('.pcapng'):
            base = base[:-7]
        elif base.endswith('.pcap'):
            base = base[:-5]
        normalized = normalize(base)

        for entry in whitelist:
            if normalize(entry) in normalized:
                return True
        return False

    def _scan_captures(self, agent):
        """Check for new or modified pcapng files from AO and trigger handshake events."""
        output_dir = self.options.get('output_dir', '/etc/pwnagotchi/handshakes/')
        handshake_dir = agent._config['bettercap']['handshakes']
        whitelist = agent._config.get('main', {}).get('whitelist', [])

        current_files = {}
        for f in glob.glob(os.path.join(output_dir, '*.pcapng')):
            try:
                current_files[f] = os.path.getmtime(f)
            except OSError:
                pass

        # detect new files and files with updated mtime
        new_or_modified = []
        for filepath, mtime in current_files.items():
            if filepath not in self._known_files or mtime > self._known_files[filepath]:
                new_or_modified.append(filepath)

        # filter against whitelist
        if whitelist:
            new_or_modified = [f for f in new_or_modified
                               if not self._is_whitelisted(os.path.basename(f), whitelist)]

        for filepath in new_or_modified:
            is_new = filepath not in self._known_files
            if is_new:
                self._captures += 1
            filename = os.path.basename(filepath)
            logging.info("[angryoxide] %s capture: %s (total: %d)",
                         "new" if is_new else "updated", filename, self._captures)

            # copy to pwnagotchi handshake dir if different from AO output
            dest = filepath
            if os.path.abspath(output_dir) != os.path.abspath(handshake_dir):
                dest = os.path.join(handshake_dir, filename)
                try:
                    shutil.copy2(filepath, dest)
                except Exception as e:
                    logging.error("[angryoxide] failed to copy capture to %s: %s", dest, e)
                    dest = filepath

            # trigger handshake event for downstream plugins (wigle, wpa-sec, pwncrack)
            ap_mac, sta_mac = self._parse_capture_filename(filename)
            plugins.on('handshake', agent, dest, ap_mac, sta_mac)

            # register in agent handshake tracking for display/mood
            if is_new:
                key = "%s -> %s" % (sta_mac, ap_mac)
                if key not in agent._handshakes:
                    agent._handshakes[key] = {'source': 'angryoxide', 'file': dest}
                agent._last_pwnd = ap_mac

        # update display and trigger mood if we got new captures
        if new_or_modified:
            new_count = sum(1 for f in new_or_modified if f not in self._known_files)
            if new_count > 0:
                agent._update_handshakes(new_count)

        self._known_files = current_files

    @staticmethod
    def _parse_capture_filename(filename):
        """Try to extract AP MAC from AO capture filename. Returns (ap_mac, sta_mac) strings."""
        # AO uses format like: AA-BB-CC-DD-EE-FF_NetworkName.pcapng
        base = filename.replace('.pcapng', '')
        parts = base.split('_', 1)
        if parts and len(parts[0].split('-')) == 6:
            ap_mac = parts[0].replace('-', ':')
            return ap_mac, 'unknown'
        return 'unknown', 'unknown'

    def on_epoch(self, agent, epoch, epoch_data):
        if self._stopped_permanently:
            return

        if not self._running and os.path.isfile(self.options.get('binary_path', '/usr/local/bin/angryoxide')):
            # try to start if not running yet (e.g. binary was installed after boot)
            self._start_ao(agent)
            return

        self._check_health(agent)
        self._scan_captures(agent)

        # adaptive throttle: tune injection delay based on stability and firmware counters
        if self._running and self.options.get('adaptive_throttle', False):
            self._stable_epochs += 1
            delay_min = self.options.get('delay_min', 100)
            delay_max = self.options.get('delay_max', 2000)

            # check pi_helper firmware counters for proactive backoff
            fw_counters = self._read_fw_counters()
            if fw_counters is not None:
                fatal_errors, hard_faults = fw_counters
                fatal_delta = fatal_errors - self._last_fatal_errors
                hard_fault_delta = hard_faults - self._last_hard_faults
                self._last_fatal_errors = fatal_errors
                self._last_hard_faults = hard_faults

                if fatal_delta > 0:
                    # fatal error counter is climbing — back off harder (double the delay)
                    if self._current_injection_delay is None:
                        self._current_injection_delay = self.options.get('injection_delay_ms', 500)
                    old_delay = self._current_injection_delay
                    self._current_injection_delay = min(int(self._current_injection_delay * 2.0), delay_max)
                    self._stable_epochs = 0
                    logging.warning("[angryoxide] adaptive throttle: firmware fatal errors climbing "
                                    "(+%d, total %d), increased injection delay %d -> %d ms",
                                    fatal_delta, fatal_errors, old_delay, self._current_injection_delay)
                elif hard_fault_delta > 0:
                    # hard faults increasing — moderate backoff (50% increase)
                    if self._current_injection_delay is None:
                        self._current_injection_delay = self.options.get('injection_delay_ms', 500)
                    old_delay = self._current_injection_delay
                    self._current_injection_delay = min(int(self._current_injection_delay * 1.5), delay_max)
                    self._stable_epochs = 0
                    logging.info("[angryoxide] adaptive throttle: firmware hard faults climbing "
                                 "(+%d, total %d), increased injection delay %d -> %d ms",
                                 hard_fault_delta, hard_faults, old_delay, self._current_injection_delay)

            # decrease delay after sustained stability (no crashes, no firmware counter spikes)
            if self._stable_epochs >= 20 and self._current_injection_delay is not None:
                new_delay = max(int(self._current_injection_delay * 0.9), delay_min)
                if new_delay != self._current_injection_delay:
                    self._current_injection_delay = new_delay
                    logging.info("[angryoxide] adaptive throttle: decreased injection delay to %d ms (stable for %d epochs)",
                                 self._current_injection_delay, self._stable_epochs)

        # reset crash count after 5 minutes of stability
        if self._crash_count > 0 and self._last_crash_time > 0:
            if time.time() - self._last_crash_time > 300:
                logging.info("[angryoxide] stable for 5+ minutes, resetting crash count (was %d)", self._crash_count)
                self._crash_count = 0

    def on_ui_setup(self, ui):
        with ui._lock:
            pos = self.options.get('position', None)
            if pos:
                pos = [int(x.strip()) for x in pos.split(',')]
            else:
                pos = (ui.width() / 2 + 35, ui.height() - 11)
            ui.add_element('angryoxide', LabeledValue(
                color=BLACK,
                label='AO:',
                value='...',
                position=pos,
                label_font=fonts.Bold,
                text_font=fonts.Medium
            ))

    def on_ui_update(self, ui):
        with ui._lock:
            if self._stopped_permanently:
                ui.set('angryoxide', 'ERR')
            elif self._running:
                ui.set('angryoxide', '%d' % self._captures)
            else:
                ui.set('angryoxide', 'off')

    def on_webhook(self, path, request):
        from flask import jsonify

        if request.method == 'GET' and path in ('/', '/status', ''):
            fw_counters = self._read_fw_counters()
            return jsonify({
                'running': self._running,
                'pid': self._process.pid if self._process else None,
                'captures': self._captures,
                'crash_count': self._crash_count,
                'fw_crash_count': self._fw_crash_count,
                'injection_delay_ms': self._current_injection_delay or self.options.get('injection_delay_ms', 500),
                'stable_epochs': self._stable_epochs,
                'is_brcmfmac': self._is_brcmfmac,
                'stopped_permanently': self._stopped_permanently,
                'fw_fatal_errors_blocked': fw_counters[0] if fw_counters else None,
                'fw_hard_faults_caught': fw_counters[1] if fw_counters else None,
            })

        if request.method == 'GET' and path == '/captures':
            # return last 50 tracked files with mtimes
            items = sorted(self._known_files.items(), key=lambda x: x[1], reverse=True)[:50]
            return jsonify([{'file': os.path.basename(f), 'mtime': mt} for f, mt in items])

        if request.method == 'POST' and path == '/reset':
            self._stopped_permanently = False
            self._crash_count = 0
            logging.info("[angryoxide] reset via webhook, will retry on next epoch")
            return jsonify({'status': 'ok', 'message': 'crash state reset'})

        return jsonify({'error': 'not found'}), 404

    def on_unload(self, ui):
        self._stop_ao()

        # restore bettercap attack settings
        # agent not available in on_unload, but the config is shared
        # next epoch will use restored values
        if self._original_deauth is not None or self._original_associate is not None:
            logging.info("[angryoxide] plugin unloaded, bettercap attacks will resume on next restart")

        with ui._lock:
            try:
                ui.remove_element('angryoxide')
            except Exception:
                pass
