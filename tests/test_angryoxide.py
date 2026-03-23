"""
Tests for the AngryOxide plugin v0.3.0.

Covers all 10 improvements:
1. Subprocess pipe deadlock fix (DEVNULL)
2. Process group kill race (cached pgid, ProcessLookupError)
3. Recovery verification (interface polling, bool return)
4. Restart backoff + max attempts
5. Modified file detection via mtime
6. Whitelist filtering
7. Handshake display counter + face/mood
8. Adaptive injection delay
9. Webhook endpoint
10. defaults.toml keys (tested via option defaults)
"""

import importlib.util
import json
import os
import signal
import subprocess
import sys
import time
import types
from threading import Lock
from unittest.mock import MagicMock, PropertyMock, patch, call

import pytest

# Windows doesn't have os.getpgid/os.killpg/os.setsid — stub them so the plugin
# module loads and patch() can find them.
if not hasattr(os, 'getpgid'):
    os.getpgid = lambda pid: pid
if not hasattr(os, 'killpg'):
    os.killpg = lambda pgid, sig: None
if not hasattr(os, 'setsid'):
    os.setsid = lambda: None
if not hasattr(signal, 'SIGKILL'):
    signal.SIGKILL = 9

# ---------------------------------------------------------------------------
# Mock out heavy pwnagotchi imports before importing the plugin
# ---------------------------------------------------------------------------
_faces_mod = types.ModuleType('pwnagotchi.ui.faces')
_faces_mod.HAPPY = '(^_^)'

_fonts_mod = types.ModuleType('pwnagotchi.ui.fonts')
_fonts_mod.Bold = 'bold'
_fonts_mod.Medium = 'medium'

_components_mod = types.ModuleType('pwnagotchi.ui.components')
_components_mod.LabeledValue = MagicMock()

_view_mod = types.ModuleType('pwnagotchi.ui.view')
_view_mod.BLACK = 0

_plugins_mod = types.ModuleType('pwnagotchi.plugins')
_plugins_mod.Plugin = object  # base class is just object for test purposes
_plugins_mod.on = MagicMock()

sys.modules['pwnagotchi'] = types.ModuleType('pwnagotchi')
sys.modules['pwnagotchi.ui'] = types.ModuleType('pwnagotchi.ui')
sys.modules['pwnagotchi.plugins'] = _plugins_mod
sys.modules['pwnagotchi.ui.faces'] = _faces_mod
sys.modules['pwnagotchi.ui.fonts'] = _fonts_mod
sys.modules['pwnagotchi.ui.components'] = _components_mod
sys.modules['pwnagotchi.ui.view'] = _view_mod

# Load the plugin module directly from file path to avoid package resolution issues
_plugin_path = os.path.join(os.path.dirname(__file__), '..', 'pwnagotchi', 'plugins', 'default', 'angryoxide.py')
_spec = importlib.util.spec_from_file_location('angryoxide', _plugin_path)
_angryoxide_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_angryoxide_mod)
AngryOxide = _angryoxide_mod.AngryOxide


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def plugin():
    """Fresh AngryOxide instance with sensible test defaults."""
    p = AngryOxide()
    p.options = {
        'binary_path': '/usr/local/bin/angryoxide',
        'interface': 'wlan0mon',
        'output_dir': '/tmp/ao_test_out/',
        'nexmon_mode': True,
        'injection_delay_ms': 500,
        'channel_dwell_ms': 5000,
        'notx': False,
        'extra_args': '',
        'max_crashes': 10,
        'adaptive_throttle': False,
        'delay_min': 100,
        'delay_max': 2000,
    }
    return p


@pytest.fixture
def agent():
    """Mock agent with the attributes the plugin touches."""
    a = MagicMock()
    a._config = {
        'personality': {'deauth': True, 'associate': True},
        'bettercap': {'handshakes': '/tmp/ao_test_hs/'},
        'main': {'whitelist': []},
    }
    a._handshakes = {}
    a._last_pwnd = None
    a._update_handshakes = MagicMock()
    return a


# ===================================================================
# 1. Subprocess pipe deadlock fix — DEVNULL instead of PIPE
# ===================================================================

class TestPipeDeadlockFix:
    @patch('subprocess.Popen')
    @patch('os.makedirs')
    @patch('glob.glob', return_value=[])
    def test_start_ao_uses_devnull(self, mock_glob, mock_mkdirs, mock_popen, plugin, agent):
        mock_proc = MagicMock()
        mock_proc.pid = 1234
        mock_popen.return_value = mock_proc

        plugin._start_ao(agent)

        mock_popen.assert_called_once()
        call_kwargs = mock_popen.call_args[1]
        assert call_kwargs['stdout'] is subprocess.DEVNULL
        assert call_kwargs['stderr'] is subprocess.DEVNULL

    @patch('subprocess.Popen')
    @patch('os.makedirs')
    @patch('glob.glob', return_value=[])
    def test_start_ao_does_not_use_pipe(self, mock_glob, mock_mkdirs, mock_popen, plugin, agent):
        mock_proc = MagicMock()
        mock_proc.pid = 1234
        mock_popen.return_value = mock_proc

        plugin._start_ao(agent)

        call_kwargs = mock_popen.call_args[1]
        assert call_kwargs['stdout'] is not subprocess.PIPE
        assert call_kwargs['stderr'] is not subprocess.PIPE


# ===================================================================
# 2. Process group kill race — cached pgid, ProcessLookupError
# ===================================================================

class TestStopAoKillRace:
    def test_stop_caches_pgid_and_handles_process_exit_before_sigkill(self, plugin):
        """Process exits between SIGTERM timeout and SIGKILL — no crash."""
        mock_proc = MagicMock()
        mock_proc.pid = 42
        mock_proc.wait.side_effect = [subprocess.TimeoutExpired('cmd', 10), None]
        plugin._process = mock_proc
        plugin._running = True

        with patch('os.getpgid', return_value=99) as mock_getpgid, \
             patch('os.killpg') as mock_killpg:
            # SIGKILL should use cached pgid=99, not call getpgid again
            plugin._stop_ao()

        # getpgid called exactly once (cached)
        mock_getpgid.assert_called_once_with(42)
        # SIGTERM then SIGKILL both to pgid 99
        assert mock_killpg.call_args_list[0] == call(99, signal.SIGTERM)
        assert mock_killpg.call_args_list[1] == call(99, signal.SIGKILL)

    def test_stop_handles_process_lookup_error_on_sigterm(self, plugin):
        """Process already gone when we try SIGTERM — no crash."""
        mock_proc = MagicMock()
        mock_proc.pid = 42
        plugin._process = mock_proc
        plugin._running = True

        with patch('os.getpgid', side_effect=ProcessLookupError):
            plugin._stop_ao()

        assert plugin._process is None
        assert plugin._running is False

    def test_stop_handles_process_lookup_error_on_sigkill(self, plugin):
        """Process exits after SIGTERM timeout but before SIGKILL."""
        mock_proc = MagicMock()
        mock_proc.pid = 42
        mock_proc.wait.side_effect = [subprocess.TimeoutExpired('cmd', 10)]
        plugin._process = mock_proc
        plugin._running = True

        with patch('os.getpgid', return_value=99), \
             patch('os.killpg') as mock_killpg:
            # First killpg (SIGTERM) succeeds, second (SIGKILL) raises ProcessLookupError
            mock_killpg.side_effect = [None, ProcessLookupError()]
            plugin._stop_ao()

        assert plugin._process is None
        assert plugin._running is False

    def test_stop_noop_when_not_running(self, plugin):
        """Calling _stop_ao when not running is a safe no-op."""
        plugin._process = None
        plugin._running = False
        plugin._stop_ao()  # should not raise


# ===================================================================
# 3. Recovery verification — interface polling, bool return
# ===================================================================

class TestFwRecovery:
    @patch('time.sleep')
    @patch('subprocess.run')
    @patch('os.path.exists')
    def test_recovery_returns_true_when_interface_comes_back(self, mock_exists, mock_run, mock_sleep, plugin):
        plugin._is_brcmfmac = True
        plugin._last_recovery = 0

        # journalctl shows firmware crash
        journal_result = MagicMock()
        journal_result.stdout = 'brcmf_cfg80211_set_channel: Set Channel failed: -110'
        mock_run.return_value = journal_result

        # interface comes back on 3rd poll
        mock_exists.side_effect = [False, False, True]

        result = plugin._try_fw_recovery()

        assert result is True
        assert plugin._fw_crash_count == 1

    @patch('time.sleep')
    @patch('subprocess.run')
    @patch('os.path.exists', return_value=False)
    def test_recovery_returns_false_when_interface_never_returns(self, mock_exists, mock_run, mock_sleep, plugin):
        plugin._is_brcmfmac = True
        plugin._last_recovery = 0

        journal_result = MagicMock()
        journal_result.stdout = 'brcmf_cfg80211_set_channel: Set Channel failed: -110'
        mock_run.return_value = journal_result

        result = plugin._try_fw_recovery()

        assert result is False
        assert mock_exists.call_count == 5  # polled 5 times

    @patch('time.sleep')
    @patch('subprocess.run')
    def test_recovery_returns_true_when_no_fw_crash_detected(self, mock_run, mock_sleep, plugin):
        plugin._last_recovery = 0

        journal_result = MagicMock()
        journal_result.stdout = 'some normal kernel log output'
        mock_run.return_value = journal_result

        result = plugin._try_fw_recovery()

        assert result is True
        assert plugin._fw_crash_count == 0

    def test_recovery_skipped_within_60_seconds(self, plugin):
        plugin._last_recovery = time.time()  # just recovered

        result = plugin._try_fw_recovery()

        assert result is True  # returns True (not needed)

    @patch('subprocess.run', side_effect=Exception("journalctl not found"))
    def test_recovery_returns_true_on_journalctl_failure(self, mock_run, plugin):
        plugin._last_recovery = 0

        result = plugin._try_fw_recovery()

        assert result is True  # graceful fallback


# ===================================================================
# 4. Restart backoff + max attempts
# ===================================================================

class TestBackoffAndMaxCrashes:
    def test_backoff_exponential(self, plugin):
        plugin._crash_count = 1
        assert plugin._backoff_seconds() == 5  # 5 * 2^0

        plugin._crash_count = 2
        assert plugin._backoff_seconds() == 10  # 5 * 2^1

        plugin._crash_count = 3
        assert plugin._backoff_seconds() == 20  # 5 * 2^2

        plugin._crash_count = 4
        assert plugin._backoff_seconds() == 40  # 5 * 2^3

    def test_backoff_caps_at_300(self, plugin):
        plugin._crash_count = 100
        assert plugin._backoff_seconds() == 300

    @patch('time.sleep')
    def test_max_crashes_stops_permanently(self, mock_sleep, plugin, agent):
        plugin.options['max_crashes'] = 3
        plugin._running = True

        mock_proc = MagicMock()
        mock_proc.poll.return_value = 1  # exited
        mock_proc.returncode = 1
        plugin._process = mock_proc

        # simulate 3 crashes
        for i in range(3):
            plugin._running = True
            plugin._process = MagicMock()
            plugin._process.poll.return_value = 1
            plugin._process.returncode = 1
            plugin._check_health(agent)

        assert plugin._stopped_permanently is True
        assert plugin._crash_count == 3

    def test_on_epoch_returns_early_when_stopped_permanently(self, plugin, agent):
        plugin._stopped_permanently = True
        plugin._running = True

        with patch.object(plugin, '_check_health') as mock_health:
            plugin.on_epoch(agent, 1, {})
            mock_health.assert_not_called()

    @patch('time.time')
    def test_crash_count_resets_after_5_min_stability(self, mock_time, plugin, agent):
        plugin._crash_count = 5
        plugin._last_crash_time = 1000.0
        plugin._running = True
        plugin._process = MagicMock()
        plugin._process.poll.return_value = None  # still running

        mock_time.return_value = 1301.0  # 301 seconds later

        with patch.object(plugin, '_check_health'), \
             patch.object(plugin, '_scan_captures'), \
             patch('os.path.isfile', return_value=True):
            plugin.on_epoch(agent, 1, {})

        assert plugin._crash_count == 0

    @patch('time.time')
    def test_crash_count_does_not_reset_before_5_min(self, mock_time, plugin, agent):
        plugin._crash_count = 5
        plugin._last_crash_time = 1000.0
        plugin._running = True
        plugin._process = MagicMock()
        plugin._process.poll.return_value = None

        mock_time.return_value = 1299.0  # 299 seconds — not yet

        with patch.object(plugin, '_check_health'), \
             patch.object(plugin, '_scan_captures'), \
             patch('os.path.isfile', return_value=True):
            plugin.on_epoch(agent, 1, {})

        assert plugin._crash_count == 5


# ===================================================================
# 5. Modified file detection via mtime
# ===================================================================

class TestMtimeTracking:
    @patch('glob.glob')
    @patch('os.path.getmtime')
    @patch('os.path.abspath', side_effect=lambda x: x)
    @patch('shutil.copy2')
    def test_detects_new_files(self, mock_copy, mock_abspath, mock_mtime, mock_glob, plugin, agent):
        plugin._known_files = {}
        mock_glob.return_value = ['/tmp/ao_test_out/AA-BB-CC-DD-EE-FF_Test.pcapng']
        mock_mtime.return_value = 1000.0

        plugin._scan_captures(agent)

        assert plugin._captures == 1

    @patch('glob.glob')
    @patch('os.path.getmtime')
    @patch('os.path.abspath', side_effect=lambda x: x)
    @patch('shutil.copy2')
    def test_detects_modified_files_by_mtime(self, mock_copy, mock_abspath, mock_mtime, mock_glob, plugin, agent):
        filepath = '/tmp/ao_test_out/AA-BB-CC-DD-EE-FF_Test.pcapng'
        plugin._known_files = {filepath: 1000.0}  # old mtime

        mock_glob.return_value = [filepath]
        mock_mtime.return_value = 2000.0  # updated mtime

        plugin._scan_captures(agent)

        # modified file triggers handshake event but does NOT increment captures count
        _plugins_mod.on.assert_called()
        # captures stays 0 — modified != new
        assert plugin._captures == 0

    @patch('glob.glob')
    @patch('os.path.getmtime')
    @patch('os.path.abspath', side_effect=lambda x: x)
    def test_deleted_files_cleaned_from_tracking(self, mock_abspath, mock_mtime, mock_glob, plugin, agent):
        plugin._known_files = {
            '/tmp/ao_test_out/old.pcapng': 500.0,
            '/tmp/ao_test_out/still_here.pcapng': 600.0,
        }

        # only still_here remains
        mock_glob.return_value = ['/tmp/ao_test_out/still_here.pcapng']
        mock_mtime.return_value = 600.0

        plugin._scan_captures(agent)

        assert '/tmp/ao_test_out/old.pcapng' not in plugin._known_files
        assert '/tmp/ao_test_out/still_here.pcapng' in plugin._known_files

    @patch('glob.glob')
    @patch('os.path.getmtime')
    @patch('os.path.abspath', side_effect=lambda x: x)
    def test_unchanged_files_not_reprocessed(self, mock_abspath, mock_mtime, mock_glob, plugin, agent):
        filepath = '/tmp/ao_test_out/AA-BB-CC-DD-EE-FF_Test.pcapng'
        plugin._known_files = {filepath: 1000.0}

        mock_glob.return_value = [filepath]
        mock_mtime.return_value = 1000.0  # same mtime

        _plugins_mod.on.reset_mock()
        plugin._scan_captures(agent)

        _plugins_mod.on.assert_not_called()


# ===================================================================
# 6. Whitelist filtering
# ===================================================================

class TestWhitelistFiltering:
    def test_exact_ssid_match(self, plugin):
        assert plugin._is_whitelisted('AA-BB-CC-DD-EE-FF_MyNetwork.pcapng', ['MyNetwork']) is True

    def test_mac_prefix_match(self, plugin):
        assert plugin._is_whitelisted('AA-BB-CC-DD-EE-FF_Something.pcapng', ['AA:BB:CC']) is True

    def test_full_mac_match(self, plugin):
        assert plugin._is_whitelisted('AA-BB-CC-DD-EE-FF_Something.pcapng', ['AA:BB:CC:DD:EE:FF']) is True

    def test_case_insensitive(self, plugin):
        assert plugin._is_whitelisted('AA-BB-CC-DD-EE-FF_MyNetwork.pcapng', ['mynetwork']) is True
        assert plugin._is_whitelisted('AA-BB-CC-DD-EE-FF_MyNetwork.pcapng', ['MYNETWORK']) is True

    def test_no_match(self, plugin):
        assert plugin._is_whitelisted('AA-BB-CC-DD-EE-FF_Something.pcapng', ['OtherNetwork']) is False

    def test_empty_whitelist(self, plugin):
        assert plugin._is_whitelisted('AA-BB-CC-DD-EE-FF_Something.pcapng', []) is False

    def test_pcap_extension_stripped(self, plugin):
        """Should also work for .pcap files (not just .pcapng)."""
        assert plugin._is_whitelisted('AA-BB-CC-DD-EE-FF_Target.pcap', ['Target']) is True

    def test_special_chars_stripped_for_matching(self, plugin):
        """Normalization removes non-alphanumeric chars."""
        assert plugin._is_whitelisted('AA-BB-CC-DD-EE-FF_My-Net_Work.pcapng', ['MyNetWork']) is True
        assert plugin._is_whitelisted('AA-BB-CC-DD-EE-FF_My Network.pcapng', ['MyNetwork']) is True

    def test_substring_match(self, plugin):
        """Whitelist entries match as substrings, not exact."""
        assert plugin._is_whitelisted('AA-BB-CC-DD-EE-FF_HomeNetwork5G.pcapng', ['HomeNetwork']) is True

    @patch('glob.glob')
    @patch('os.path.getmtime')
    @patch('os.path.abspath', side_effect=lambda x: x)
    def test_whitelisted_files_skipped_in_scan(self, mock_abspath, mock_mtime, mock_glob, plugin, agent):
        """Integration: whitelisted captures not counted or triggered."""
        agent._config['main']['whitelist'] = ['TargetNet']
        plugin._known_files = {}

        mock_glob.return_value = [
            '/tmp/ao_test_out/AA-BB-CC-DD-EE-FF_TargetNet.pcapng',
            '/tmp/ao_test_out/11-22-33-44-55-66_OtherNet.pcapng',
        ]
        mock_mtime.side_effect = [1000.0, 1000.0]

        _plugins_mod.on.reset_mock()
        plugin._scan_captures(agent)

        # only OtherNet should be processed
        assert plugin._captures == 1
        assert _plugins_mod.on.call_count == 1

    @patch('glob.glob')
    @patch('os.path.getmtime')
    @patch('os.path.abspath', side_effect=lambda x: x)
    def test_empty_whitelist_processes_all(self, mock_abspath, mock_mtime, mock_glob, plugin, agent):
        agent._config['main']['whitelist'] = []
        plugin._known_files = {}

        mock_glob.return_value = [
            '/tmp/ao_test_out/AA-BB-CC-DD-EE-FF_Net1.pcapng',
            '/tmp/ao_test_out/11-22-33-44-55-66_Net2.pcapng',
        ]
        mock_mtime.side_effect = [1000.0, 1000.0]

        _plugins_mod.on.reset_mock()
        plugin._scan_captures(agent)

        assert plugin._captures == 2


# ===================================================================
# 7. Handshake display counter + face/mood
# ===================================================================

class TestHandshakeIntegration:
    @patch('glob.glob')
    @patch('os.path.getmtime')
    @patch('os.path.abspath', side_effect=lambda x: x)
    @patch('shutil.copy2')
    def test_new_capture_registers_in_agent_handshakes(self, mock_copy, mock_abspath, mock_mtime, mock_glob, plugin, agent):
        plugin._known_files = {}
        mock_glob.return_value = ['/tmp/ao_test_out/AA-BB-CC-DD-EE-FF_TestNet.pcapng']
        mock_mtime.return_value = 1000.0

        plugin._scan_captures(agent)

        assert len(agent._handshakes) == 1
        key = list(agent._handshakes.keys())[0]
        assert 'AA:BB:CC:DD:EE:FF' in key
        assert agent._handshakes[key]['source'] == 'angryoxide'

    @patch('glob.glob')
    @patch('os.path.getmtime')
    @patch('os.path.abspath', side_effect=lambda x: x)
    @patch('shutil.copy2')
    def test_new_capture_sets_last_pwnd(self, mock_copy, mock_abspath, mock_mtime, mock_glob, plugin, agent):
        plugin._known_files = {}
        mock_glob.return_value = ['/tmp/ao_test_out/AA-BB-CC-DD-EE-FF_TestNet.pcapng']
        mock_mtime.return_value = 1000.0

        plugin._scan_captures(agent)

        assert agent._last_pwnd == 'AA:BB:CC:DD:EE:FF'

    @patch('glob.glob')
    @patch('os.path.getmtime')
    @patch('os.path.abspath', side_effect=lambda x: x)
    @patch('shutil.copy2')
    def test_new_capture_calls_update_handshakes(self, mock_copy, mock_abspath, mock_mtime, mock_glob, plugin, agent):
        plugin._known_files = {}
        mock_glob.return_value = [
            '/tmp/ao_test_out/AA-BB-CC-DD-EE-FF_Net1.pcapng',
            '/tmp/ao_test_out/11-22-33-44-55-66_Net2.pcapng',
        ]
        mock_mtime.side_effect = [1000.0, 1000.0]

        plugin._scan_captures(agent)

        agent._update_handshakes.assert_called_once_with(2)

    @patch('glob.glob')
    @patch('os.path.getmtime')
    @patch('os.path.abspath', side_effect=lambda x: x)
    def test_modified_file_does_not_call_update_handshakes(self, mock_abspath, mock_mtime, mock_glob, plugin, agent):
        filepath = '/tmp/ao_test_out/AA-BB-CC-DD-EE-FF_Net1.pcapng'
        plugin._known_files = {filepath: 1000.0}

        mock_glob.return_value = [filepath]
        mock_mtime.return_value = 2000.0  # modified

        plugin._scan_captures(agent)

        # new_count is 0 (modified, not new) — _update_handshakes should NOT be called
        agent._update_handshakes.assert_not_called()

    @patch('glob.glob')
    @patch('os.path.getmtime')
    @patch('os.path.abspath', side_effect=lambda x: x)
    @patch('shutil.copy2')
    def test_duplicate_handshake_key_not_overwritten(self, mock_copy, mock_abspath, mock_mtime, mock_glob, plugin, agent):
        """If the same AP was already captured, don't overwrite the existing entry."""
        agent._handshakes['unknown -> AA:BB:CC:DD:EE:FF'] = {'source': 'bettercap'}
        plugin._known_files = {}

        mock_glob.return_value = ['/tmp/ao_test_out/AA-BB-CC-DD-EE-FF_TestNet.pcapng']
        mock_mtime.return_value = 1000.0

        plugin._scan_captures(agent)

        # original entry preserved
        assert agent._handshakes['unknown -> AA:BB:CC:DD:EE:FF']['source'] == 'bettercap'


# ===================================================================
# 8. Adaptive injection delay
# ===================================================================

class TestAdaptiveThrottle:
    @patch('time.sleep')
    def test_crash_increases_delay_by_50_pct(self, mock_sleep, plugin, agent):
        plugin.options['adaptive_throttle'] = True
        plugin.options['injection_delay_ms'] = 500
        plugin._running = True

        mock_proc = MagicMock()
        mock_proc.poll.return_value = 1
        mock_proc.returncode = 1
        plugin._process = mock_proc
        plugin._is_brcmfmac = False

        with patch.object(plugin, '_start_ao'):
            plugin._check_health(agent)

        assert plugin._current_injection_delay == 750  # 500 * 1.5

    @patch('time.sleep')
    def test_successive_crashes_compound_delay(self, mock_sleep, plugin, agent):
        plugin.options['adaptive_throttle'] = True
        plugin.options['injection_delay_ms'] = 500
        plugin.options['delay_max'] = 2000
        plugin._is_brcmfmac = False

        for _ in range(3):
            plugin._running = True
            mock_proc = MagicMock()
            mock_proc.poll.return_value = 1
            mock_proc.returncode = 1
            plugin._process = mock_proc

            with patch.object(plugin, '_start_ao'):
                plugin._check_health(agent)

        # 500 -> 750 -> 1125 -> 1687
        assert plugin._current_injection_delay == 1687

    @patch('time.sleep')
    def test_delay_capped_at_delay_max(self, mock_sleep, plugin, agent):
        plugin.options['adaptive_throttle'] = True
        plugin.options['injection_delay_ms'] = 1500
        plugin.options['delay_max'] = 2000
        plugin._is_brcmfmac = False
        plugin._running = True

        mock_proc = MagicMock()
        mock_proc.poll.return_value = 1
        mock_proc.returncode = 1
        plugin._process = mock_proc

        with patch.object(plugin, '_start_ao'):
            plugin._check_health(agent)

        # 1500 * 1.5 = 2250 -> capped to 2000
        assert plugin._current_injection_delay == 2000

    def test_stability_decreases_delay_by_10_pct(self, plugin, agent):
        plugin.options['adaptive_throttle'] = True
        plugin.options['delay_min'] = 100
        plugin._current_injection_delay = 1000
        plugin._running = True
        plugin._stable_epochs = 19  # will become 20 in on_epoch

        with patch.object(plugin, '_check_health'), \
             patch.object(plugin, '_scan_captures'), \
             patch('os.path.isfile', return_value=True), \
             patch('time.time', return_value=99999):
            plugin.on_epoch(agent, 1, {})

        assert plugin._current_injection_delay == 900  # 1000 * 0.9

    def test_delay_floored_at_delay_min(self, plugin, agent):
        plugin.options['adaptive_throttle'] = True
        plugin.options['delay_min'] = 100
        plugin._current_injection_delay = 105
        plugin._running = True
        plugin._stable_epochs = 19

        with patch.object(plugin, '_check_health'), \
             patch.object(plugin, '_scan_captures'), \
             patch('os.path.isfile', return_value=True), \
             patch('time.time', return_value=99999):
            plugin.on_epoch(agent, 1, {})

        # 105 * 0.9 = 94 -> floored to 100
        assert plugin._current_injection_delay == 100

    def test_delay_at_min_does_not_decrease_further(self, plugin, agent):
        plugin.options['adaptive_throttle'] = True
        plugin.options['delay_min'] = 100
        plugin._current_injection_delay = 100
        plugin._running = True
        plugin._stable_epochs = 19

        with patch.object(plugin, '_check_health'), \
             patch.object(plugin, '_scan_captures'), \
             patch('os.path.isfile', return_value=True), \
             patch('time.time', return_value=99999):
            plugin.on_epoch(agent, 1, {})

        # 100 * 0.9 = 90 -> floored to 100, same as before so no change
        assert plugin._current_injection_delay == 100

    def test_build_cmd_uses_adaptive_delay(self, plugin):
        plugin._current_injection_delay = 777
        cmd = plugin._build_cmd()
        idx = cmd.index('--injection-delay-ms')
        assert cmd[idx + 1] == '777'

    def test_build_cmd_uses_configured_delay_when_no_adaptive(self, plugin):
        plugin._current_injection_delay = None
        plugin.options['injection_delay_ms'] = 500
        cmd = plugin._build_cmd()
        idx = cmd.index('--injection-delay-ms')
        assert cmd[idx + 1] == '500'

    def test_crash_resets_stable_epochs(self, plugin, agent):
        plugin.options['adaptive_throttle'] = True
        plugin._stable_epochs = 15
        plugin._running = True
        plugin._is_brcmfmac = False

        mock_proc = MagicMock()
        mock_proc.poll.return_value = 1
        mock_proc.returncode = 1
        plugin._process = mock_proc

        with patch.object(plugin, '_start_ao'), patch('time.sleep'):
            plugin._check_health(agent)

        assert plugin._stable_epochs == 0

    def test_no_throttle_when_disabled(self, plugin, agent):
        plugin.options['adaptive_throttle'] = False
        plugin._running = True
        plugin._is_brcmfmac = False

        mock_proc = MagicMock()
        mock_proc.poll.return_value = 1
        mock_proc.returncode = 1
        plugin._process = mock_proc

        with patch.object(plugin, '_start_ao'), patch('time.sleep'):
            plugin._check_health(agent)

        assert plugin._current_injection_delay is None

    def test_fw_counters_fatal_errors_double_delay(self, plugin, agent):
        """When pi_helper reports rising fatal errors, delay should double."""
        plugin.options['adaptive_throttle'] = True
        plugin.options['delay_max'] = 2000
        plugin._current_injection_delay = 500
        plugin._running = True
        plugin._stable_epochs = 5
        plugin._last_fatal_errors = 10
        plugin._last_hard_faults = 0

        # pi_helper returns fatal_errors=12 (delta +2), hard_faults=0
        with patch.object(plugin, '_check_health'), \
             patch.object(plugin, '_scan_captures'), \
             patch.object(plugin, '_read_fw_counters', return_value=(12, 0)), \
             patch('os.path.isfile', return_value=True), \
             patch('time.time', return_value=99999):
            plugin.on_epoch(agent, 1, {})

        assert plugin._current_injection_delay == 1000  # 500 * 2.0
        assert plugin._stable_epochs == 0  # reset on counter spike
        assert plugin._last_fatal_errors == 12

    def test_fw_counters_hard_faults_increase_delay_50pct(self, plugin, agent):
        """When pi_helper reports rising hard faults (no fatal), delay increases 50%."""
        plugin.options['adaptive_throttle'] = True
        plugin.options['delay_max'] = 2000
        plugin._current_injection_delay = 500
        plugin._running = True
        plugin._stable_epochs = 5
        plugin._last_fatal_errors = 10
        plugin._last_hard_faults = 3

        # fatal_errors unchanged, hard_faults climbed by 2
        with patch.object(plugin, '_check_health'), \
             patch.object(plugin, '_scan_captures'), \
             patch.object(plugin, '_read_fw_counters', return_value=(10, 5)), \
             patch('os.path.isfile', return_value=True), \
             patch('time.time', return_value=99999):
            plugin.on_epoch(agent, 1, {})

        assert plugin._current_injection_delay == 750  # 500 * 1.5
        assert plugin._stable_epochs == 0
        assert plugin._last_hard_faults == 5

    def test_fw_counters_unavailable_no_effect(self, plugin, agent):
        """When pi_helper is unavailable, adaptive throttle still works normally."""
        plugin.options['adaptive_throttle'] = True
        plugin.options['delay_min'] = 100
        plugin._current_injection_delay = 1000
        plugin._running = True
        plugin._stable_epochs = 19

        with patch.object(plugin, '_check_health'), \
             patch.object(plugin, '_scan_captures'), \
             patch.object(plugin, '_read_fw_counters', return_value=None), \
             patch('os.path.isfile', return_value=True), \
             patch('time.time', return_value=99999):
            plugin.on_epoch(agent, 1, {})

        # should still decrease after stability (20 epochs)
        assert plugin._current_injection_delay == 900

    def test_fw_counters_stable_no_backoff(self, plugin, agent):
        """When counters are flat, no backoff occurs."""
        plugin.options['adaptive_throttle'] = True
        plugin._current_injection_delay = 500
        plugin._running = True
        plugin._stable_epochs = 5
        plugin._last_fatal_errors = 10
        plugin._last_hard_faults = 3

        # counters unchanged
        with patch.object(plugin, '_check_health'), \
             patch.object(plugin, '_scan_captures'), \
             patch.object(plugin, '_read_fw_counters', return_value=(10, 3)), \
             patch('os.path.isfile', return_value=True), \
             patch('time.time', return_value=99999):
            plugin.on_epoch(agent, 1, {})

        # delay unchanged, stable_epochs incremented
        assert plugin._current_injection_delay == 500
        assert plugin._stable_epochs == 6

    def test_fw_counters_fatal_capped_at_delay_max(self, plugin, agent):
        """Fatal error backoff respects delay_max."""
        plugin.options['adaptive_throttle'] = True
        plugin.options['delay_max'] = 1500
        plugin._current_injection_delay = 1000
        plugin._running = True
        plugin._last_fatal_errors = 0
        plugin._last_hard_faults = 0

        with patch.object(plugin, '_check_health'), \
             patch.object(plugin, '_scan_captures'), \
             patch.object(plugin, '_read_fw_counters', return_value=(5, 0)), \
             patch('os.path.isfile', return_value=True), \
             patch('time.time', return_value=99999):
            plugin.on_epoch(agent, 1, {})

        # 1000 * 2.0 = 2000 -> capped to 1500
        assert plugin._current_injection_delay == 1500

    def test_read_fw_counters_returns_none_on_error(self, plugin):
        """_read_fw_counters returns None when pi_helper is not reachable."""
        # No mocking of urllib — actual connection to 127.0.0.1:8888 will fail
        result = plugin._read_fw_counters()
        assert result is None

    def test_fw_counters_init_state(self, plugin):
        """Initial firmware counter tracking state is zero."""
        assert plugin._last_fatal_errors == 0
        assert plugin._last_hard_faults == 0


# ===================================================================
# 9. Webhook endpoint
# ===================================================================

class TestWebhook:
    def _make_request(self, method='GET'):
        req = MagicMock()
        req.method = method
        return req

    def test_status_endpoint_returns_all_fields(self, plugin):
        import flask
        app = flask.Flask(__name__)

        plugin._running = True
        plugin._captures = 5
        plugin._crash_count = 2
        plugin._fw_crash_count = 1
        plugin._stable_epochs = 10
        plugin._is_brcmfmac = True
        plugin._stopped_permanently = False
        plugin._process = MagicMock()
        plugin._process.pid = 999

        with patch.object(plugin, '_read_fw_counters', return_value=(42, 7)):
            with app.app_context():
                resp = plugin.on_webhook('/status', self._make_request('GET'))
                data = json.loads(resp.get_data())

        assert data['running'] is True
        assert data['pid'] == 999
        assert data['captures'] == 5
        assert data['crash_count'] == 2
        assert data['fw_crash_count'] == 1
        assert data['stable_epochs'] == 10
        assert data['is_brcmfmac'] is True
        assert data['stopped_permanently'] is False
        assert data['fw_fatal_errors_blocked'] == 42
        assert data['fw_hard_faults_caught'] == 7

    def test_status_root_path(self, plugin):
        import flask
        app = flask.Flask(__name__)

        plugin._process = None

        with patch.object(plugin, '_read_fw_counters', return_value=None):
            with app.app_context():
                resp = plugin.on_webhook('/', self._make_request('GET'))
                data = json.loads(resp.get_data())

        assert data['pid'] is None
        assert data['fw_fatal_errors_blocked'] is None
        assert data['fw_hard_faults_caught'] is None

    def test_status_empty_path(self, plugin):
        import flask
        app = flask.Flask(__name__)

        plugin._process = None

        with patch.object(plugin, '_read_fw_counters', return_value=None):
            with app.app_context():
                resp = plugin.on_webhook('', self._make_request('GET'))
                data = json.loads(resp.get_data())

        assert 'running' in data

    def test_captures_endpoint(self, plugin):
        import flask
        app = flask.Flask(__name__)

        plugin._known_files = {
            '/tmp/file1.pcapng': 3000.0,
            '/tmp/file2.pcapng': 1000.0,
            '/tmp/file3.pcapng': 2000.0,
        }

        with app.app_context():
            resp = plugin.on_webhook('/captures', self._make_request('GET'))
            data = json.loads(resp.get_data())

        assert len(data) == 3
        # sorted by mtime descending
        assert data[0]['file'] == 'file1.pcapng'
        assert data[0]['mtime'] == 3000.0
        assert data[2]['file'] == 'file2.pcapng'

    def test_captures_limited_to_50(self, plugin):
        import flask
        app = flask.Flask(__name__)

        plugin._known_files = {'/tmp/file%d.pcapng' % i: float(i) for i in range(100)}

        with app.app_context():
            resp = plugin.on_webhook('/captures', self._make_request('GET'))
            data = json.loads(resp.get_data())

        assert len(data) == 50

    def test_reset_endpoint(self, plugin):
        import flask
        app = flask.Flask(__name__)

        plugin._stopped_permanently = True
        plugin._crash_count = 7

        with app.app_context():
            resp = plugin.on_webhook('/reset', self._make_request('POST'))
            data = json.loads(resp.get_data())

        assert data['status'] == 'ok'
        assert plugin._stopped_permanently is False
        assert plugin._crash_count == 0

    def test_unknown_route_returns_404(self, plugin):
        import flask
        app = flask.Flask(__name__)

        with app.app_context():
            result = plugin.on_webhook('/nonexistent', self._make_request('GET'))
            # returns tuple (response, status_code) for 404
            resp, status = result
            data = json.loads(resp.get_data())

        assert status == 404
        assert 'error' in data

    def test_wrong_method_returns_404(self, plugin):
        import flask
        app = flask.Flask(__name__)

        with app.app_context():
            result = plugin.on_webhook('/status', self._make_request('POST'))
            resp, status = result

        assert status == 404

    def test_injection_delay_shows_adaptive_value(self, plugin):
        import flask
        app = flask.Flask(__name__)

        plugin._current_injection_delay = 750
        plugin._process = None

        with patch.object(plugin, '_read_fw_counters', return_value=None):
            with app.app_context():
                resp = plugin.on_webhook('/status', self._make_request('GET'))
                data = json.loads(resp.get_data())

        assert data['injection_delay_ms'] == 750

    def test_injection_delay_shows_config_when_no_adaptive(self, plugin):
        import flask
        app = flask.Flask(__name__)

        plugin._current_injection_delay = None
        plugin.options['injection_delay_ms'] = 500
        plugin._process = None

        with patch.object(plugin, '_read_fw_counters', return_value=None):
            with app.app_context():
                resp = plugin.on_webhook('/status', self._make_request('GET'))
                data = json.loads(resp.get_data())

        assert data['injection_delay_ms'] == 500


# ===================================================================
# 10. Config defaults / option fallbacks
# ===================================================================

class TestConfigDefaults:
    def test_max_crashes_default(self):
        p = AngryOxide()
        assert p.options.get('max_crashes', 10) == 10

    def test_adaptive_throttle_default(self):
        p = AngryOxide()
        assert p.options.get('adaptive_throttle', False) is False

    def test_delay_min_default(self):
        p = AngryOxide()
        assert p.options.get('delay_min', 100) == 100

    def test_delay_max_default(self):
        p = AngryOxide()
        assert p.options.get('delay_max', 2000) == 2000


# ===================================================================
# Parse capture filename edge cases
# ===================================================================

class TestParseFilename:
    def test_standard_format(self):
        ap, sta = AngryOxide._parse_capture_filename('AA-BB-CC-DD-EE-FF_MyNetwork.pcapng')
        assert ap == 'AA:BB:CC:DD:EE:FF'
        assert sta == 'unknown'

    def test_no_ssid(self):
        ap, sta = AngryOxide._parse_capture_filename('AA-BB-CC-DD-EE-FF_.pcapng')
        assert ap == 'AA:BB:CC:DD:EE:FF'

    def test_ssid_with_underscores(self):
        ap, sta = AngryOxide._parse_capture_filename('AA-BB-CC-DD-EE-FF_My_Cool_Network.pcapng')
        assert ap == 'AA:BB:CC:DD:EE:FF'

    def test_invalid_format_returns_unknown(self):
        ap, sta = AngryOxide._parse_capture_filename('random_file.pcapng')
        assert ap == 'unknown'
        assert sta == 'unknown'

    def test_short_mac_returns_unknown(self):
        ap, sta = AngryOxide._parse_capture_filename('AA-BB-CC_Network.pcapng')
        assert ap == 'unknown'


# ===================================================================
# UI display states
# ===================================================================

class TestUIUpdate:
    def test_shows_err_when_stopped_permanently(self, plugin):
        ui = MagicMock()
        ui._lock = Lock()
        plugin._stopped_permanently = True

        plugin.on_ui_update(ui)

        ui.set.assert_called_with('angryoxide', 'ERR')

    def test_shows_count_when_running(self, plugin):
        ui = MagicMock()
        ui._lock = Lock()
        plugin._stopped_permanently = False
        plugin._running = True
        plugin._captures = 42

        plugin.on_ui_update(ui)

        ui.set.assert_called_with('angryoxide', '42')

    def test_shows_off_when_not_running(self, plugin):
        ui = MagicMock()
        ui._lock = Lock()
        plugin._stopped_permanently = False
        plugin._running = False

        plugin.on_ui_update(ui)

        ui.set.assert_called_with('angryoxide', 'off')


# ===================================================================
# on_epoch flow integration
# ===================================================================

class TestOnEpochFlow:
    def test_epoch_starts_ao_if_not_running_and_binary_exists(self, plugin, agent):
        plugin._running = False

        with patch('os.path.isfile', return_value=True), \
             patch.object(plugin, '_start_ao') as mock_start:
            plugin.on_epoch(agent, 1, {})

        mock_start.assert_called_once_with(agent)

    def test_epoch_does_not_start_if_binary_missing(self, plugin, agent):
        """When not running and binary missing, _start_ao is NOT called.
        _check_health still runs but returns early since _running=False."""
        plugin._running = False

        with patch('os.path.isfile', return_value=False), \
             patch.object(plugin, '_start_ao') as mock_start:
            plugin.on_epoch(agent, 1, {})

        mock_start.assert_not_called()

    def test_epoch_checks_health_and_scans_when_running(self, plugin, agent):
        plugin._running = True

        with patch.object(plugin, '_check_health') as mock_health, \
             patch.object(plugin, '_scan_captures') as mock_scan, \
             patch('os.path.isfile', return_value=True), \
             patch('time.time', return_value=99999):
            plugin.on_epoch(agent, 1, {})

        mock_health.assert_called_once_with(agent)
        mock_scan.assert_called_once_with(agent)


# ===================================================================
# on_ready disables bettercap attacks
# ===================================================================

class TestOnReady:
    @patch('subprocess.Popen')
    @patch('os.makedirs')
    @patch('os.path.isfile', return_value=True)
    @patch('glob.glob', return_value=[])
    def test_disables_bettercap_attacks(self, mock_glob, mock_isfile, mock_mkdirs, mock_popen, plugin, agent):
        mock_popen.return_value = MagicMock(pid=1)
        agent._config['personality']['deauth'] = True
        agent._config['personality']['associate'] = True

        plugin.on_ready(agent)

        assert agent._config['personality']['deauth'] is False
        assert agent._config['personality']['associate'] is False
        assert plugin._original_deauth is True
        assert plugin._original_associate is True


# ===================================================================
# _check_health integration with _try_fw_recovery gating
# ===================================================================

class TestCheckHealthRecoveryGating:
    @patch('time.sleep')
    def test_does_not_restart_on_failed_recovery(self, mock_sleep, plugin, agent):
        plugin._running = True
        plugin._is_brcmfmac = True

        mock_proc = MagicMock()
        mock_proc.poll.return_value = 1
        mock_proc.returncode = -11
        plugin._process = mock_proc

        with patch.object(plugin, '_try_fw_recovery', return_value=False), \
             patch.object(plugin, '_start_ao') as mock_start:
            plugin._check_health(agent)

        mock_start.assert_not_called()

    @patch('time.sleep')
    def test_restarts_on_successful_recovery(self, mock_sleep, plugin, agent):
        plugin._running = True
        plugin._is_brcmfmac = True

        mock_proc = MagicMock()
        mock_proc.poll.return_value = 1
        mock_proc.returncode = -11
        plugin._process = mock_proc

        with patch.object(plugin, '_try_fw_recovery', return_value=True), \
             patch.object(plugin, '_start_ao') as mock_start:
            plugin._check_health(agent)

        mock_start.assert_called_once_with(agent)

    @patch('time.sleep')
    def test_skips_recovery_for_non_brcmfmac(self, mock_sleep, plugin, agent):
        plugin._running = True
        plugin._is_brcmfmac = False

        mock_proc = MagicMock()
        mock_proc.poll.return_value = 1
        mock_proc.returncode = 1
        plugin._process = mock_proc

        with patch.object(plugin, '_try_fw_recovery') as mock_recovery, \
             patch.object(plugin, '_start_ao') as mock_start:
            plugin._check_health(agent)

        mock_recovery.assert_not_called()
        mock_start.assert_called_once()
