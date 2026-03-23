"""
StubClient — drop-in replacement for bettercap.Client when running in AO-only mode.

All bettercap API calls become no-ops. Shell escape commands (prefixed with !)
are executed via subprocess. session() returns a fake session with injectable AP data.
"""

import logging
import asyncio
import subprocess
import threading


class StubClient:
    def __init__(self, hostname='localhost', scheme='http', port=8081, username='user', password='pass'):
        self.hostname = hostname
        self.scheme = scheme
        self.port = port
        self.username = username
        self.password = password
        self.url = "%s://%s:%d/api" % (scheme, hostname, port)
        self.websocket = None
        self.auth = None

        self._stub_aps = []
        self._stub_lock = threading.Lock()

    def session(self, sess="session"):
        """Return a fake bettercap session structure."""
        with self._stub_lock:
            aps = list(self._stub_aps)
        return {
            'wifi': {'aps': aps},
            'interfaces': [{'name': 'wlan0mon', 'type': 'monitor'}],
            'modules': [],
        }

    async def start_websocket(self, consumer):
        """No-op — AO detects captures from disk, no bettercap events needed."""
        while True:
            await asyncio.sleep(3600)

    def run(self, command, verbose_errors=True):
        """Execute shell escapes (! prefix) via subprocess; everything else is a no-op."""
        if command.startswith('!'):
            shell_cmd = command[1:].strip()
            logging.info("[stub_client] running shell command: %s", shell_cmd)
            try:
                result = subprocess.run(
                    shell_cmd, shell=True,
                    capture_output=True, text=True, timeout=30
                )
                if result.returncode != 0:
                    logging.warning("[stub_client] command exited %d: %s", result.returncode, result.stderr.strip())
                return result.stdout
            except subprocess.TimeoutExpired:
                logging.error("[stub_client] command timed out: %s", shell_cmd)
                return ''
        else:
            logging.debug("[stub_client] no-op command: %s", command)
            return ''

    def set_stub_aps(self, aps):
        """Inject AP data (called by AO plugin to feed the display/epoch)."""
        with self._stub_lock:
            self._stub_aps = aps
