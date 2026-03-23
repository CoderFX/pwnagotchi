import hashlib
import json
import time
import re
import os
import logging
import shutil
import gzip
import warnings
from datetime import datetime

from pwnagotchi.voice import Voice
from pwnagotchi.mesh.peer import Peer
from file_read_backwards import FileReadBackwards

LAST_SESSION_FILE = '/root/.pwnagotchi-last-session'


class LastSession(object):
    EPOCH_TOKEN = '[epoch '
    EPOCH_PARSER = re.compile(r'^.+\[epoch (\d+)] (.+)')
    EPOCH_DATA_PARSER = re.compile(r'([a-z_]+)=(\S+)')
    TRAINING_TOKEN = ' training epoch '
    START_TOKEN = 'connecting to http'
    DEAUTH_TOKEN = 'deauthing '
    ASSOC_TOKEN = 'sending association frame to '
    HANDSHAKE_TOKEN = '!!! captured new handshake '
    PEER_TOKEN = 'detected unit '

    def __init__(self, config):
        self.config = config
        self.voice = Voice(lang=config['main']['lang'])
        self.path = config['main']['log']['path']
        self.last_session = []
        self.last_session_id = ''
        self.last_saved_session_id = ''
        self.duration = ''
        self.duration_human = ''
        self.deauthed = 0
        self.associated = 0
        self.handshakes = 0
        self.peers = 0
        self.last_peer = None
        self.epochs = 0
        self.train_epochs = 0
        self.min_reward = 1000
        self.max_reward = -1000
        self.avg_reward = 0
        self._peer_parser = re.compile(
            'detected unit (.+)@(.+) \(v.+\) on channel \d+ \(([\d\-]+) dBm\) \[sid:(.+) pwnd_tot:(\d+) uptime:(\d+)]')
        self.parsed = False

    def _get_last_saved_session_id(self):
        saved = ''
        try:
            with open(LAST_SESSION_FILE, 'rt') as fp:
                saved = fp.read().strip()
        except Exception:  # FIX B4: was bare except, swallowed KeyboardInterrupt
            saved = ''
        return saved

    def save_session_id(self):
        with open(LAST_SESSION_FILE, 'w+t') as fp:
            fp.write(self.last_session_id)
            self.last_saved_session_id = self.last_session_id

    def _parse_datetime(self, dt):
        dt = dt.split('.')[0]
        dt = dt.split(',')[0]
        dt = datetime.strptime(dt.split('.')[0], '%Y-%m-%d %H:%M:%S')
        return time.mktime(dt.timetuple())

    def _parse_stats(self):
        self.duration = ''
        self.duration_human = ''
        self.deauthed = 0
        self.associated = 0
        self.handshakes = 0
        self.epochs = 0
        self.train_epochs = 0
        self.peers = 0
        self.last_peer = None
        self.min_reward = 1000
        self.max_reward = -1000
        self.avg_reward = 0

        started_at = None
        stopped_at = None
        cache = {}

        for line in self.last_session:
            parts = line.split(']')
            if len(parts) < 2:
                continue

            try:
                line_timestamp = parts[0].strip('[')
                line = ']'.join(parts[1:])
                stopped_at = self._parse_datetime(line_timestamp)
                if started_at is None:
                    started_at = stopped_at

                if LastSession.DEAUTH_TOKEN in line and line not in cache:
                    self.deauthed += 1
                    cache[line] = 1

                elif LastSession.ASSOC_TOKEN in line and line not in cache:
                    self.associated += 1
                    cache[line] = 1

                elif LastSession.HANDSHAKE_TOKEN in line and line not in cache:
                    self.handshakes += 1
                    cache[line] = 1

                elif LastSession.TRAINING_TOKEN in line:
                    self.train_epochs += 1

                elif LastSession.EPOCH_TOKEN in line:
                    self.epochs += 1
                    m = LastSession.EPOCH_PARSER.findall(line)
                    if m:
                        epoch_num, epoch_data = m[0]
                        m = LastSession.EPOCH_DATA_PARSER.findall(epoch_data)
                        for key, value in m:
                            if key == 'reward':
                                reward = float(value)
                                self.avg_reward += reward
                                if reward < self.min_reward:
                                    self.min_reward = reward

                                elif reward > self.max_reward:
                                    self.max_reward = reward

                elif LastSession.PEER_TOKEN in line:
                    m = self._peer_parser.findall(line)
                    if m:
                        name, pubkey, rssi, sid, pwnd_tot, uptime = m[0]
                        if pubkey not in cache:
                            self.last_peer = Peer({
                                'session_id': sid,
                                'channel': 1,
                                'rssi': int(rssi),
                                'identity': pubkey,
                                'advertisement': {
                                    'name': name,
                                    'pwnd_tot': int(pwnd_tot)
                                }})
                            self.peers += 1
                            cache[pubkey] = self.last_peer
                        else:
                            cache[pubkey].adv['pwnd_tot'] = pwnd_tot
            except Exception as e:
                logging.error("error parsing line '%s': %s" % (line, e))

        if started_at is not None:
            self.duration = stopped_at - started_at
            mins, secs = divmod(self.duration, 60)
            hours, mins = divmod(mins, 60)
        else:
            hours = mins = secs = 0

        self.duration = '%02d:%02d:%02d' % (hours, mins, secs)
        self.duration_human = []
        if hours > 0:
            self.duration_human.append('%d %s' % (hours, self.voice.hhmmss(hours, 'h')))
        if mins > 0:
            self.duration_human.append('%d %s' % (mins, self.voice.hhmmss(mins, 'm')))
        if secs > 0:
            self.duration_human.append('%d %s' % (secs, self.voice.hhmmss(secs, 's')))

        self.duration_human = ', '.join(self.duration_human)
        self.avg_reward /= (self.epochs if self.epochs else 1)

    _CACHE_FILE = '/home/pi/last_session_cache.json'

    def _save_cache(self):
        """Save parsed session data to cache file for fast boot."""
        try:
            stat = os.stat(self.path) if os.path.exists(self.path) else None
            peer_data = None
            if self.last_peer:
                try:
                    peer_data = {
                        'session_id': self.last_peer.session_id(),
                        'channel': 1,
                        'rssi': self.last_peer.rssi,
                        'identity': self.last_peer.identity(),
                        'name': self.last_peer.name(),
                        'pwnd_tot': self.last_peer.pwnd_total(),
                    }
                except Exception:
                    pass
            data = {
                'version': 1,
                'log_mtime': stat.st_mtime if stat else 0,
                'log_size': stat.st_size if stat else 0,
                'last_session_id': self.last_session_id,
                'duration': self.duration,
                'duration_human': self.duration_human,
                'deauthed': self.deauthed,
                'associated': self.associated,
                'handshakes': self.handshakes,
                'epochs': self.epochs,
                'train_epochs': self.train_epochs,
                'peers': self.peers,
                'last_peer': peer_data,
                'min_reward': self.min_reward,
                'max_reward': self.max_reward,
                'avg_reward': self.avg_reward,
            }
            with open(self._CACHE_FILE, 'w') as f:
                json.dump(data, f)
        except Exception as e:
            logging.debug("could not save session cache: %s" % e)

    def _load_cache(self):
        """Load cached session data for fast boot.
        Always use cache if it exists — the few shutdown log lines written after
        the cache was saved don't meaningfully change session stats, and avoiding
        the full FileReadBackwards parse saves 30-60s on Pi Zero 2W."""
        try:
            if not os.path.isfile(self._CACHE_FILE):
                return False
            with open(self._CACHE_FILE, 'r') as f:
                data = json.load(f)
            if data.get('version') != 1:
                return False
            # Cache is valid — restore fields
            self.last_session_id = data.get('last_session_id', '')
            self.duration = data.get('duration', '')
            self.duration_human = data.get('duration_human', '')
            self.deauthed = data.get('deauthed', 0)
            self.associated = data.get('associated', 0)
            self.handshakes = data.get('handshakes', 0)
            self.epochs = data.get('epochs', 0)
            self.train_epochs = data.get('train_epochs', 0)
            self.peers = data.get('peers', 0)
            self.min_reward = data.get('min_reward', 1000)
            self.max_reward = data.get('max_reward', -1000)
            self.avg_reward = data.get('avg_reward', 0)
            peer_data = data.get('last_peer')
            if peer_data:
                self.last_peer = Peer({
                    'session_id': peer_data.get('session_id', ''),
                    'channel': peer_data.get('channel', 1),
                    'rssi': peer_data.get('rssi', 0),
                    'identity': peer_data.get('identity', ''),
                    'advertisement': {
                        'name': peer_data.get('name', ''),
                        'pwnd_tot': peer_data.get('pwnd_tot', 0),
                    }
                })
            self.last_saved_session_id = self._get_last_saved_session_id()
            logging.info("loaded session data from cache (skipped log parsing)")
            return True
        except Exception as e:
            logging.debug("could not load session cache: %s" % e)
            return False

    def parse(self, ui, skip=False):
        if skip:
            logging.debug("skipping parsing of the last session logs ...")
        elif self._load_cache():
            logging.debug("session data loaded from cache")
        else:
            logging.debug("reading last session logs ...")

            ui.on_reading_logs()

            lines = []

            if os.path.exists(self.path):
                with FileReadBackwards(self.path, encoding="utf-8") as fp:
                    for line in fp:
                        line = line.strip()
                        if line != "" and line[0] != '[':
                            continue
                        lines.append(line)
                        if LastSession.START_TOKEN in line:
                            break

                        lines_so_far = len(lines)
                        if lines_so_far % 100 == 0:
                            ui.on_reading_logs(lines_so_far)

                lines.reverse()

            if len(lines) == 0:
                lines.append("Initial Session")

            ui.on_reading_logs()

            self.last_session = lines
            self.last_session_id = hashlib.md5(lines[0].encode()).hexdigest()
            self.last_saved_session_id = self._get_last_saved_session_id()

            logging.debug("parsing last session logs (%d lines) ..." % len(lines))

            self._parse_stats()
            self._save_cache()
        self.parsed = True

    def is_new(self):
        return self.last_session_id != self.last_saved_session_id


def setup_logging(args, config):
    cfg = config['main']['log']
    filename = cfg['path']
    filenameDebug = cfg['path-debug']

    #global formatter
    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] [%(threadName)s] : %(message)s")
    logger = logging.getLogger()
    
    for handler in logger.handlers:
        handler.setLevel(logging.DEBUG if args.debug else logging.INFO)
        handler.setFormatter(formatter)
    
    
    logger.setLevel(logging.DEBUG if args.debug else logging.INFO)

    if filename:
        # since python default log rotation might break session data in different files,
        # we need to do log rotation ourselves
        log_rotation(filename, cfg)
        log_rotation(filenameDebug, cfg)

    
    
        # File handler for logging all normal messages
    file_handler = logging.FileHandler(filename) #creates new
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # File handler for logging all debug messages
    file_handler = logging.FileHandler(filenameDebug) #creates new
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Console handler for logging debug messages if args.debug is true else just log normal
    #console_handler = logging.StreamHandler() #creates new
    #console_handler.setLevel(logging.DEBUG if args.debug else logging.INFO)
    #console_handler.setFormatter(formatter)
    #logger.addHandler(console_handler)
    
    if not args.debug:
        # disable scapy and tensorflow logging
        logging.getLogger("scapy").disabled = True
        # https://stackoverflow.com/questions/15777951/how-to-suppress-pandas-future-warning
        warnings.simplefilter(action='ignore', category=FutureWarning)
        warnings.simplefilter(action='ignore', category=DeprecationWarning)
        # https://stackoverflow.com/questions/24344045/how-can-i-completely-remove-any-logging-from-requests-module-in-python?noredirect=1&lq=1
        logging.getLogger("urllib3").propagate = False
        requests_log = logging.getLogger("requests")
        requests_log.addHandler(logging.NullHandler())
        requests_log.prpagate = False

    logging.info("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- Pwnagotchi Re|Started -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-")



def log_rotation(filename, cfg):
    rotation = cfg['rotation']
    if not rotation['enabled']:
        return
    elif not os.path.isfile(filename):
        return

    stats = os.stat(filename)
    # specify a maximum size to rotate ( format is 10/10B, 10K, 10M 10G )
    if rotation['size']:
        max_size = parse_max_size(rotation['size'])
        if stats.st_size >= max_size:
            do_rotate(filename, stats, cfg)
    else:
        raise Exception("log rotation is enabled but log.rotation.size was not specified")


def parse_max_size(s):
    parts = re.findall(r'(^\d+)([bBkKmMgG]?)', s)
    if len(parts) != 1 or len(parts[0]) != 2:
        raise Exception("can't parse %s as a max size" % s)

    num, unit = parts[0]
    num = int(num)
    unit = unit.lower()

    if unit == 'k':
        return num * 1024
    elif unit == 'm':
        return num * 1024 * 1024
    elif unit == 'g':
        return num * 1024 * 1024 * 1024
    else:
        return num


def do_rotate(filename, stats, cfg):
    base_path = os.path.dirname(filename)
    name = os.path.splitext(os.path.basename(filename))[0]
    archive_filename = os.path.join(base_path, "%s.gz" % name)
    counter = 2

    while os.path.exists(archive_filename):
        archive_filename = os.path.join(base_path, "%s-%d.gz" % (name, counter))
        counter += 1

    log_filename = archive_filename.replace('gz', 'log')

    print("%s is %d bytes big, rotating to %s ..." % (filename, stats.st_size, log_filename))

    shutil.move(filename, log_filename)

    print("compressing to %s ..." % archive_filename)

    with open(log_filename, 'rb') as src:
        with gzip.open(archive_filename, 'wb') as dst:
            dst.writelines(src)

    os.remove(log_filename)
