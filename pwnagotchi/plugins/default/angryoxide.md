# AngryOxide Plugin v0.3.0

Runs [AngryOxide](https://github.com/Ragnt/AngryOxide) as the active attack engine alongside bettercap. Bettercap continues handling recon (AP/client discovery) while AngryOxide handles all active attacks: PMKID capture, CSA (Channel Switch Announcement), and deauthentication.

## Requirements

- AngryOxide binary installed (default: `/usr/local/bin/angryoxide`)
- Monitor-mode interface (default: `wlan0mon`)
- For brcmfmac chips (Pi Zero 2W, Pi 3/4 onboard): a nexmon-patched AO binary

## Quick Start

Enable in `/etc/pwnagotchi/config.toml`:

```toml
[main.plugins.angryoxide]
enabled = true
```

The plugin auto-detects brcmfmac and enables nexmon_mode defaults. No further configuration needed for most setups.

## How It Works

### Startup

1. On `on_ready`, the plugin disables bettercap's deauth and associate attacks
2. Launches AngryOxide as a subprocess in headless mode on the monitor interface
3. Snapshots existing `.pcapng` files in the output directory to avoid double-counting

### Each Epoch

1. If `stopped_permanently` due to crash limit: returns immediately
2. If AO isn't running and binary exists: starts it
3. Health check: detects if AO process died, handles crash recovery
4. Capture scan: detects new/modified `.pcapng` files, filters whitelist, triggers handshake events
5. Adaptive throttle: adjusts injection delay based on stability (if enabled)
6. Crash count reset: clears after 5 minutes of stability

### Capture Detection

The plugin tracks files by path and modification time (mtime). This catches:
- **New files** — AO created a new capture (increments counter, triggers mood)
- **Modified files** — AO appended data to existing capture (triggers handshake event, no counter increment)
- **Deleted files** — automatically cleaned from tracking

New captures are:
- Filtered against the `main.whitelist` config (same normalization as core: lowercase, alphanumeric-only, substring match)
- Copied to the bettercap handshakes directory if different from AO output
- Fired as `handshake` plugin events (for wigle, wpa-sec, pwncrack, etc.)
- Registered in `agent._handshakes` so the session counter and display include them
- Trigger the happy face via `agent._update_handshakes()`

### Crash Recovery

When AO dies:
1. Crash counter increments, stable epoch counter resets
2. If `max_crashes` reached: stops permanently (UI shows "ERR", webhook available to reset)
3. If `adaptive_throttle` enabled: injection delay increases by 50%
4. If brcmfmac detected: checks kernel logs for firmware crash signature (`-110` / `firmware has halted`)
   - Runs modprobe recovery cycle: `monstop` → `modprobe -r brcmfmac` → `modprobe brcmfmac` → `monstart`
   - Polls `/sys/class/net/<iface>` up to 5 times (2s apart) to verify interface returned
   - If interface never comes back: does **not** restart AO
5. Exponential backoff before restart: `min(5 * 2^(crashes-1), 300)` seconds
6. After 5 minutes of stability, crash count resets to 0

## Configuration

All options go under `[main.plugins.angryoxide]` in your config.

### Core Options

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `false` | Enable the plugin |
| `binary_path` | `/usr/local/bin/angryoxide` | Path to the AO binary |
| `interface` | `wlan0mon` | Monitor-mode interface to use |
| `output_dir` | `/etc/pwnagotchi/handshakes/` | Where AO writes `.pcapng` captures |
| `nexmon_mode` | `true` | Enable injection throttling for brcmfmac/nexmon chips |
| `injection_delay_ms` | `500` | Milliseconds between injected frames (~2 fps) |
| `channel_dwell_ms` | `5000` | Milliseconds to dwell per channel (nexmon needs >100ms) |
| `notx` | `false` | Passive-only mode (capture only, no injection) |
| `extra_args` | `""` | Additional AO CLI arguments (space-separated) |

### Resilience Options

| Option | Default | Description |
|--------|---------|-------------|
| `max_crashes` | `10` | Stop retrying after this many crashes |
| `adaptive_throttle` | `false` | Auto-tune `injection_delay_ms` based on stability |
| `delay_min` | `100` | Minimum injection delay for adaptive throttle (ms) |
| `delay_max` | `2000` | Maximum injection delay for adaptive throttle (ms) |

### Display Options

| Option | Default | Description |
|--------|---------|-------------|
| `position` | auto | UI element position as `"x, y"` string. Auto-places if not set. |

## Display

The plugin adds an `AO:` element to the pwnagotchi display showing:

| State | Display | Meaning |
|-------|---------|---------|
| Running | `AO: 5` | Number of unique captures this session |
| Stopped | `AO: off` | AO process is not running |
| Error | `AO: ERR` | Permanently stopped after `max_crashes` exceeded |

New captures also update the main handshake counter (`shakes`) and trigger the happy face.

## Adaptive Throttle

When `adaptive_throttle = true`, the plugin auto-tunes `injection_delay_ms` to find the fastest stable rate for your hardware:

- **On crash**: delay increases by 50% (capped at `delay_max`)
- **After 20 stable epochs**: delay decreases by 10% (floored at `delay_min`)
- **Compounding**: successive crashes keep increasing; stability slowly recovers

The adjusted delay takes effect on the next AO restart. The current value is visible in the webhook status endpoint.

Example progression after a crash at 500ms default:
```
crash 1:  500 → 750ms
crash 2:  750 → 1125ms
(stable for 20 epochs): 1125 → 1012ms
(stable for 20 more):   1012 → 910ms
...
```

## Webhook API

The plugin exposes three HTTP endpoints through the pwnagotchi web UI webhook system.

### GET /plugins/angryoxide/status

Returns JSON with current plugin state:

```json
{
  "running": true,
  "pid": 1234,
  "captures": 5,
  "crash_count": 2,
  "fw_crash_count": 1,
  "injection_delay_ms": 750,
  "stable_epochs": 10,
  "is_brcmfmac": true,
  "stopped_permanently": false
}
```

Also accessible via `/plugins/angryoxide/` or `/plugins/angryoxide`.

### GET /plugins/angryoxide/captures

Returns the last 50 tracked capture files sorted by modification time (newest first):

```json
[
  {"file": "AA-BB-CC-DD-EE-FF_MyNetwork.pcapng", "mtime": 1710000000.0},
  {"file": "11-22-33-44-55-66_OtherNet.pcapng", "mtime": 1709999000.0}
]
```

### POST /plugins/angryoxide/reset

Resets `stopped_permanently` and `crash_count` so the plugin will retry on the next epoch. Use this after the plugin has given up due to `max_crashes`.

```json
{"status": "ok", "message": "crash state reset"}
```

## Whitelist

The plugin respects pwnagotchi's `main.whitelist` configuration. Captures matching any whitelist entry are silently skipped (not counted, not triggered, not copied).

Matching uses the same normalization as the core `utils.remove_whitelisted()`:
- Filename is stripped of `.pcapng`/`.pcap` extension
- Both filename and whitelist entry are lowercased and reduced to alphanumeric characters only
- Match is **substring**: whitelist entry `"HomeNet"` matches `AA-BB-CC-DD-EE-FF_HomeNetwork5G.pcapng`

Whitelist entries can be SSIDs, MAC addresses, or MAC prefixes:

```toml
[main]
whitelist = [
    "MyHomeNetwork",
    "aa:bb:cc:dd:ee:ff",
    "aa:bb:cc",
]
```

## Troubleshooting

### AO not starting
- Check binary exists: `ls -la /usr/local/bin/angryoxide`
- Check logs: `grep angryoxide /etc/pwnagotchi/log/pwnagotchi.log`
- The plugin will retry each epoch if the binary appears later

### Display shows "ERR"
- Plugin hit `max_crashes` and stopped permanently
- Check logs for crash details
- Reset via webhook: `curl -X POST http://<pwn-ip>:8080/plugins/angryoxide/reset`
- Or increase `max_crashes` in config

### Firmware crashes on brcmfmac (Pi Zero 2W / Pi 3/4)
- Ensure `nexmon_mode = true` (default)
- Increase `injection_delay_ms` (try 1000 or higher)
- Enable `adaptive_throttle = true` to let the plugin find a stable rate
- Check `fw_crash_count` in the webhook status

### Captures not showing on display counter
- The parenthesized total in `shakes` counts only `.pcap` files (core limitation)
- The `AO:` element shows the correct AO-specific count
- Session counter (`shakes` left number) does include AO captures

### Downstream plugins not seeing captures
- Verify `output_dir` matches or differs from `bettercap.handshakes` — the plugin copies if they differ
- Check that the capture isn't being filtered by whitelist
- Look for `[angryoxide] new capture:` log lines

## Changelog

### v0.3.0
- **Fixed**: Subprocess pipe deadlock — AO no longer hangs when stdout/stderr buffer fills
- **Fixed**: Process group kill race — cached pgid prevents crash when process exits between SIGTERM and SIGKILL
- **Added**: Recovery verification — polls for interface after modprobe cycle, blocks restart if interface missing
- **Added**: Exponential restart backoff (5s to 300s) with configurable `max_crashes` limit
- **Added**: Mtime-based file detection — catches modified captures, not just new ones
- **Added**: Whitelist filtering — respects `main.whitelist`, same matching as core
- **Added**: Handshake display integration — AO captures update shakes counter and trigger happy face
- **Added**: Adaptive injection delay — auto-tunes based on crash/stability patterns
- **Added**: Webhook API — status, captures list, and crash reset endpoints
- **Added**: 4 new config options: `max_crashes`, `adaptive_throttle`, `delay_min`, `delay_max`

### v0.2.0
- Initial release with bettercap integration, nexmon_mode, brcmfmac detection, firmware crash recovery
