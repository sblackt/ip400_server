import os
import struct
import random
from typing import Tuple

CHAR_MAP = "0123456789 ABCDEFGHIJKLMNOPQRSTUVWXYZ_-@"
CHAR_TO_INDEX = {c: i for i, c in enumerate(CHAR_MAP)}
MAX_CALLSIGN_LEN = 6
HEADER_SIZE = 24
MAGIC_EYE = b"IP4C"
CODING_MASK = 0x0F
CODING_TEXT = 0x00
CODING_DATA = 0x03
CODING_IP_ENCAP = 0x05
CODING_LOCAL_COMMAND = 0x0F


class CallsignEncodingError(ValueError):
    pass


def encode_excess40_callsign(callsign: str) -> bytes:
    """
    Encode a callsign using the Excess-40 compression used by the IP400.
    Returns a 4-byte little-endian representation suitable for the frame header.
    """
    if callsign.upper() == "BROADCAST":
        return b"\xff\xff\xff\xff"

    clean = (callsign or "").upper().strip()
    if len(clean) > MAX_CALLSIGN_LEN:
        raise CallsignEncodingError(f"Callsign '{callsign}' longer than {MAX_CALLSIGN_LEN} characters")

    # Pad with spaces to ensure deterministic encoding
    padded = clean.ljust(MAX_CALLSIGN_LEN)
    value = 0
    for char in padded:
        if char not in CHAR_TO_INDEX:
            raise CallsignEncodingError(f"Unsupported character '{char}' in callsign '{callsign}'")
        value = value * 40 + CHAR_TO_INDEX[char]

    return struct.pack("<I", value)


def build_ip4c_frame(
    from_call: str,
    from_port: int,
    to_call: str,
    to_port: int,
    coding: int,
    flags: int,
    payload: bytes,
    *,
    status: int = 1,
    offset: int = 0,
    hop_table: bytes = b"",
) -> bytes:
    """
    Construct an IP4C frame (header + hop table + payload).
    """
    if not (0 <= len(payload) <= 1025):
        raise ValueError("Payload must be between 0 and 1025 bytes")

    header = bytearray(HEADER_SIZE)
    header[:4] = MAGIC_EYE
    header[4] = status & 0xFF
    header[5] = (offset >> 8) & 0xFF
    header[6] = offset & 0xFF
    length = len(payload)
    header[7] = (length >> 8) & 0xFF
    header[8] = length & 0xFF

    header[9:13] = encode_excess40_callsign(from_call)
    header[13:15] = struct.pack(">H", from_port & 0xFFFF)
    header[15:19] = encode_excess40_callsign(to_call)
    header[19:21] = struct.pack(">H", to_port & 0xFFFF)
    header[21] = coding & 0xFF
    hop_entries = len(hop_table) // 4 if hop_table else 0
    header[22] = hop_entries & 0xFF
    header[23] = flags & 0xFF

    if hop_table:
        return bytes(header) + hop_table + payload
    return bytes(header) + payload


def build_local_command_frame(
    from_call: str,
    from_port: int,
    to_call: str,
    to_port: int,
    payload: bytes,
) -> bytes:
    return build_ip4c_frame(
        from_call=from_call,
        from_port=from_port,
        to_call=to_call,
        to_port=to_port,
        coding=CODING_LOCAL_COMMAND,
        flags=0,
        payload=payload,
    )


def random_file_id() -> int:
    return random.randint(0, 0xFFFF)


def callsign_from_env(var_name: str, default: str) -> str:
    return os.getenv(var_name, default)
