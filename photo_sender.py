import struct
import socket
import time
from io import BytesIO
from pathlib import Path
from typing import Iterable, List, Optional, Tuple, Dict, Any

from ip4c_utils import build_ip4c_frame, random_file_id, CODING_DATA

try:
    from PIL import Image  # type: ignore

    PIL_AVAILABLE = True
except Exception:  # noqa: BLE001
    Image = None  # type: ignore
    PIL_AVAILABLE = False

PHOTO_MAGIC = b"IPPH"
PHOTO_VERSION = 1
CHUNK_HEADER_STRUCT = struct.Struct(">4sBHHH")
CHUNK_HEADER_SIZE = CHUNK_HEADER_STRUCT.size


class PhotoSendError(Exception):
    """Raised when preparing or sending a photo fails."""


def parse_resize(value: str) -> Tuple[int, int]:
    parts = value.lower().split("x")
    if len(parts) != 2:
        raise PhotoSendError("Resize must be WIDTHxHEIGHT (e.g., 320x240)")
    try:
        width = int(parts[0])
        height = int(parts[1])
    except ValueError as exc:  # noqa: BLE001
        raise PhotoSendError("Resize values must be integers") from exc
    if width <= 0 or height <= 0:
        raise PhotoSendError("Resize dimensions must be positive")
    return width, height


def _ensure_pillow() -> None:
    if not PIL_AVAILABLE:
        raise PhotoSendError(
            "Image resizing requires Pillow. Install with 'pip install Pillow' or omit resize options."
        )


def load_image_file(path: Path, resize: Optional[Tuple[int, int]], quality: int) -> Tuple[bytes, str]:
    data = path.read_bytes()
    return prepare_image_bytes(data, path.name, resize, quality)


def prepare_image_bytes(
    data: bytes,
    filename: str,
    resize: Optional[Tuple[int, int]],
    quality: int,
) -> Tuple[bytes, str]:
    """
    Optionally resize and recompress image data.
    Returns (processed_bytes, suggested_filename).
    """
    if not resize:
        return data, filename

    _ensure_pillow()
    buffer = BytesIO(data)
    with Image.open(buffer) as img:  # type: ignore
        img = img.convert("RGB")
        img.thumbnail(resize, Image.LANCZOS)  # type: ignore
        output = BytesIO()
        img.save(output, format="JPEG", quality=quality, optimize=True)
    processed = output.getvalue()
    new_name = Path(filename).with_suffix(".jpg").name
    return processed, new_name


def build_chunks(
    data: bytes,
    filename: str,
    max_payload: int,
    file_id: Optional[int] = None,
) -> Tuple[List[bytes], int]:
    """
    Slice photo bytes into IP400-friendly chunks.
    Returns (chunk_list, file_id).
    """
    if max_payload <= CHUNK_HEADER_SIZE + 4:
        raise PhotoSendError("Max payload too small for photo transfer")

    file_id = file_id if file_id is not None else random_file_id()
    filename_bytes = filename.encode("utf-8")[:255]

    first_overhead = CHUNK_HEADER_SIZE + 1 + len(filename_bytes)
    first_capacity = max_payload - first_overhead
    if first_capacity <= 0:
        raise PhotoSendError("Filename too long for chosen payload size")

    other_capacity = max_payload - CHUNK_HEADER_SIZE
    if other_capacity <= 0:
        raise PhotoSendError("Max payload too small")

    chunks: List[bytes] = []
    offset = 0

    # First chunk
    first_chunk = data[:first_capacity]
    offset += len(first_chunk)
    chunk_payloads = [first_chunk]
    while offset < len(data):
        next_chunk = data[offset : offset + other_capacity]
        chunk_payloads.append(next_chunk)
        offset += len(next_chunk)

    total_chunks = len(chunk_payloads)
    for seq, payload in enumerate(chunk_payloads):
        header = bytearray(CHUNK_HEADER_SIZE)
        header[:4] = PHOTO_MAGIC
        header[4] = PHOTO_VERSION
        header[5] = (file_id >> 8) & 0xFF
        header[6] = file_id & 0xFF
        header[7] = (seq >> 8) & 0xFF
        header[8] = seq & 0xFF
        header[9] = (total_chunks >> 8) & 0xFF
        header[10] = total_chunks & 0xFF
        chunk = bytearray(header)
        if seq == 0:
            chunk.append(len(filename_bytes))
            chunk.extend(filename_bytes)
        chunk.extend(payload)
        chunks.append(bytes(chunk))
    return chunks, file_id


def send_chunks(
    chunks: Iterable[bytes],
    *,
    udp_host: str,
    udp_port: int,
    from_call: str,
    from_port: int,
    to_call: str,
    to_port: int,
    flags: int,
    delay: float,
) -> None:
    chunk_list = list(chunks)
    total = len(chunk_list)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for idx, payload in enumerate(chunk_list):
            frame = build_ip4c_frame(
                from_call=from_call,
                from_port=from_port,
                to_call=to_call,
                to_port=to_port,
                coding=CODING_DATA,
                flags=flags,
                payload=payload,
            )
            sock.sendto(frame, (udp_host, udp_port))
            print(f"[PHOTO-TX] Chunk {idx + 1}/{total} ({len(payload)} bytes payload)")
            if delay:
                time.sleep(delay)
    finally:
        sock.close()


def send_photo_bytes(
    *,
    image_bytes: bytes,
    filename: str,
    resize: Optional[Tuple[int, int]],
    quality: int,
    max_payload: int,
    delay: float,
    udp_host: str,
    udp_port: int,
    from_call: str,
    from_port: int,
    to_call: str,
    to_port: int,
    repeatable: bool,
    connectionless: bool,
    file_id: Optional[int] = None,
) -> Dict[str, Any]:
    if not image_bytes:
        raise PhotoSendError("Image payload is empty")
    if max_payload > 1025:
        raise PhotoSendError("Max payload cannot exceed 1025 bytes")

    processed_bytes, name = prepare_image_bytes(image_bytes, filename, resize, quality)
    chunks, final_file_id = build_chunks(processed_bytes, name, max_payload, file_id=file_id)

    flags = 0
    if connectionless:
        flags |= 0x02
    if repeatable:
        flags |= 0x01

    send_chunks(
        chunks,
        udp_host=udp_host,
        udp_port=udp_port,
        from_call=from_call,
        from_port=from_port,
        to_call=to_call,
        to_port=to_port,
        flags=flags,
        delay=max(delay, 0.0),
    )

    return {
        "chunks": len(chunks),
        "bytes": len(processed_bytes),
        "file_id": final_file_id,
        "filename": name,
    }
