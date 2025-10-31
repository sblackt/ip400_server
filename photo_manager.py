import os
import time
import struct
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple, List

PHOTO_MAGIC = b"IPPH"
PHOTO_VERSION = 1
CHUNK_HEADER = struct.Struct(">4sBHHH")
HEADER_SIZE = CHUNK_HEADER.size


class PhotoChunkError(Exception):
    pass


@dataclass
class PhotoSession:
    source_call: str
    file_id: int
    total_chunks: int
    created: float = field(default_factory=time.time)
    filename: Optional[str] = None
    chunks: Dict[int, bytes] = field(default_factory=dict)

    def add_chunk(self, seq: int, data: bytes, filename: Optional[str] = None) -> None:
        if seq in self.chunks:
            return
        if filename:
            self.filename = filename
        self.chunks[seq] = data

    def is_complete(self) -> bool:
        return len(self.chunks) == self.total_chunks and self.filename is not None

    def assemble(self) -> bytes:
        return b"".join(self.chunks[i] for i in range(self.total_chunks))


class PhotoManager:
    def __init__(self, storage_dir: str = "photos", history: int = 10):
        self.storage_dir = storage_dir
        self.history = history
        self._lock = threading.Lock()
        os.makedirs(self.storage_dir, exist_ok=True)
        self._sessions: Dict[Tuple[str, int], PhotoSession] = {}
        self._photos: deque = deque(maxlen=history)

    def parse_chunk(self, payload: bytes) -> Tuple[int, int, int, Optional[str], bytes]:
        if len(payload) < HEADER_SIZE:
            raise PhotoChunkError("Payload too small for photo chunk header")

        magic, version, file_id, seq, total = CHUNK_HEADER.unpack_from(payload)
        if magic != PHOTO_MAGIC or version != PHOTO_VERSION:
            raise PhotoChunkError("Invalid photo chunk header")
        if total == 0:
            raise PhotoChunkError("Total chunk count cannot be zero")
        if seq >= total:
            raise PhotoChunkError("Chunk sequence exceeds total count")

        cursor = HEADER_SIZE
        filename = None
        if seq == 0:
            if cursor >= len(payload):
                raise PhotoChunkError("Missing filename length in first chunk")
            name_len = payload[cursor]
            cursor += 1
            if cursor + name_len > len(payload):
                raise PhotoChunkError("Filename truncated in chunk")
            filename = payload[cursor : cursor + name_len].decode("utf-8", errors="ignore") or "photo.bin"
            cursor += name_len

        data = payload[cursor:]
        return file_id, seq, total, filename, data

    def handle_frame(self, source_call: str, payload: bytes) -> Optional[Dict]:
        try:
            file_id, seq, total, filename, data = self.parse_chunk(payload)
        except PhotoChunkError as exc:
            print(f"[PHOTO] Ignoring invalid chunk from {source_call}: {exc}")
            return None

        key = (source_call, file_id)
        with self._lock:
            session = self._sessions.get(key)
            if session is None:
                session = PhotoSession(source_call=source_call, file_id=file_id, total_chunks=total)
                self._sessions[key] = session

            session.add_chunk(seq, data, filename)

            if not session.is_complete():
                return None

            blob = session.assemble()
            safe_name = self._safe_filename(session.filename or f"{file_id:04X}.bin")
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            disk_name = f"{timestamp}_{source_call}_{safe_name}"
            disk_path = os.path.join(self.storage_dir, disk_name)

            with open(disk_path, "wb") as f:
                f.write(blob)

            metadata = {
                "id": f"{source_call}-{file_id}",
                "source": source_call,
                "original_name": session.filename,
                "stored_name": disk_name,
                "path": disk_path,
                "size": len(blob),
                "chunks": session.total_chunks,
                "received_at": timestamp,
            }

            self._photos.appendleft(metadata)
            del self._sessions[key]
            print(f"[PHOTO] Stored {metadata['original_name']} ({metadata['size']} bytes) from {source_call}")
            return metadata

    def list_photos(self) -> List[Dict]:
        with self._lock:
            return list(self._photos)

    def get_photo(self, photo_id: str) -> Optional[Dict]:
        with self._lock:
            for item in self._photos:
                if item["id"] == photo_id:
                    return item
        return None

    def _safe_filename(self, name: str) -> str:
        cleaned = "".join(c for c in name if c.isalnum() or c in ("-", "_", ".", " "))
        return cleaned.strip().replace(" ", "_") or "photo.bin"

