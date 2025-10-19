import socket
import threading
import time
from typing import Callable, Dict, Optional

from ip4c_utils import build_local_command_frame


class LocalCommandTimeout(Exception):
    """Raised when a local command does not receive a response in time."""


class LocalCommandManager:
    def __init__(
        self,
        spi_host: str,
        spi_port: int,
        callsign_provider: Callable[[], str],
        from_port: int,
        to_port: int,
    ):
        self.spi_host = spi_host
        self.spi_port = spi_port
        self.callsign_provider = callsign_provider
        self.from_port = from_port
        self.to_port = to_port

        self._seq_lock = threading.Lock()
        self._seq = 1
        self._pending: Dict[int, Dict[str, object]] = {}
        self._pending_lock = threading.Lock()

    def _next_seq(self) -> int:
        with self._seq_lock:
            value = self._seq
            self._seq = (self._seq + 1) & 0xFFFF
            if self._seq == 0:
                self._seq = 1
            return value

    def send_command(self, command: str, params: Optional[Dict[str, str]] = None, timeout: float = 3.0) -> Dict[str, str]:
        seq = self._next_seq()
        lines = [f"seq:{seq}", f"cmd:{command}"]
        if params:
            for key, value in params.items():
                lines.append(f"{key}:{value}")
        payload = ("\n".join(lines) + "\n").encode("utf-8")

        frame = build_local_command_frame(
            from_call=self.callsign_provider()[:6],
            from_port=self.from_port,
            to_call="LOCAL",
            to_port=self.to_port,
            payload=payload,
        )

        result_event = threading.Event()
        with self._pending_lock:
            self._pending[seq] = {"event": result_event, "response": None}

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(frame, (self.spi_host, self.spi_port))
        finally:
            sock.close()

        if not result_event.wait(timeout):
            with self._pending_lock:
                self._pending.pop(seq, None)
            raise LocalCommandTimeout(f"Local command '{command}' timed out")

        with self._pending_lock:
            entry = self._pending.pop(seq, None)

        if not entry or entry.get("response") is None:
            raise LocalCommandTimeout(f"Local command '{command}' returned no response")

        return entry["response"]  # type: ignore[return-value]

    def handle_response(self, payload: bytes) -> None:
        data = self._parse_payload(payload)
        if not data:
            return

        seq = int(data.get("seq", "0"))
        with self._pending_lock:
            entry = self._pending.get(seq)
            if not entry:
                return
            entry["response"] = data
            event: threading.Event = entry["event"]  # type: ignore[assignment]
            event.set()

    @staticmethod
    def _parse_payload(payload: bytes) -> Dict[str, str]:
        try:
            text = payload.decode("utf-8", errors="ignore")
        except Exception:
            return {}
        result: Dict[str, str] = {}
        for line in text.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            result[key.strip()] = value.strip()
        return result
