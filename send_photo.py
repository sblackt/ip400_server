#!/usr/bin/env python3
"""
CLI helper to transmit images over the IP400 mesh by wrapping them into data frames.

Example:
  python3 -m ip400_server.send_photo --from-call VE3XYZ --image ./snapshot.jpg --to-call BROADCAST
"""
import argparse
import sys
from pathlib import Path
from typing import List, Optional, Tuple

from photo_sender import (
    PhotoSendError,
    parse_resize,
    send_photo_bytes,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Transmit an image over the IP400 RF mesh.")
    parser.add_argument("--image", required=True, type=Path, help="Path to the input image file")
    parser.add_argument("--from-call", required=True, help="Source callsign (up to 6 chars)")
    parser.add_argument("--to-call", default="BROADCAST", help="Destination callsign (default BROADCAST)")
    parser.add_argument("--from-port", type=int, default=100, help="Source port number (default 100)")
    parser.add_argument("--to-port", type=int, default=100, help="Destination port number (default 100)")
    parser.add_argument("--udp-host", default="127.0.0.1", help="UDP host for ip400spi (default 127.0.0.1)")
    parser.add_argument("--udp-port", type=int, default=8400, help="UDP port for ip400spi (default 8400)")
    parser.add_argument("--max-payload", type=int, default=900, help="Max payload bytes per frame (<=1025)")
    parser.add_argument("--delay", type=float, default=0.3, help="Delay between frames (seconds)")
    parser.add_argument(
        "--resize",
        type=parse_resize,
        help="Resize image to WIDTHxHEIGHT before sending (requires Pillow). Example: 320x240",
    )
    parser.add_argument("--quality", type=int, default=75, help="JPEG quality when resizing (default 75)")
    parser.add_argument("--file-id", type=lambda x: int(x, 0), help="Override file/session id (0-65535)")
    parser.add_argument("--repeatable", action="store_true", help="Set repeat flag so relays may retransmit")
    parser.add_argument(
        "--disable-connectionless",
        action="store_true",
        help="Clear connectionless flag (bit 1) if you need a connected frame",
    )
    return parser


def main(argv: List[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.image.exists():
        print(f"Image file '{args.image}' does not exist.", file=sys.stderr)
        return 1

    image_bytes = args.image.read_bytes()

    try:
        result = send_photo_bytes(
            image_bytes=image_bytes,
            filename=args.image.name,
            resize=args.resize,
            quality=args.quality,
            max_payload=args.max_payload,
            delay=args.delay,
            udp_host=args.udp_host,
            udp_port=args.udp_port,
            from_call=args.from_call,
            from_port=args.from_port,
            to_call=args.to_call,
            to_port=args.to_port,
            repeatable=args.repeatable,
            connectionless=not args.disable_connectionless,
            file_id=args.file_id,
        )
    except PhotoSendError as exc:
        print(f"Photo send error: {exc}", file=sys.stderr)
        return 2

    print(
        f"[DONE] Sent {result['filename']} ({result['bytes']} bytes) "
        f"in {result['chunks']} frames (file_id=0x{result['file_id']:04X})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

