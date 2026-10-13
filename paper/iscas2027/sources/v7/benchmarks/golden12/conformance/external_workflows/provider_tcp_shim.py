#!/usr/bin/env python3
"""Expose one mounted provider Unix socket on container loopback only."""
from __future__ import annotations

import argparse
import selectors
from pathlib import Path
import socket
import socketserver
import threading


class RelayHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        upstream.connect(str(self.server.provider_socket))  # type: ignore[attr-defined]
        sockets = (self.request, upstream)
        selector = selectors.DefaultSelector()
        for item in sockets:
            item.setblocking(False)
            selector.register(item, selectors.EVENT_READ)
        try:
            open_read = set(sockets)
            while open_read:
                for key, _mask in selector.select(timeout=30):
                    source = key.fileobj
                    assert isinstance(source, socket.socket)
                    target = upstream if source is self.request else self.request
                    data = source.recv(1024 * 1024)
                    if not data:
                        open_read.discard(source)
                        try:
                            target.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        continue
                    target.sendall(data)
        finally:
            selector.close()
            upstream.close()


class LoopbackRelay(socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = True

    def __init__(self, address: tuple[str, int], provider_socket: Path) -> None:
        self.provider_socket = provider_socket
        super().__init__(address, RelayHandler)


def start_relay(provider_socket: Path, port: int) -> tuple[LoopbackRelay, threading.Thread]:
    if provider_socket.is_symlink() or not provider_socket.is_socket():
        raise ValueError("provider broker socket is unavailable or unsafe")
    server = LoopbackRelay(("127.0.0.1", port), provider_socket)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider-socket", type=Path, required=True)
    parser.add_argument("--port", type=int, default=18080)
    args = parser.parse_args()
    server, thread = start_relay(args.provider_socket, args.port)
    try:
        thread.join()
    finally:
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
