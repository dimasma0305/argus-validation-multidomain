#!/usr/bin/env python3
"""Route a benchmark container's public-domain request to its published peer.

Docker containers resolve *.localhost to their own loopback. The controller
attaches this proxy to the case network so browser callbacks to the public
benchmark URL reach the same service that a host-side agent sees.
"""

import json
import os
import socket
import threading


def copy_stream(source: socket.socket, destination: socket.socket) -> None:
    try:
        while chunk := source.recv(65536):
            destination.sendall(chunk)
    except OSError:
        pass
    finally:
        try:
            destination.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle(client: socket.socket, host: str, port: int) -> None:
    with client:
        try:
            with socket.create_connection((host, port), timeout=10) as upstream:
                left = threading.Thread(target=copy_stream, args=(client, upstream))
                right = threading.Thread(target=copy_stream, args=(upstream, client))
                left.start()
                right.start()
                left.join()
                right.join()
        except OSError:
            pass


def listen(public_port: int, host: str, target_port: int) -> None:
    with socket.create_server(("0.0.0.0", public_port)) as server:
        while True:
            client, _ = server.accept()
            threading.Thread(target=handle, args=(client, host, target_port), daemon=True).start()


def main() -> None:
    routes = json.loads(os.environ["PUBLIC_PORT_ROUTES"])
    threads = []
    for public_port, (host, target_port) in routes.items():
        thread = threading.Thread(
            target=listen, args=(int(public_port), host, int(target_port))
        )
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()
