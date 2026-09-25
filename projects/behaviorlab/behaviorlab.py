#!/usr/bin/env python3
"""Generate harmless, local-only telemetry for defensive detection testing."""

from __future__ import annotations

import argparse
import json
import socket
import threading
from datetime import datetime, timezone
from pathlib import Path


class EventLog:
    def __init__(self, path: Path) -> None:
        self.path = path

    def write(self, action: str, object_name: str, simulation: str) -> None:
        event = {"timestamp": datetime.now(timezone.utc).isoformat(), "action": action, "object": object_name, "simulation": simulation}
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, sort_keys=True) + "\n")


def loopback_exchange(log: EventLog) -> None:
    ready = threading.Event()
    port_holder: list[int] = []

    def server() -> None:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port_holder.append(listener.getsockname()[1])
            ready.set()
            connection, _ = listener.accept()
            with connection:
                data = connection.recv(64)
                connection.sendall(b"LAB-ACK:" + data)

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    if not ready.wait(timeout=2):
        raise TimeoutError("loopback lab server did not start")
    with socket.create_connection(("127.0.0.1", port_holder[0]), timeout=2) as client:
        client.sendall(b"BENIGN-HEARTBEAT")
        response = client.recv(64)
    thread.join(timeout=2)
    log.write("loopback-exchange", response.decode("ascii"), "mock-command-and-control")


def run(workspace: Path) -> Path:
    workspace = workspace.resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    log = EventLog(workspace / "events.jsonl")
    decoys = workspace / "generated-decoys"
    decoys.mkdir(exist_ok=True)
    for name in ("budget-demo.txt", "roadmap-demo.txt"):
        path = decoys / name
        path.write_text("synthetic training content\n", encoding="utf-8")
        _ = path.read_text(encoding="utf-8")
        log.write("read", str(path.relative_to(workspace)), "file-discovery")
    marker = workspace / "simulated-autostart.json"
    marker.write_text('{"disabled": true, "purpose": "defensive training"}\n', encoding="utf-8")
    log.write("create", marker.name, "persistence-marker")
    loopback_exchange(log)
    marker.unlink()
    log.write("remove", marker.name, "cleanup")
    return log.path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path, help="dedicated directory for generated lab artifacts")
    args = parser.parse_args()
    path = run(args.workspace)
    print(f"BehaviorLab complete; telemetry={path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
