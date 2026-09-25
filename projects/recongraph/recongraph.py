#!/usr/bin/env python3
"""Passive-first, scope-aware domain inventory with SQLite evidence."""

from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import socket
import sqlite3
import ssl
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY, root TEXT NOT NULL, scanned_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS observations(
  run_id INTEGER NOT NULL, hostname TEXT NOT NULL, address TEXT,
  scheme TEXT, status INTEGER, server TEXT, location TEXT, error TEXT,
  FOREIGN KEY(run_id) REFERENCES runs(id)
);
"""


def normalize_names(root: str, names: str) -> list[str]:
    root = root.strip(".").lower()
    candidates = {root}
    for raw in names.split(","):
        name = raw.strip(".").lower()
        if not name:
            continue
        candidate = name if name == root or name.endswith("." + root) else f"{name}.{root}"
        if candidate != root and not candidate.endswith("." + root):
            raise ValueError(f"out-of-scope name: {raw}")
        candidates.add(candidate)
    return sorted(candidates)


def resolve(hostname: str) -> tuple[list[str], str | None]:
    try:
        records = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        return sorted({record[4][0] for record in records}), None
    except socket.gaierror as exc:
        return [], type(exc).__name__


def request_metadata(hostname: str, scheme: str, timeout: float) -> dict[str, object]:
    connection_class = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
    kwargs: dict[str, object] = {"timeout": timeout}
    if scheme == "https":
        kwargs["context"] = ssl.create_default_context()
    try:
        connection = connection_class(hostname, 443 if scheme == "https" else 80, **kwargs)
        connection.request("HEAD", "/", headers={"User-Agent": "ReconGraph/1.0"})
        response = connection.getresponse()
        result = {"scheme": scheme, "status": response.status, "server": response.getheader("Server"), "location": response.getheader("Location"), "error": None}
        connection.close()
        return result
    except (OSError, TimeoutError, ssl.SSLError, http.client.HTTPException) as exc:
        return {"scheme": scheme, "status": None, "server": None, "location": None, "error": type(exc).__name__}


def collect(root: str, names: list[str], timeout: float = 2.0) -> list[dict[str, object]]:
    observations: list[dict[str, object]] = []
    for hostname in names:
        addresses, dns_error = resolve(hostname)
        if dns_error:
            observations.append({"hostname": hostname, "address": None, "scheme": None, "status": None, "server": None, "location": None, "error": dns_error})
            continue
        safe_addresses = [str(ipaddress.ip_address(address)) for address in addresses]
        for address in safe_addresses:
            for scheme in ("https", "http"):
                observations.append({"hostname": hostname, "address": address, **request_metadata(hostname, scheme, timeout)})
    return observations


def save(database: Path, root: str, observations: list[dict[str, object]]) -> int:
    with sqlite3.connect(database) as connection:
        connection.executescript(SCHEMA)
        cursor = connection.execute("INSERT INTO runs(root, scanned_at) VALUES (?, ?)", (root, datetime.now(timezone.utc).isoformat()))
        run_id = int(cursor.lastrowid)
        connection.executemany(
            "INSERT INTO observations(run_id, hostname, address, scheme, status, server, location, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [(run_id, item["hostname"], item["address"], item["scheme"], item["status"], item["server"], item["location"], item["error"]) for item in observations],
        )
    return run_id


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("domain")
    parser.add_argument("--names", default="www")
    parser.add_argument("--output", type=Path, default=Path("recongraph.db"))
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        names = normalize_names(args.domain, args.names)
    except ValueError as exc:
        parser.error(str(exc))
    observations = collect(args.domain, names, args.timeout)
    run_id = save(args.output, args.domain, observations)
    result = {"tool": "ReconGraph", "root": args.domain, "run_id": run_id, "database": str(args.output), "observations": observations}
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"ReconGraph root={args.domain} run={run_id}")
        for item in observations:
            outcome = item["error"] or f"{item['scheme']}:{item['status']}"
            print(f"{item['hostname']} {item['address'] or '-'} {outcome}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
