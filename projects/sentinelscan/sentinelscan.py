#!/usr/bin/env python3
"""Bounded TCP/TLS exposure scanner for explicitly authorized targets."""

from __future__ import annotations

import argparse
import asyncio
import json
import socket
import ipaddress
import ssl
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

COMMON_SERVICES = {21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb", 3306: "mysql", 5432: "postgresql", 6379: "redis", 8000: "http-alt", 8080: "http-proxy", 8443: "https-alt"}
TLS_PORTS = {443, 465, 636, 853, 993, 995, 8443}


@dataclass
class Finding:
    address: str
    port: int
    state: str
    service: str
    evidence: str
    banner: str | None = None
    tls: dict[str, object] | None = None
    error: str | None = None
    tls_state: str = "not_attempted"


def parse_ports(value: str) -> list[int]:
    ports: set[int] = set()
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        if "-" in item:
            start_text, end_text = item.split("-", 1)
            start, end = int(start_text), int(end_text)
            if start > end:
                raise ValueError(f"invalid range: {item}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(item))
    if not ports or any(port < 1 or port > 65535 for port in ports):
        raise ValueError("ports must be between 1 and 65535")
    if len(ports) > 1024:
        raise ValueError("a single run is limited to 1024 ports")
    return sorted(ports)


async def resolve_target(target: str) -> list[str]:
    loop = asyncio.get_running_loop()
    records = await loop.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    addresses = sorted({record[4][0] for record in records})
    if len(addresses) > 16:
        raise ValueError("target resolves to more than 16 addresses")
    return addresses


def _certificate_summary(cert: dict[str, object]) -> dict[str, object]:
    return {key: cert.get(key) for key in ("subject", "issuer", "notBefore", "notAfter") if cert.get(key)}


async def probe(address: str, port: int, timeout: float, *, target: str | None = None) -> Finding:
    result = Finding(address, port, "open", COMMON_SERVICES.get(port, "unknown"), "tcp-connect")
    family = socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setblocking(False)
    writer = None
    try:
        try:
            await asyncio.wait_for(asyncio.get_running_loop().sock_connect(sock, (address, port)), timeout)
        except (OSError, asyncio.TimeoutError) as exc:
            result.state = "refused" if isinstance(exc, ConnectionRefusedError) else (
                "timeout" if isinstance(exc, (TimeoutError, asyncio.TimeoutError)) else "connection_error"
            )
            result.evidence = "connection-failed"
            result.error = type(exc).__name__
            return result

        context = ssl.create_default_context() if port in TLS_PORTS else None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    sock=sock, ssl=context,
                    server_hostname=(target or address).rstrip(".") if context else None,
                ),
                timeout,
            )
        except (OSError, asyncio.TimeoutError) as exc:
            result.error = type(exc).__name__
            if context:
                if isinstance(exc, ssl.SSLCertVerificationError):
                    result.tls_state = "certificate_error"
                elif isinstance(exc, (TimeoutError, asyncio.TimeoutError)):
                    result.tls_state = "timeout"
                else:
                    result.tls_state = "handshake_error"
            return result

        ssl_object = writer.get_extra_info("ssl_object")
        if ssl_object:
            result.tls_state = "verified"
            result.tls = {
                "version": ssl_object.version(),
                "cipher": ssl_object.cipher()[0] if ssl_object.cipher() else None,
                "certificate": _certificate_summary(ssl_object.getpeercert()),
            }
        try:
            data = await asyncio.wait_for(reader.read(256), min(timeout, 0.4))
            if data:
                result.banner = data.decode("utf-8", errors="replace").strip()[:200]
        except (OSError, asyncio.TimeoutError):
            pass
        return result
    finally:
        if writer is None:
            sock.close()
        else:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout)
            except (OSError, asyncio.TimeoutError):
                writer.transport.abort()


async def scan(target: str, ports: list[int], timeout: float = 1.0, concurrency: int = 100) -> dict[str, object]:
    addresses = await resolve_target(target)
    semaphore = asyncio.Semaphore(max(1, min(concurrency, 256)))

    async def bounded(address: str, port: int) -> Finding:
        async with semaphore:
            return await probe(address, port, timeout, target=target)

    findings = await asyncio.gather(*(bounded(address, port) for address in addresses for port in ports))
    return {
        "tool": "SentinelScan",
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "addresses": addresses,
        "ports": ports,
        "findings": [asdict(finding) for finding in findings],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target")
    parser.add_argument("--ports", default="22,80,443,8080")
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--concurrency", type=int, default=100)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--acknowledge-authorization", action="store_true", help="confirm permission to test the target")
    args = parser.parse_args()
    if not args.acknowledge_authorization:
        parser.error("--acknowledge-authorization is required")
    try:
        result = asyncio.run(scan(args.target, parse_ports(args.ports), args.timeout, args.concurrency))
    except (ValueError, socket.gaierror) as exc:
        parser.error(str(exc))
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(f"SentinelScan target={result['target']} addresses={','.join(result['addresses'])}")
        open_findings = [item for item in result["findings"] if item["state"] == "open"]
        for item in result["findings"]:
            error = f"  error={item['error']}" if item["error"] else ""
            print(f"{item['state'].upper()}  {item['address']}:{item['port']}  service={item['service']}  tls={item['tls_state']}{error}")
        print(f"Summary: {len(open_findings)} open / {len(result['findings'])} tested")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
