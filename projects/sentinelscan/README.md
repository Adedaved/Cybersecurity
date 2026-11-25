# SentinelScan

SentinelScan is a bounded asynchronous TCP exposure scanner for authorized environments. It records what it directly observes—open ports, limited service banners, and TLS certificate metadata—without claiming that a version string proves exploitation.

## Architecture

`CLI -> scope validation -> bounded async probes -> evidence normalization -> JSON/text report`

## Usage

```bash
python projects/sentinelscan/sentinelscan.py --acknowledge-authorization 127.0.0.1 --ports 22,80,443
python projects/sentinelscan/sentinelscan.py --acknowledge-authorization localhost --ports 8000-8010 --json
```

The acknowledgement flag is mandatory. Targets resolving to more than 16 addresses are rejected, port lists are capped at 1,024 entries, concurrency is bounded, and every connection has a timeout.

## Sample output

```text
SentinelScan target=127.0.0.1 addresses=127.0.0.1
OPEN  127.0.0.1:443  service=https  tls=certificate_error  error=SSLCertVerificationError
REFUSED  127.0.0.1:80  service=http  tls=not_attempted  error=ConnectionRefusedError
TIMEOUT  127.0.0.1:22  service=ssh  tls=not_attempted  error=TimeoutError
Summary: 1 open / 3 tested
```

## Reading TCP and TLS results

The JSON `state` field reports TCP connectivity as `open`, `refused`, `timeout`, or `connection_error`. The separate `tls_state` field reports `verified`, `certificate_error`, `handshake_error`, `timeout`, or `not_attempted`. A TLS failure leaves the TCP state as `open`. This replaces the old `closed_or_filtered` classification.

TLS connects to each resolved IP and uses the requested DNS name for SNI and certificate verification. For IP literal targets, the certificate must cover that IP. Certificate verification stays enabled, and `--timeout` applies separately to TCP connect and TLS negotiation.

## Limitations

- TCP connect scanning only; no raw packets or evasion.
- Service names are hints based on common port assignments.
- TLS is attempted only on common TLS ports.
- A closed port is not evidence that a service is absent behind another interface or firewall.
