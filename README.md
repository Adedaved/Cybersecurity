# Cybersecurity Engineering Portfolio

A collection of defensive security tools and research projects focused on vulnerability discovery, attack-surface analysis, reverse engineering, and safe behavioral analysis.

> [!IMPORTANT]
> These projects are intended only for systems you own or have explicit permission to test. The tools include scope and safety controls, but authorization remains the operator's responsibility.

## Projects

| Project | Purpose | Engineering evidence |
|---|---|---|
| [SentinelScan](projects/sentinelscan/) | Asynchronous TCP and TLS exposure scanner | Networking, concurrency, failure handling, structured reporting |
| [ReconGraph](projects/recongraph/) | Passive-first DNS and HTTP attack-surface mapper | Backend design, SQLite, evidence provenance, change detection |
| [SafeTrace](projects/safetrace/) | Static triage for suspicious PE/ELF files | Binary analysis, entropy, indicators, explainable findings |
| [BehaviorLab](projects/behaviorlab/) | Harmless attack-behavior simulator | Detection engineering, observability, cleanup and regression tests |

All four projects use only the Python standard library, work with Python 3.9+, and include automated tests. They are intentionally small enough to audit and extend.

## Quick start

```bash
git clone https://github.com/Adedaved/Cybersecurity.git
cd Cybersecurity
python -m unittest discover -s tests -v
```

Run a tool from the repository root:

```bash
python projects/sentinelscan/sentinelscan.py --acknowledge-authorization 127.0.0.1 --ports 22,80,443
python projects/recongraph/recongraph.py example.com --output recon.db
python projects/safetrace/safetrace.py path/to/a/benign-training-file
python projects/behaviorlab/behaviorlab.py --workspace /tmp/behavior-lab
```

## What this portfolio demonstrates

- Analysis and remediation of software defects and security weaknesses across network, web, and binary contexts.
- Backend engineering with async I/O, persistent data models, deterministic output, and defensive error handling.
- Communication of technical evidence through documented methodology, structured findings, limitations, and remediation guidance.

See [PORTFOLIO.md](PORTFOLIO.md) for the evidence map and [SECURITY.md](SECURITY.md) for responsible disclosure.

## Development

```bash
python -m compileall projects
python -m unittest discover -s tests -v
```

No live malware samples, exploit payloads, credential attacks, stealth features, or persistence mechanisms are included.
