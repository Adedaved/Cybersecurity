#!/usr/bin/env python3
"""Explainable, static-only file triage that never executes its input."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from collections import Counter
from pathlib import Path

STRING_PATTERN = re.compile(rb"[\x20-\x7e]{4,}")
INDICATORS = {
    "network-primitive": [b"http://", b"https://", b"User-Agent", b"socket"],
    "command-execution-primitive": [b"CreateProcess", b"WinExec", b"/bin/sh", b"cmd.exe", b"powershell"],
    "persistence-related-string": [b"CurrentVersion\\Run", b"crontab", b"systemd"],
}


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def file_type(data: bytes) -> str:
    if data.startswith(b"MZ"):
        return "PE"
    if data.startswith(b"\x7fELF"):
        return "ELF"
    if data.startswith(b"#!"):
        return "script"
    if data.startswith(b"PK\x03\x04"):
        return "ZIP"
    return "unknown"


def analyze(path: Path, max_bytes: int = 25_000_000) -> dict[str, object]:
    stat = path.stat()
    if not path.is_file():
        raise ValueError("input must be a regular file")
    if stat.st_size > max_bytes:
        raise ValueError(f"file exceeds the {max_bytes}-byte analysis limit")
    data = path.read_bytes()
    strings = [match.decode("ascii", errors="replace") for match in STRING_PATTERN.findall(data)]
    score = entropy(data)
    findings: list[dict[str, str]] = []
    if score >= 7.2 and len(data) >= 256:
        findings.append({"severity": "medium", "indicator": "high-entropy-content", "evidence": f"entropy {score:.2f} may indicate compression, encryption, or packing"})
    lowered = data.lower()
    for category, needles in INDICATORS.items():
        matched = [needle.decode("ascii", errors="replace") for needle in needles if needle.lower() in lowered]
        if matched:
            findings.append({"severity": "informational", "indicator": category, "evidence": ", ".join(matched)})
    return {
        "tool": "SafeTrace",
        "sample": path.name,
        "size": len(data),
        "type": file_type(data),
        "entropy": round(score, 4),
        "hashes": {"sha256": hashlib.sha256(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest()},
        "strings_preview": strings[:40],
        "findings": findings,
        "verdict": "manual-review-required" if findings else "no-listed-indicators-observed",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sample", type=Path)
    parser.add_argument("--max-bytes", type=int, default=25_000_000)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        result = analyze(args.sample, args.max_bytes)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"SafeTrace sample={result['sample']} type={result['type']} size={result['size']} entropy={result['entropy']}")
        print(f"SHA256 {result['hashes']['sha256']}")
        for finding in result["findings"]:
            print(f"[{finding['severity']}] {finding['indicator']}: {finding['evidence']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
