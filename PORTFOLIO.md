# Portfolio Evidence Map

## 1. Analyze, debug, and resolve bugs and vulnerabilities

- SentinelScan distinguishes confirmed observations from version-based leads and preserves evidence for review.
- ReconGraph records provenance and scan history so inconsistent DNS and HTTP behavior can be reproduced.
- SafeTrace explains why each indicator was raised instead of presenting an opaque risk score.
- BehaviorLab produces deterministic, harmless telemetry for validating defensive detections.

## 2. Backend development for complex systems

- Bounded asynchronous network operations and timeout handling.
- SQLite persistence with explicit schemas and parameterized queries.
- Stable JSON interfaces suitable for CI and downstream automation.
- Regression tests for parsing, error paths, scope validation, and cleanup.

## 3. Clear technical communication

Every project documents its threat model, architecture, usage, sample output, limitations, and extension points. Findings use a consistent format: observation, evidence, impact, confidence, and recommendation.

## Suggested case-study format

For future investigations, add a Markdown document under `case-studies/` containing:

1. Symptom and scope
2. Reproduction environment
3. Investigation and competing hypotheses
4. Root cause
5. Fix and design trade-offs
6. Regression test
7. Security impact and remediation

## Open-source experience

Coursework and certificates support learning but do not replace public collaboration. Track upstream issues, pull requests, reviews, and accepted changes in `OPEN_SOURCE_CONTRIBUTIONS.md`. Never copy proprietary course labs into this repository.
