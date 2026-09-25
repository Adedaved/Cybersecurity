# Contributing

Defensive improvements, reproducible bug reports, tests, documentation, and false-positive reductions are welcome.

## Workflow

1. Open an issue describing the behavior, impact, and proposed scope.
2. Create a focused branch and keep the change small enough to review.
3. Add or update tests for behavioral changes.
4. Run `python -m compileall projects` and `python -m unittest discover -s tests -v`.
5. Submit a pull request explaining the root cause, solution, trade-offs, and security impact.

Do not submit live malware, weaponized payloads, credential material, personal data, destructive behavior, stealth features, or code intended for unauthorized access. Use synthetic fixtures and local lab targets.
