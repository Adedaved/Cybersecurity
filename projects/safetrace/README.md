# SafeTrace

SafeTrace performs static triage without executing the supplied file. It reports cryptographic hashes, type hints, entropy, readable strings, and explainable indicators.

## Usage

```bash
python projects/safetrace/safetrace.py path/to/file
python projects/safetrace/safetrace.py path/to/file --json --max-bytes 10000000
```

## Sample output

```text
SafeTrace sample=training.bin type=ELF size=14472 entropy=5.11
SHA256 8b0a...
[medium] high-entropy-content: entropy 7.42 may indicate compression or packing
```

## Method and limitations

- Inputs are opened only for reading and never loaded as code.
- Entropy is a lead, not proof of packing or maliciousness.
- String indicators provide context, not a verdict.
- The size cap limits resource consumption.
- This is a triage aid, not a sandbox or antivirus product.
