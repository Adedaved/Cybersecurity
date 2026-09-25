# BehaviorLab

BehaviorLab generates deterministic, harmless endpoint and network telemetry for validating defensive detections. It operates only in a caller-selected directory and communicates only over the loopback interface.

## Simulated behaviors

- Creates a clearly labelled autostart-style marker inside the lab directory.
- Reads generated decoy documents and records file-discovery events.
- Exchanges a benign heartbeat with an in-process loopback server.
- Writes newline-delimited JSON telemetry and then removes simulated artifacts.

It does **not** modify real persistence locations, access personal files, execute commands, evade controls, or contact the internet.

## Usage

```bash
python projects/behaviorlab/behaviorlab.py --workspace /tmp/behavior-lab
```

Inspect `/tmp/behavior-lab/events.jsonl` and use it to develop Sigma, EDR, or SIEM detections.

## Sample event

```json
{"action":"create","object":"simulated-autostart.json","simulation":"persistence-marker"}
```
