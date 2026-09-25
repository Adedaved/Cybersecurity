import importlib.util
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).parents[1]


def load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


sentinelscan = load("sentinelscan", "projects/sentinelscan/sentinelscan.py")
recongraph = load("recongraph", "projects/recongraph/recongraph.py")
safetrace = load("safetrace", "projects/safetrace/safetrace.py")
behaviorlab = load("behaviorlab", "projects/behaviorlab/behaviorlab.py")


class SentinelScanTests(unittest.TestCase):
    def test_port_parser_deduplicates_and_sorts(self):
        self.assertEqual(sentinelscan.parse_ports("443,80,80,81-82"), [80, 81, 82, 443])

    def test_port_parser_rejects_invalid_values(self):
        with self.assertRaises(ValueError):
            sentinelscan.parse_ports("0")


class ReconGraphTests(unittest.TestCase):
    def test_names_remain_under_root(self):
        self.assertEqual(recongraph.normalize_names("Example.COM", "www,api.example.com"), ["api.example.com", "example.com", "www.example.com"])

    def test_save_uses_structured_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "recon.db"
            run_id = recongraph.save(database, "example.com", [{"hostname": "example.com", "address": "127.0.0.1", "scheme": "http", "status": 200, "server": None, "location": None, "error": None}])
            with sqlite3.connect(database) as connection:
                count = connection.execute("SELECT COUNT(*) FROM observations WHERE run_id = ?", (run_id,)).fetchone()[0]
            self.assertEqual(count, 1)


class SafeTraceTests(unittest.TestCase):
    def test_static_analysis_hashes_and_classifies(self):
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory) / "sample.bin"
            sample.write_bytes(b"\x7fELF" + b"https://127.0.0.1/test" + b"\x00" * 20)
            result = safetrace.analyze(sample)
            self.assertEqual(result["type"], "ELF")
            self.assertEqual(len(result["hashes"]["sha256"]), 64)
            self.assertTrue(any(item["indicator"] == "network-primitive" for item in result["findings"]))


class BehaviorLabTests(unittest.TestCase):
    def test_simulation_cleans_marker_and_logs_events(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "lab"
            def simulated_loopback(log):
                log.write("loopback-exchange", "LAB-ACK:BENIGN-HEARTBEAT", "mock-command-and-control")

            with mock.patch.object(behaviorlab, "loopback_exchange", simulated_loopback):
                log_path = behaviorlab.run(workspace)
            events = [json.loads(line) for line in log_path.read_text().splitlines()]
            self.assertFalse((workspace / "simulated-autostart.json").exists())
            self.assertEqual(events[-1]["simulation"], "cleanup")
            self.assertTrue(any(item["simulation"] == "mock-command-and-control" for item in events))


if __name__ == "__main__":
    unittest.main()
