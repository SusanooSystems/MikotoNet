"""Four actual validator processes over loopback, not shared-memory replicas."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

from mikotonet.devnet import generate
from mikotonet.engine import Node


class ProcessClusterTests(unittest.TestCase):
    def test_four_processes_finalize_and_recover_equal_state(self):
        with tempfile.TemporaryDirectory() as directory:
            sockets = [socket.socket() for _ in range(4)]
            try:
                for s in sockets:
                    s.bind(("127.0.0.1", 0))
                ports = [s.getsockname()[1] for s in sockets]
            finally:
                for s in sockets:
                    s.close()
            configs = generate(Path(directory) / "cluster", ports)
            processes = []
            logs = []
            try:
                for config in configs:
                    log = tempfile.TemporaryFile()
                    logs.append(log)
                    processes.append(subprocess.Popen([sys.executable, "-m", "mikotonet.network", str(config)], stdout=log, stderr=log))
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    if all((config.parent / f"node{i}.jsonl").exists() for i, config in enumerate(configs)):
                        break
                    if any(p.poll() is not None for p in processes):
                        self.fail("validator exited before finalizing")
                    time.sleep(0.1)
                else:
                    self.fail("cluster did not finalize before deadline")
            finally:
                for p in processes:
                    p.terminate()
                for p in processes:
                    try:
                        p.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        p.kill()
                        p.wait()
                for log in logs:
                    log.close()
            roots = []
            for path in configs:
                config = json.loads(path.read_text())
                node = Node(config["chain"], list(config["peers"]), config["balances"], config["journal"])
                try:
                    self.assertEqual(node.height, 1)
                    self.assertEqual(len(node.exchange.fills), 1)
                    self.assertEqual(node.exchange.fills[0]["price"], 25)
                    self.assertEqual(node.exchange.fills[0]["quantity"], 4)
                    roots.append(node.exchange.root)
                finally:
                    node.close()
            self.assertEqual(len(set(roots)), 1)
