import asyncio
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mikotonet.engine import Node, Transaction, Vertex, canonical, digest, public
from mikotonet.network import MAX_FRAME, Peer, read_frame, write_frame


class DurableVoteTests(unittest.TestCase):
    def test_vote_survives_process_exit_and_conflict_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            keys = [Ed25519PrivateKey.generate() for _ in range(4)]
            validators = [public(k) for k in keys]
            a = Vertex.sign(keys[0], "test", 0)
            b = Vertex.sign(keys[1], "test", 0)
            path = str(Path(directory) / "ledger")
            # Abrupt process exit without Node.close, immediately after vote returns.
            code = """
import json, os, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mikotonet.engine import Node
from mikotonet.network import decode_vertex
c = json.loads(sys.stdin.read())
n = Node('test', c['validators'], {}, c['path'])
n.graph.insert(decode_vertex(c['vertex']))
n.vote(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(c['key'])), n.propose((c['id'],)))
os._exit(0)
"""
            config = {"validators": validators, "path": path, "vertex": asdict(a), "id": a.id, "key": keys[0].private_bytes_raw().hex()}
            result = subprocess.run([sys.executable, "-c", code], input=json.dumps(config), text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            n = Node("test", validators, {}, path)
            n.graph.insert(a)
            n.graph.insert(b)
            n.vote(keys[0], n.propose((a.id,)))
            with self.assertRaisesRegex(ValueError, "conflicting"):
                n.vote(keys[0], n.propose((b.id,)))
            with self.assertRaisesRegex(ValueError, "writer"):
                Node("test", validators, {}, path)
            n.close()
            vote_path = Path(path + ".votes")
            vote_path.write_bytes(vote_path.read_bytes()[:-1])
            with self.assertRaisesRegex(ValueError, "truncated"):
                Node("test", validators, {}, path)

    def test_fsync_failure_returns_no_vote_and_disables_signing(self):
        with tempfile.TemporaryDirectory() as directory:
            keys = [Ed25519PrivateKey.generate() for _ in range(4)]
            n = Node("test", [public(k) for k in keys], {}, Path(directory) / "ledger")
            a = n.graph.insert(Vertex.sign(keys[0], "test", 0))
            cp = n.propose((a,))
            with patch("mikotonet.storage.os.fsync", side_effect=OSError("disk failure")):
                with self.assertRaises(OSError):
                    n.vote(keys[0], cp)
            with self.assertRaisesRegex(ValueError, "storage failure"):
                n.vote(keys[0], cp)
            n.close()


class NetworkTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.keys = sorted([Ed25519PrivateKey.generate() for _ in range(4)], key=public)
        self.validators = [public(k) for k in self.keys]
        self.addresses = {a: ("127.0.0.1", 0) for a in self.validators}
        self.account = Ed25519PrivateKey.generate()
        self.balances = {public(self.account): {"BASE": 100, "QUOTE": 1000}}
        self.peers = []
        for i, key in enumerate(self.keys):
            node = Node("test", self.validators, self.balances, Path(self.directory.name) / f"node{i}")
            peer = Peer(node, key, self.addresses)
            await peer.start(background=False)
            self.peers.append(peer)

    async def asyncTearDown(self):
        for peer in self.peers:
            await peer.stop()
        self.directory.cleanup()

    def add_vertex(self, index=0):
        tx = Transaction.sign(self.account, "test", 0, "order", side="sell", price=10, quantity=3)
        v = Vertex.sign(self.keys[index], "test", 0, transactions=(tx,))
        self.peers[index].ingest(asdict(v))
        return v

    async def test_quorum_replication_offline_peer_catches_up_after_restart(self):
        self.add_vertex()
        await self.peers[3].stop()
        await self.peers[0].tick()
        self.assertEqual([p.node.height for p in self.peers[:3]], [1, 1, 1])
        path = Path(self.directory.name) / "node3"
        restored = Peer(Node("test", self.validators, self.balances, path), self.keys[3], self.addresses)
        self.peers[3] = restored
        await restored.start(background=False)
        await restored.tick()
        self.assertEqual(restored.node.height, 1)
        self.assertEqual(len({p.node.exchange.root for p in self.peers}), 1)
        # Height two rotates the leader and extends the same Polytree branch.
        previous = next(iter(self.peers[0].node.graph.vertices))
        v = Vertex.sign(self.keys[1], "test", 0, parents=(previous,))
        self.peers[1].ingest(asdict(v))
        await self.peers[1].tick()
        self.assertEqual([p.node.height for p in self.peers], [2] * 4)
        self.assertEqual(len({p.node.exchange.root for p in self.peers}), 1)

    async def test_no_quorum_does_not_finalize_and_same_proposal_retries(self):
        self.add_vertex()
        await self.peers[2].stop()
        await self.peers[3].stop()
        await self.peers[0].tick()
        self.assertEqual(self.peers[0].node.height, 0)
        # Restart leader with its durable vote and vertices intact.
        await self.peers[0].stop()
        self.peers[0] = Peer(Node("test", self.validators, self.balances, Path(self.directory.name) / "node0"), self.keys[0], self.addresses)
        await self.peers[0].start(background=False)
        self.peers[2] = Peer(Node("test", self.validators, self.balances, Path(self.directory.name) / "node2"), self.keys[2], self.addresses)
        await self.peers[2].start(background=False)
        await self.peers[0].tick()
        self.assertEqual(self.peers[0].node.height, 1)

    async def test_bad_identity_and_replayed_challenge_are_rejected(self):
        peer = self.peers[0]
        reader, writer = await asyncio.open_connection(*self.addresses[self.validators[0]])
        challenge = (await read_frame(reader))["challenge"]
        request = {"challenge": challenge, "recipient": self.validators[0], "author": self.validators[1],
                   "genesis": peer.node.genesis, "payload": {"op": "status"}}
        wire = {**request, "signature": self.keys[1].sign(bytes.fromhex(digest("mikoto/rpc/request/v1", request))).hex()}
        await write_frame(writer, wire)
        self.assertTrue((await read_frame(reader))["ok"])
        writer.close()
        await writer.wait_closed()
        reader, writer = await asyncio.open_connection(*self.addresses[self.validators[0]])
        await read_frame(reader)
        await write_frame(writer, wire)
        self.assertEqual(await reader.read(), b"")
        writer.close()
        await writer.wait_closed()
        outsider = Ed25519PrivateKey.generate()
        client = self.peers[1]
        original = client.key, client.author
        client.key, client.author = outsider, public(outsider)
        try:
            with self.assertRaises(asyncio.IncompleteReadError):
                await client.rpc(peer.author, {"op": "status"})
        finally:
            client.key, client.author = original

    async def test_frame_limit_and_wrong_leader(self):
        reader, writer = await asyncio.open_connection(*self.addresses[self.validators[0]])
        await read_frame(reader)
        writer.write(struct.pack("!I", MAX_FRAME + 1))
        await writer.drain()
        self.assertEqual(await reader.read(), b"")
        writer.close()
        await writer.wait_closed()
        with self.assertRaisesRegex(ValueError, "leader"):
            await self.peers[1].rpc(self.validators[2], {"op": "vote", "checkpoint": {}, "vertices": []})
