"""Bounded, mutually signed TCP RPC and fixed-leader checkpoint replication.

Messages have integrity/authentication, not confidentiality. Use a private
network or an encrypted tunnel. No view changes: leader loss stalls progress.
"""
import argparse
import asyncio
import json
import logging
import secrets
import struct
from dataclasses import asdict
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .engine import Node, Transaction, Vertex, canonical, digest, public, verify
from .storage import append, records

MAX_FRAME = 4 * 1024 * 1024
TIMEOUT = 5
LOG = logging.getLogger(__name__)


async def read_frame(reader):
    size = struct.unpack("!I", await reader.readexactly(4))[0]
    if not 0 < size <= MAX_FRAME:
        raise ValueError("frame limit exceeded")
    return json.loads(await reader.readexactly(size))


async def write_frame(writer, value):
    data = canonical(value)
    if len(data) > MAX_FRAME:
        raise ValueError("frame limit exceeded")
    writer.write(struct.pack("!I", len(data)) + data)
    await writer.drain()


def decode_vertex(raw):
    return Vertex(**{**raw, "parents": tuple(raw["parents"]),
                     "transactions": tuple(Transaction(**t) for t in raw["transactions"])})


class Peer:
    def __init__(self, node, key, addresses):
        if not node.journal or public(key) not in node.graph.validators:
            raise ValueError("network validator requires durable storage and an allowlisted key")
        if set(addresses) != set(node.graph.validators):
            raise ValueError("one address required per validator")
        self.node, self.key, self.addresses = node, key, addresses
        self.author = public(key)
        self.server, self.task, self.connections = None, None, 0
        self.vertices_path = str(node.journal) + ".vertices"
        for record in records(self.vertices_path):
            if record["genesis"] != node.genesis:
                raise ValueError("foreign vertex journal")
            node.graph.insert(decode_vertex(record["vertex"]))
        self.history = list(records(node.journal))

    @property
    def leader(self):
        return sorted(self.node.graph.validators)[self.node.height % len(self.addresses)]

    def ingest(self, raw):
        v = decode_vertex(raw)
        if v.id not in self.node.graph.vertices:
            self.node.graph.insert(v)
            try:
                append(self.vertices_path, {"genesis": self.node.genesis, "vertex": raw})
            except OSError:
                self.node.failed = True
                raise
        return v.id

    def bundle(self, checkpoint):
        return [asdict(self.node.graph.vertices[i]) for i in checkpoint["order"] if i not in self.node.finalized]

    def accept(self, record):
        height = record["checkpoint"]["height"]
        if type(height) is not int or height < 1:
            raise ValueError("invalid checkpoint height")
        if record["checkpoint"]["height"] <= self.node.height:
            known = self.history[record["checkpoint"]["height"] - 1]
            if canonical(known["checkpoint"]) != canonical(record["checkpoint"]):
                raise ValueError("conflicting finalized checkpoint")
            return self.node.exchange.root
        for raw in record["vertices"]:
            self.ingest(raw)
        root = self.node.finalize(record["checkpoint"], record["votes"])
        self.history.append(record)
        return root

    def dispatch(self, author, payload):
        if self.node.failed:
            raise ValueError("node storage unavailable")
        op = payload["op"]
        if op == "status":
            return {"height": self.node.height, "head": self.node.head, "root": self.node.exchange.root}
        if op == "sync":
            height = payload["after"]
            if type(height) is not int or not 0 <= height <= self.node.height:
                raise ValueError("invalid sync cursor")
            return self.history[height] if height < self.node.height else None
        if op == "vertices":
            if len(payload["vertices"]) > 1024:
                raise ValueError("vertex bundle limit")
            return [self.ingest(raw) for raw in payload["vertices"]]
        if op == "vote":
            if author != self.leader:
                raise ValueError("proposal sender is not the current leader")
            if len(payload["vertices"]) > 1024:
                raise ValueError("vertex bundle limit")
            for raw in payload["vertices"]:
                self.ingest(raw)
            return self.node.vote(self.key, payload["checkpoint"])
        if op == "finalize":
            return self.accept(payload["record"])
        raise ValueError("unknown RPC operation")

    async def _session(self, reader, writer):
        # Server nonce is fresh per connection and consumed by exactly one request.
        challenge = secrets.token_hex(32)
        await write_frame(writer, {"challenge": challenge})
        request = await read_frame(reader)
        signature = request.pop("signature")
        if (request["challenge"] != challenge or request["recipient"] != self.author or
                request["genesis"] != self.node.genesis or request["author"] not in self.node.graph.validators):
            raise ValueError("invalid peer identity/domain/challenge")
        verify(request["author"], signature, bytes.fromhex(digest("mikoto/rpc/request/v1", request)))
        try:
            result = {"ok": True, "result": self.dispatch(request["author"], request["payload"])}
        except (ValueError, KeyError, TypeError, OSError) as exc:
            result = {"ok": False, "error": str(exc)}
        response = {"request": digest("mikoto/rpc/request/v1", request), **result}
        response["signature"] = self.key.sign(bytes.fromhex(digest("mikoto/rpc/response/v1", response))).hex()
        await write_frame(writer, response)

    async def handle(self, reader, writer):
        if self.connections >= 32:
            writer.close()
            return
        self.connections += 1
        try:
            async with asyncio.timeout(TIMEOUT):
                await self._session(reader, writer)
        except (ValueError, KeyError, TypeError, OSError, asyncio.IncompleteReadError, TimeoutError):
            pass
        finally:
            self.connections -= 1
            writer.close()
            await writer.wait_closed()

    async def rpc(self, recipient, payload):
        async with asyncio.timeout(TIMEOUT):
            reader, writer = await asyncio.open_connection(*self.addresses[recipient])
            try:
                challenge = (await read_frame(reader))["challenge"]
                request = {"challenge": challenge, "recipient": recipient, "author": self.author,
                           "genesis": self.node.genesis, "payload": payload}
                request_id = digest("mikoto/rpc/request/v1", request)
                await write_frame(writer, {**request, "signature": self.key.sign(bytes.fromhex(request_id)).hex()})
                response = await read_frame(reader)
                signature = response.pop("signature")
                verify(recipient, signature, bytes.fromhex(digest("mikoto/rpc/response/v1", response)))
                if response["request"] != request_id:
                    raise ValueError("response does not match request")
                if not response["ok"]:
                    raise ValueError(response["error"])
                return response["result"]
            finally:
                writer.close()
                await writer.wait_closed()

    async def start(self, background=True):
        self.server = await asyncio.start_server(self.handle, *self.addresses[self.author])
        # Port zero supports isolated integration tests.
        self.addresses[self.author] = self.server.sockets[0].getsockname()[:2]
        if background:
            self.task = asyncio.create_task(self.run())

    async def stop(self):
        if self.task:
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        self.node.close()

    async def tick(self):
        others = [a for a in sorted(self.addresses) if a != self.author]
        # Pull one certified checkpoint per peer each tick; bounded catch-up.
        for author in others:
            try:
                record = await self.rpc(author, {"op": "sync", "after": self.node.height})
                if record:
                    self.accept(record)
            except (ValueError, OSError, TimeoutError, asyncio.IncompleteReadError):
                continue
        # Disseminate all unfinalized vertices in dependency order. Small bounded batches.
        pending = sorted((i for i in self.node.graph.vertices if i not in self.node.finalized),
                         key=lambda i: (len(self.node.graph.ancestors[i]), i))
        if not pending:
            return
        if len(pending) > 1024:
            raise ValueError("pending graph exceeds checkpoint bound")
        vertices = [asdict(self.node.graph.vertices[i]) for i in pending]
        await asyncio.gather(*(self.rpc(a, {"op": "vertices", "vertices": vertices}) for a in others), return_exceptions=True)
        if self.author != self.leader:
            return
        # A finalized prefix may change while RPCs run; recompute from current state.
        fresh = set(self.node.graph.vertices) - self.node.finalized
        tips = fresh - {p for i in fresh for p in self.node.graph.vertices[i].parents}
        if not tips:
            return
        cp = self.node.vote_checkpoints.get((self.author, self.node.height + 1))
        if cp is None:
            cp = self.node.propose(tuple(sorted(tips)))
        bundle = self.bundle(cp)
        # Leave space for envelopes, signatures and the final quorum certificate.
        if len(canonical({"checkpoint": cp, "vertices": bundle})) > MAX_FRAME // 2:
            raise ValueError("checkpoint exceeds network payload budget")
        votes = {self.author: self.node.vote(self.key, cp)}
        replies = await asyncio.gather(*(self.rpc(a, {"op": "vote", "checkpoint": cp, "vertices": bundle}) for a in others), return_exceptions=True)
        for author, reply in zip(others, replies):
            if isinstance(reply, str):
                votes[author] = reply
        if len(votes) < self.node.quorum:
            return
        record = {"checkpoint": cp, "vertices": bundle, "votes": votes}
        self.accept(record)
        await asyncio.gather(*(self.rpc(a, {"op": "finalize", "record": record}) for a in others), return_exceptions=True)

    async def run(self):
        while True:
            try:
                await self.tick()
            except (ValueError, OSError, TimeoutError) as exc:
                LOG.warning("replication paused: %s", exc)
            await asyncio.sleep(1)


async def serve(config_path):
    config = json.loads(Path(config_path).read_text())
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(Path(config["key_file"]).read_text().strip()))
    addresses = {a: tuple(address) for a, address in config["peers"].items()}
    node = Node(config["chain"], list(addresses), config["balances"], config["journal"])
    peer = Peer(node, key, addresses)
    try:
        # Optional startup vertices are fully signed and persisted, never auto-signed orders.
        for filename in config.get("vertex_files", []):
            peer.ingest(json.loads(Path(filename).read_text()))
        await peer.start()
        LOG.info("validator listening at %s", addresses[public(key)])
        await asyncio.Event().wait()
    finally:
        await peer.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", help="JSON config: chain, peers, balances, key_file, journal, optional vertex_files")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    try:
        asyncio.run(serve(args.config))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
