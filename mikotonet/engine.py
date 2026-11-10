"""Signed Polytree checkpoints and deterministic integer spot exchange."""
from __future__ import annotations

import hashlib
import copy
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from .storage import WriterLock, append, records

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(domain, value):
    return hashlib.sha256(domain.encode() + b"\0" + canonical(value)).hexdigest()


def public(key):
    return key.public_key().public_bytes_raw().hex()


def verify(key, signature, message):
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(bytes.fromhex(signature), message)
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise ValueError("invalid signature") from exc


@dataclass(frozen=True)
class Transaction:
    chain: str
    account: str
    nonce: int
    kind: str
    side: str = ""
    price: int = 0
    quantity: int = 0
    order: str = ""
    signature: str = ""

    def body(self):
        return {k: v for k, v in asdict(self).items() if k != "signature"}

    def validate(self):
        for name in ("chain", "account", "kind", "side", "order", "signature"):
            if type(getattr(self, name)) is not str or len(getattr(self, name)) > 256:
                raise ValueError("invalid transaction field")
        for name in ("nonce", "price", "quantity"):
            if type(getattr(self, name)) is not int or not 0 <= getattr(self, name) < 2**63:
                raise ValueError("invalid transaction integer")
        verify(self.account, self.signature, bytes.fromhex(self.id))

    @property
    def id(self):
        return digest("mikoto/tx/v1", self.body())

    @classmethod
    def sign(cls, key, chain, nonce, kind, **fields):
        tx = cls(chain, public(key), nonce, kind, **fields)
        return cls(**tx.body(), signature=key.sign(bytes.fromhex(tx.id)).hex())


@dataclass(frozen=True)
class Vertex:
    chain: str
    author: str
    sequence: int
    parents: tuple[str, ...]
    transactions: tuple[Transaction, ...]
    signature: str = ""

    def body(self):
        return {"chain": self.chain, "author": self.author, "sequence": self.sequence,
                "parents": self.parents, "transactions": [asdict(t) for t in self.transactions]}

    @property
    def id(self):
        return digest("mikoto/vertex/v1", self.body())

    @classmethod
    def sign(cls, key, chain, sequence, parents=(), transactions=()):
        v = cls(chain, public(key), sequence, tuple(sorted(parents)), tuple(transactions))
        return cls(**{**v.__dict__, "signature": key.sign(bytes.fromhex(v.id)).hex()})


class Polytree:
    """A multitree adaptation: each vertex has at most one path to any ancestor.

    Parent ancestor closures must be disjoint. This is a directed multitree,
    not the stricter undirected-tree definition sometimes called a polytree.
    """
    def __init__(self, chain, validators):
        self.chain, self.validators = chain, frozenset(validators)
        self.vertices, self.ancestors, self.slots = {}, {}, {}

    def insert(self, v):
        if v.id in self.vertices:
            return v.id
        if v.chain != self.chain or v.author not in self.validators:
            raise ValueError("wrong chain or unknown validator")
        verify(v.author, v.signature, bytes.fromhex(v.id))
        if type(v.sequence) is not int or not 0 <= v.sequence < 2**63:
            raise ValueError("invalid sequence")
        if (v.author, v.sequence) in self.slots:
            raise ValueError("validator equivocation")
        if len(v.parents) > 8 or tuple(sorted(set(v.parents))) != v.parents:
            raise ValueError("parents must be sorted, unique and bounded")
        if len(v.transactions) > 1024 or len(self.vertices) >= 100_000:
            raise ValueError("graph capacity exceeded")
        closure = set()
        for parent in v.parents:
            if parent not in self.vertices:
                raise ValueError("missing parent")
            branch = self.ancestors[parent] | {parent}
            if closure & branch:
                raise ValueError("multiple ancestry paths")
            closure |= branch
        previous = self.slots.get((v.author, v.sequence - 1))
        if v.sequence and (previous is None or previous not in closure):
            raise ValueError("missing author's previous vertex ancestry")
        for tx in v.transactions:
            if tx.chain != self.chain:
                raise ValueError("wrong transaction chain")
            tx.validate()
        self.vertices[v.id], self.ancestors[v.id] = v, closure
        self.slots[v.author, v.sequence] = v.id
        return v.id

    def ordered(self, tips):
        if not tips or tuple(sorted(set(tips))) != tuple(tips):
            raise ValueError("tips must be nonempty, sorted and unique")
        selected = set()
        for tip in tips:
            if tip not in self.vertices:
                raise ValueError("unknown tip")
            selected |= self.ancestors[tip] | {tip}
        # Ancestor count strictly increases along edges; ID breaks concurrent ties.
        return sorted(selected, key=lambda i: (len(self.ancestors[i]), i))


class Exchange:
    """One BASE/QUOTE spot market. Positive integer atomic units, no leverage."""
    def __init__(self, balances):
        self.balances = {a: dict(b) for a, b in balances.items()}
        for account, amounts in self.balances.items():
            if len(bytes.fromhex(account)) != 32 or set(amounts) != {"BASE", "QUOTE"}:
                raise ValueError("invalid genesis account")
            if any(type(x) is not int or not 0 <= x < 2**63 for x in amounts.values()):
                raise ValueError("invalid genesis balance")
        self.nonces, self.orders, self.fills, self.receipts = {}, {}, [], []
        self.arrival = 0

    @property
    def root(self):
        return digest("mikoto/state/v1", self.__dict__)

    def apply(self, tx):
        # All rejection checks precede mutations. Rejected transactions consume no nonce.
        try:
            self._apply(tx)
            status = "accepted"
        except ValueError as exc:
            status = str(exc)
        self.receipts.append({"transaction": tx.id, "status": status})

    def _apply(self, tx):
        tx.validate()
        if tx.account not in self.balances:
            raise ValueError("unknown account")
        if type(tx.nonce) is not int or tx.nonce != self.nonces.get(tx.account, 0):
            raise ValueError("invalid nonce")
        if tx.kind == "cancel":
            order = self.orders.get(tx.order)
            if not order or order["account"] != tx.account:
                raise ValueError("unknown owned order")
            self._refund(order)
            del self.orders[tx.order]
        elif tx.kind == "order":
            if tx.side not in ("buy", "sell") or any(type(x) is not int or not 0 < x < 2**63 for x in (tx.price, tx.quantity)):
                raise ValueError("invalid order")
            if tx.price * tx.quantity >= 2**63 or len(self.orders) >= 100_000:
                raise ValueError("order limit exceeded")
            asset, reserve = ("QUOTE", tx.price * tx.quantity) if tx.side == "buy" else ("BASE", tx.quantity)
            if self.balances[tx.account][asset] < reserve:
                raise ValueError("insufficient funds")
            opposite = [o for o in self.orders.values() if o["side"] != tx.side and
                        (o["price"] <= tx.price if tx.side == "buy" else o["price"] >= tx.price)]
            opposite.sort(key=lambda o: (o["price"] if tx.side == "buy" else -o["price"], o["arrival"]))
            # Reject crossing one's own liquidity atomically.
            remaining = tx.quantity
            for maker in opposite:
                if remaining == 0:
                    break
                if maker["account"] == tx.account:
                    raise ValueError("self trade")
                remaining -= min(remaining, maker["quantity"])
            self.balances[tx.account][asset] -= reserve
            remaining = tx.quantity
            for maker in opposite:
                if not remaining:
                    break
                qty = min(remaining, maker["quantity"])
                price = maker["price"]
                buyer = tx.account if tx.side == "buy" else maker["account"]
                seller = maker["account"] if tx.side == "buy" else tx.account
                self.balances[buyer]["BASE"] += qty
                self.balances[seller]["QUOTE"] += price * qty
                if tx.side == "buy":
                    self.balances[buyer]["QUOTE"] += (tx.price - price) * qty
                maker["quantity"] -= qty
                remaining -= qty
                self.fills.append({"maker": maker["id"], "taker": tx.id, "price": price, "quantity": qty})
                if not maker["quantity"]:
                    del self.orders[maker["id"]]
            if remaining:
                self.orders[tx.id] = {"id": tx.id, "account": tx.account, "side": tx.side,
                                      "price": tx.price, "quantity": remaining, "arrival": self.arrival}
            self.arrival += 1
        else:
            raise ValueError("unknown transaction kind")
        self.nonces[tx.account] = tx.nonce + 1

    def _refund(self, order):
        asset = "QUOTE" if order["side"] == "buy" else "BASE"
        self.balances[order["account"]][asset] += order["quantity"] * (order["price"] if asset == "QUOTE" else 1)


class Node:
    """Single-writer replica with optional durable checkpoint and signing journals."""
    def __init__(self, chain, validators, balances, journal=None):
        if len(set(validators)) != len(validators) or len(validators) < 4:
            raise ValueError("need at least four distinct validators")
        self.graph = Polytree(chain, validators)
        self.exchange = Exchange(balances)
        self.genesis = digest("mikoto/genesis/v1", {"chain": chain, "validators": sorted(validators), "balances": balances})
        self.head, self.height, self.finalized = self.genesis, 0, set()
        self.quorum = (2 * len(validators)) // 3 + 1
        self.journal = Path(journal) if journal else None
        self.failed = False
        self.voted = {}
        self.vote_checkpoints = {}
        self._lock = WriterLock(str(self.journal) + ".lock") if self.journal else None
        try:
            self._recover()
        except BaseException:
            self.close()
            raise

    def close(self):
        if self._lock:
            self._lock.close()
        self.failed = True

    def _recover(self):
        if self.journal:
            for record in records(self.journal):
                for raw in record["vertices"]:
                    raw["parents"] = tuple(raw["parents"])
                    raw["transactions"] = tuple(Transaction(**t) for t in raw["transactions"])
                    self.graph.insert(Vertex(**raw))
                self.finalize(record["checkpoint"], record["votes"], persist=False)
            for record in records(str(self.journal) + ".votes"):
                if record["genesis"] != self.genesis or record["author"] not in self.graph.validators:
                    raise ValueError("foreign vote journal")
                verify(record["author"], record["signature"], bytes.fromhex(record["message"]))
                # The signature binds the entire checkpoint, including its height.
                cp = record["checkpoint"]
                if cp["genesis"] != self.genesis or digest("mikoto/checkpoint/v1", cp) != record["message"]:
                    raise ValueError("corrupt vote journal")
                slot = (record["author"], cp["height"])
                if slot in self.voted and self.voted[slot] != record["message"]:
                    raise ValueError("conflicting vote journal")
                self.voted[slot] = record["message"]
                self.vote_checkpoints[slot] = cp

    def propose(self, tips):
        ordered = self.graph.ordered(tips)
        preview = copy.deepcopy(self.exchange)
        for i in ordered:
            if i not in self.finalized:
                for tx in self.graph.vertices[i].transactions:
                    preview.apply(tx)
        return {"genesis": self.genesis, "height": self.height + 1, "previous": self.head,
                "tips": list(tips), "order": ordered, "pre_state": self.exchange.root,
                "post_state": preview.root}

    def vote(self, key, checkpoint):
        if self.failed:
            raise ValueError("storage failure or closed node; restart required")
        if public(key) not in self.graph.validators or checkpoint != self.propose(tuple(checkpoint["tips"])):
            raise ValueError("invalid proposal")
        message = digest("mikoto/checkpoint/v1", checkpoint)
        slot = checkpoint["height"]
        if (public(key), slot) in self.voted and self.voted[public(key), slot] != message:
            raise ValueError("conflicting local vote")
        signature = key.sign(bytes.fromhex(message)).hex()
        if self.journal and (public(key), slot) not in self.voted:
            try:
                append(str(self.journal) + ".votes", {"genesis": self.genesis, "author": public(key),
                       "message": message, "checkpoint": checkpoint, "signature": signature})
            except OSError:
                self.failed = True
                raise
        self.voted[public(key), slot] = message
        self.vote_checkpoints[public(key), slot] = copy.deepcopy(checkpoint)
        return signature

    def finalize(self, checkpoint, votes, persist=True):
        if self.failed:
            raise ValueError("journal failure; restart required")
        if checkpoint != self.propose(tuple(checkpoint["tips"])):
            raise ValueError("stale or invalid checkpoint")
        message = digest("mikoto/checkpoint/v1", checkpoint)
        if len(votes) < self.quorum:
            raise ValueError("insufficient quorum")
        for author, signature in votes.items():
            if author not in self.graph.validators:
                raise ValueError("unknown voter")
            verify(author, signature, bytes.fromhex(message))
        fresh = [i for i in checkpoint["order"] if i not in self.finalized]
        if not fresh:
            raise ValueError("empty checkpoint")
        if persist and self.journal:
            record = {"checkpoint": checkpoint, "votes": votes,
                      "vertices": [asdict(self.graph.vertices[i]) for i in fresh]}
            try:
                append(self.journal, record)
            except OSError:
                self.failed = True
                raise
        for i in fresh:
            for tx in self.graph.vertices[i].transactions:
                self.exchange.apply(tx)
        self.finalized.update(fresh)
        self.head, self.height = message, checkpoint["height"]
        return self.exchange.root
