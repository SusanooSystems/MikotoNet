import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mikotonet.engine import Exchange, Node, Polytree, Transaction, Vertex, public


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.keys = [Ed25519PrivateKey.generate() for _ in range(4)]
        self.accounts = [Ed25519PrivateKey.generate() for _ in range(3)]
        self.validators = [public(k) for k in self.keys]
        self.balances = {public(k): {"BASE": 100, "QUOTE": 10000} for k in self.accounts}

    def tx(self, who=0, nonce=0, **fields):
        return Transaction.sign(self.accounts[who], "test", nonce, fields.pop("kind", "order"), **fields)

    def vertex(self, who=0, seq=0, parents=(), txs=()):
        return Vertex.sign(self.keys[who], "test", seq, parents, txs)

    def finalize(self, node, tips):
        cp = node.propose(tuple(sorted(tips)))
        votes = {public(k): node.vote(k, cp) for k in self.keys[:3]}
        return node.finalize(cp, votes)

    def test_polytree_merge_and_reject_diamond(self):
        g = Polytree("test", self.validators)
        a = g.insert(self.vertex())
        b = g.insert(self.vertex(1, parents=(a,)))
        c = g.insert(self.vertex(2, parents=(a,)))
        with self.assertRaisesRegex(ValueError, "multiple ancestry"):
            g.insert(self.vertex(3, parents=tuple(sorted((b, c)))))
        d = g.insert(self.vertex(3))
        g.insert(self.vertex(1, 1, tuple(sorted((b, d)))))

    def test_missing_parent_equivocation_and_authentication(self):
        g = Polytree("test", self.validators)
        with self.assertRaisesRegex(ValueError, "missing parent"):
            g.insert(self.vertex(parents=("00" * 32,)))
        v = self.vertex()
        with self.assertRaisesRegex(ValueError, "signature"):
            g.insert(replace(v, signature="00" * 64))
        g.insert(v)
        with self.assertRaisesRegex(ValueError, "equivocation"):
            g.insert(self.vertex(txs=(self.tx(side="buy", price=1, quantity=1),)))
        with self.assertRaisesRegex(ValueError, "previous"):
            g.insert(self.vertex(seq=1))

    def test_order_independent_of_arrival(self):
        a, b = self.vertex(), self.vertex(1)
        x, y = Polytree("test", self.validators), Polytree("test", self.validators)
        for g, vertices in ((x, (a, b)), (y, (b, a))):
            for v in vertices:
                g.insert(v)
        tips = tuple(sorted((a.id, b.id)))
        self.assertEqual(x.ordered(tips), y.ordered(tips))

    def test_spot_matching_reserves_price_improvement_and_cancel(self):
        e = Exchange(self.balances)
        ask = self.tx(side="sell", price=25, quantity=10)
        e.apply(ask)
        e.apply(self.tx(1, side="buy", price=30, quantity=4))
        self.assertEqual(e.fills[0]["price"], 25)
        self.assertEqual(e.balances[public(self.accounts[1])], {"BASE": 104, "QUOTE": 9900})
        e.apply(self.tx(nonce=1, kind="cancel", order=ask.id))
        self.assertEqual(e.balances[public(self.accounts[0])], {"BASE": 96, "QUOTE": 10100})
        self.assertFalse(e.orders)

    def test_price_time_and_sell_taker(self):
        e = Exchange(self.balances)
        a = self.tx(side="buy", price=20, quantity=2)
        b = self.tx(1, side="buy", price=20, quantity=2)
        e.apply(a)
        e.apply(b)
        e.apply(self.tx(2, side="sell", price=15, quantity=3))
        self.assertEqual([f["maker"] for f in e.fills], [a.id, b.id])
        self.assertEqual(e.orders[b.id]["quantity"], 1)
        totals = {asset: sum(bal[asset] for bal in e.balances.values()) for asset in ("BASE", "QUOTE")}
        for order in e.orders.values():
            totals["QUOTE" if order["side"] == "buy" else "BASE"] += order["quantity"] * (order["price"] if order["side"] == "buy" else 1)
        self.assertEqual(totals, {"BASE": 300, "QUOTE": 30000})

    def test_rejections_do_not_change_balances_or_nonce(self):
        e = Exchange(self.balances)
        for tx in (self.tx(side="buy", price=10001, quantity=1), self.tx(side="sell", price=-1, quantity=1), self.tx(nonce=9, side="buy", price=1, quantity=1)):
            e.apply(tx)
        self.assertEqual(e.balances, self.balances)
        self.assertEqual(e.nonces, {})
        ask = self.tx(side="sell", price=1, quantity=1)
        e.apply(ask)
        e.apply(self.tx(nonce=1, side="buy", price=1, quantity=1))
        self.assertEqual(e.receipts[-1]["status"], "self trade")
        self.assertEqual(e.orders[ask.id]["quantity"], 1)
        e.apply(self.tx(1, kind="cancel", order=ask.id))
        self.assertEqual(e.receipts[-1]["status"], "unknown owned order")

    def test_quorum_chain_and_no_double_execution(self):
        n = Node("test", self.validators, self.balances)
        a = n.graph.insert(self.vertex(txs=(self.tx(side="buy", price=1, quantity=1),)))
        cp = n.propose((a,))
        votes = {public(k): n.vote(k, cp) for k in self.keys[:2]}
        with self.assertRaisesRegex(ValueError, "quorum"):
            n.finalize(cp, votes)
        self.finalize(n, (a,))
        with self.assertRaisesRegex(ValueError, "stale"):
            n.finalize(cp, votes)
        b = n.graph.insert(self.vertex(1, parents=(a,)))
        self.finalize(n, (b,))
        self.assertEqual(len(n.exchange.receipts), 1)
        with self.assertRaisesRegex(ValueError, "chain"):
            n.graph.insert(Vertex.sign(self.keys[2], "other", 0))

    def test_replay_and_corruption_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.jsonl"
            n = Node("test", self.validators, self.balances, path)
            a = n.graph.insert(self.vertex(txs=(self.tx(side="sell", price=5, quantity=2),)))
            self.finalize(n, (a,))
            b = n.graph.insert(self.vertex(1, parents=(a,), txs=(self.tx(1, side="buy", price=6, quantity=1),)))
            self.finalize(n, (b,))
            n.close()
            restored = Node("test", self.validators, self.balances, path)
            self.assertEqual(restored.exchange.root, n.exchange.root)
            self.assertEqual(restored.head, n.head)
            restored.close()
            with self.assertRaises(ValueError):
                Node("another-chain", self.validators, self.balances, path)
            path.write_bytes(path.read_bytes()[:-1])
            with self.assertRaisesRegex(ValueError, "truncated"):
                Node("test", self.validators, self.balances, path)

    def test_conflicting_vote_refused(self):
        n = Node("test", self.validators, self.balances)
        a, b = n.graph.insert(self.vertex()), n.graph.insert(self.vertex(1))
        n.vote(self.keys[0], n.propose((a,)))
        with self.assertRaisesRegex(ValueError, "conflicting"):
            n.vote(self.keys[0], n.propose((b,)))


if __name__ == "__main__":
    unittest.main()
