"""Run a four-validator local demonstration with ephemeral signing keys."""
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .engine import Node, Transaction, Vertex, public


def main():
    validators = [Ed25519PrivateKey.generate() for _ in range(4)]
    seller, buyer = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    node = Node("mikoto-local", [public(k) for k in validators], {
        public(seller): {"BASE": 10, "QUOTE": 0},
        public(buyer): {"BASE": 0, "QUOTE": 1000},
    })
    ask = Transaction.sign(seller, "mikoto-local", 0, "order", side="sell", price=25, quantity=4)
    bid = Transaction.sign(buyer, "mikoto-local", 0, "order", side="buy", price=30, quantity=4)
    first = node.graph.insert(Vertex.sign(validators[0], "mikoto-local", 0, transactions=(ask,)))
    second = node.graph.insert(Vertex.sign(validators[1], "mikoto-local", 0, parents=(first,), transactions=(bid,)))
    checkpoint = node.propose((second,))
    root = node.finalize(checkpoint, {public(k): node.vote(k, checkpoint) for k in validators[:3]})
    print(json.dumps({"mode": "local simulation", "height": node.height, "state_root": root,
                      "fills": node.exchange.fills, "balances": node.exchange.balances}, indent=2))


if __name__ == "__main__":
    main()
