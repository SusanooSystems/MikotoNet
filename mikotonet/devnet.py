"""Generate private local-only development keys, genesis and four node configs."""
import argparse
import json
import os
from dataclasses import asdict
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .engine import Transaction, Vertex, public


def generate(directory, ports):
    directory = Path(directory).resolve()
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    keys = sorted([Ed25519PrivateKey.generate() for _ in range(4)], key=public)
    seller, buyer = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    chain = "mikoto-devnet"
    balances = {public(seller): {"BASE": 10, "QUOTE": 0}, public(buyer): {"BASE": 0, "QUOTE": 1000}}
    ask = Transaction.sign(seller, chain, 0, "order", side="sell", price=25, quantity=4)
    bid = Transaction.sign(buyer, chain, 0, "order", side="buy", price=30, quantity=4)
    a = Vertex.sign(keys[0], chain, 0, transactions=(ask,))
    b = Vertex.sign(keys[1], chain, 0, parents=(a.id,), transactions=(bid,))
    for name, vertex in (("ask.json", a), ("bid.json", b)):
        (directory / name).write_text(json.dumps(asdict(vertex)))
    peers = {public(k): ["127.0.0.1", port] for k, port in zip(keys, ports)}
    configs = []
    for i, key in enumerate(keys):
        key_file = directory / f"validator{i}.key"
        fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(key.private_bytes_raw().hex())
        config = {"chain": chain, "balances": balances, "peers": peers, "key_file": str(key_file),
                  "journal": str(directory / f"node{i}.jsonl"),
                  "vertex_files": [str(directory / "ask.json"), str(directory / "bid.json")]}
        path = directory / f"node{i}.json"
        path.write_text(json.dumps(config, indent=2))
        configs.append(path)
    return configs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", help="new directory; must not already exist")
    parser.add_argument("--base-port", type=int, default=9100)
    args = parser.parse_args()
    if not 1024 <= args.base_port <= 65532:
        parser.error("base port must be 1024..65532")
    for config in generate(args.directory, range(args.base_port, args.base_port + 4)):
        print(f"python3 -m mikotonet.network {str(config)!r}")


if __name__ == "__main__":
    main()
