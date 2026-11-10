# MikotoNet

Minimal financial-ledger implementation inspired by EbisuNet, replacing TideDAG
with a **Polytree**, an explicitly defined adaptation of a multitree DAG.
This is a standalone Python reference implementation; it does not depend on
or modify the EbisuNet workspace. The existing MikotoNet license is retained.

## Run

Requires Python 3.11+ and `cryptography` (ordinary Ed25519 signatures).

```sh
python3 -m pip install -e .
python3 -m mikotonet.demo
python3 -m unittest discover -s tests -v
```

The demo creates four ephemeral validator keys and two funded accounts, executes
a maker ask and a crossing bid, and finalizes them with three validator signatures.
It prints actual fills, balances and a SHA-256 state commitment. No keys or
funds from an external chain are used. Prices and quantities are positive integer
atomic units: `price * quantity` is QUOTE cost; market scaling is caller-defined.

## Minimal scope

- One BASE/QUOTE spot market with deterministic price-time priority, maker-price
  fills, partial fills, cancellation, reserved funds and self-trade rejection.
- Genesis-funded accounts; ordinary account Ed25519 signatures and sequential
  nonces. Genesis binds chain ID, validator public keys and initial balances.
- Signed vertices with bounded parent and transaction counts, author sequence
  ancestry, missing-parent rejection, and per-author/sequence equivocation checks.
- Deterministic topological ordering and explicit checkpoint certificates with
  `floor(2N/3)+1` distinct allowlisted validator signatures (minimum four validators).
  Certificates bind genesis, previous checkpoint, height, tips, exact vertex
  order and pre/post execution state roots including receipts and fills.
- Optional append-only JSONL journal: `Node(chain, validators, balances, path)`.
  Checkpoints are flushed and fsynced before applying/acknowledging. Restart
  re-verifies signatures and re-executes the certified history. Corrupt, foreign
  or truncated records fail closed; storage write failures require a restart.

No Solana/Ethereum settlement, MPC/FROST, PQC, encrypted mempool, VRF, staking,
perpetuals/leverage, derivatives, AI/ML, WASM, oracle adapters or custody bridges
are included. Funding is fixed by genesis; there is no unauthenticated mint route.

## Polytree definition

Edges point from a new vertex to existing parents. The ancestor closure of each
parent (including that parent) must be disjoint from every other parent's closure.
Thus each vertex has at most one directed path to any ancestor: independent
branches can merge, but a diamond cannot. This uses the directed **multitree**
meaning; it does not assert that the underlying undirected graph is a tree.
Only known parents are accepted, so cycles cannot be introduced.

An author's next vertex must descend from its previous vertex. Parent IDs are
sorted and unique. A checkpoint selects the full ancestor closure of its tips;
vertices sort by `(ancestor_count, vertex_id)`. Ancestors always precede
descendants; concurrent vertices have a deterministic hash tie-break. Finalized
vertices are skipped during later execution. Repeated transactions fail their
account nonce checks rather than moving funds twice.

Polytree supplies graph structure and ordering, **not finality on its own**.
Finality here is explicit permissioned checkpoint certification. Accounts need
only one Ed25519 signature per transaction; validators each sign the checkpoint.
This is not threshold cryptography or proof of stake.

## Trust and operating limits

This is a single-process, single-writer reference node with library APIs and a
local demo, not a deployed exchange or a complete networked BFT protocol. There
is no P2P transport, HTTP service, UI, leader/view-change protocol, synchronization
service, wall-clock expiry, external price feed or performance claim.

The local `vote` helper refuses conflicting votes at the same height during its
process lifetime. **Vote locks are not durable across restart**. Independent
validators would require durable signing locks, authenticated transport, a
proposal/locking/view-change protocol and fault testing before any distributed
safety or liveness claim. Keys are supplied by callers; production key custody
is not provided. Quorum verification assumes honest validators do not sign
conflicting checkpoints. Conflicting certificates are not resolved by fork choice.

The journal path must be on trusted local storage and have exactly one writer;
pre-create its parent directory. Directory creation durability, cross-process
locking, compaction, snapshots and protection from whole-file rollback/deletion
are not implemented. Unfinalized vertices are volatile. Keep an external trusted
head/genesis if rollback detection is required. History, fills and receipts grow
in memory; graph and order caps are development bounds, not a production resource
budget. Invalid signed business operations produce deterministic rejection
receipts and leave balances/nonces unchanged. Graph admission rejects malformed
or unauthenticated transactions before certification.

## Source map

`mikotonet/engine.py` contains canonical encoding, signatures, graph validation,
spot execution, checkpoints and recovery. `mikotonet/demo.py` is the runnable
example. `tests/test_engine.py` covers graph invariants, admission, deterministic
ordering, matching, conservation, rejection atomicity, quorum, replay and recovery.
