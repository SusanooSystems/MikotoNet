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

## Four-validator network

```sh
python3 -m mikotonet.devnet /tmp/mikoto-devnet
```

The generator prints four commands. Run each in a separate terminal, for example:

```sh
python3 -m mikotonet.network /tmp/mikoto-devnet/node0.json
```

Run the other three configs the same way. The generated signed ask/bid vertices
are startup fixtures; nodes gossip them, collect three checkpoint signatures,
fsync their journals and replicate the same fill and state root. Each process
has its own Ed25519 key, vote locks, vertex log and checkpoint journal. The
installed equivalent is `mikotonet-node CONFIG.json`. Stop with Ctrl-C and
restart using the same config and data files. The generator refuses to overwrite
an existing directory and writes development private keys with mode 0600.

Configuration contains `chain`, `balances`, `peers` (public-key to `[host, port]`),
`key_file` (hex Ed25519 seed), `journal`, and optional `vertex_files` containing
signed vertex JSON. All validators must share the same chain, peer key set and
genesis balances. For separate hosts, configure reachable peer addresses and
separate local key/journal paths. Never copy a validator key into two running
validators. Use private networking or an encrypted tunnel: wire messages are
signed, but are not encrypted.

The library exposes authenticated `status`, `vertices`, `vote`, `finalize` and
one-checkpoint-at-a-time `sync` RPCs through `Peer.rpc`. Only allowlisted validator
keys can call these operations. New signed vertices can be sent with `vertices`;
the network does not hold account keys or manufacture user orders. There is no
public trading HTTP API.

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
- Append-only JSONL checkpoint journal: `Node(chain, validators, balances, path)`.
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

## Networking and crash-safe voting

TCP frames have a 4 MiB limit, five-second session timeout and 32 concurrent
inbound-session limit. Every connection uses a fresh server challenge. The
request signature binds challenge, intended recipient, genesis and operation;
the response is signed by the expected peer and binds the exact request digest.
Replay on a new connection, unknown peers, foreign genesis and altered content
are rejected. Signatures authenticate payloads; they do not hide their contents.

The leader is `sorted(validator_keys)[current_height % N]`. The leader requests
votes, validates the resulting quorum certificate locally, commits it, then
broadcasts it. Followers independently reconstruct ordering and execution roots
before signing. Restarted or disconnected nodes pull and verify missing
certificates. Unfinalized vertices are persisted and re-gossiped. A restarted
leader retries its original durably locked proposal, even if new vertices arrived.

With a journal configured, a signed checkpoint vote is fsynced to a separate
vote log **before the signature is returned or sent**. Recovery checks the saved
signature and full checkpoint and restores the `(validator, height)` lock. A
conflicting digest at that height is refused, including after abrupt process
exit. A storage failure disables further signing until restart; incomplete logs
fail closed. File and directory fsync protect new log entries and filenames.
An OS advisory lock prevents two node processes from sharing the same journal.
Without a journal, the original in-memory demo remains intentionally ephemeral;
network validators require a journal.

## Trust and operating limits

This is a minimal permissioned network implementation, not a complete
production BFT protocol. Each node runs one event loop and one storage writer.
There is no timeout-based view change: losing the designated leader stalls that
height. A Byzantine leader that splits votes across proposals can also stall
progress. Do not clear vote locks to regain liveness. There is no automatic
membership change, fork resolution, snapshot/compaction service, wall-clock
expiry or performance/WAN claim. Quorum safety assumes fewer than one third
Byzantine validators, intact durable vote locks and uncompromised keys.

Keep the key, checkpoint journal, `.votes`, `.vertices` and `.lock` files together
on trusted POSIX local storage. Whole-directory deletion/rollback and cloned
keys are outside the crash model; retain an external trusted checkpoint if
rollback detection is needed. Do not edit a truncated log to resume signing
without authoritative recovery. Account and validator key custody is caller-owned.

History, fills, receipts and ancestor sets grow in memory. Graph/order caps and
the 1,024-vertex gossip bundle limit are development bounds, not a production
resource budget. A checkpoint and its fresh vertices must fit a wire frame;
large-batch fragmentation is not implemented. Invalid signed business operations
produce deterministic rejection receipts and leave balances/nonces unchanged.
Malformed or unauthenticated transactions are rejected before certification.

## Source map

`mikotonet/engine.py` contains canonical encoding, signatures, graph validation,
spot execution, checkpoints and recovery. `storage.py` owns sync writes and writer
locks; `network.py` owns the authenticated TCP service and replication loop;
`devnet.py` generates a runnable four-node local deployment. `mikotonet/demo.py` is the runnable
example. `tests/test_engine.py` covers graph invariants, admission, deterministic
ordering, matching, conservation, rejection atomicity, quorum, replay and recovery.
Network tests cover authentication, replay, frame limits, leader restrictions,
quorum loss, restart catch-up and durable proposal retry. A separate integration
test launches four actual node processes, finalizes a funded trade, stops them
and verifies equal recovered state. Crash-vote testing uses abrupt process exit;
fsync failure and concurrent writers are also tested. These are loopback results,
not evidence of geographically distributed deployment.
