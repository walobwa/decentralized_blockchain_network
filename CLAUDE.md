# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

Each node is a standalone Express process taking two CLI args: `<port>` and `<currentNodeUrl>`.

```bash
# Run an individual node (nodemon, auto-restarts on changes in dev/)
npm run node_1     # port 3001, http://localhost:3001
npm run node_2     # port 3002
# ... node_3 (3003), node_4 (3004), node_5 (3005)

# Run a node directly without nodemon
node dev/networkNode.js 3001 http://localhost:3001

# Sanity-check the Blockchain class in isolation (logs genesis block)
node dev/test.js
```

There is **no test runner, linter, or build step** — `npm test` is a placeholder that exits 1. To exercise behavior, run multiple nodes on different ports and drive them with HTTP requests (curl/Postman).

## Architecture

A tutorial-style proof-of-work blockchain where each node holds a **full, independent copy** of the chain. There is no shared store — consistency is maintained purely by HTTP broadcast between peers.

**Two layers:**

- `dev/blockchain.js` — the `Blockchain` constructor (prototype-based, not ES class). Owns chain data and crypto: `createNewBlock`, `createNewTransaction`, `addTransactionToPendingTransactions`, `hashBlock` (sha256 of `previousBlockHash + nonce + JSON.stringify(blockData)`), and `proofOfWork` (increments nonce until the hash starts with `0000`). Pure logic, no networking. Note: `currentNodeUrl` is read from `process.argv[3]` at module load.
- `dev/networkNode.js` — the Express API wrapping one `Blockchain` instance (`bitcoin`). All peer coordination lives here.

**Peer registration (3-endpoint handshake).** When a new node joins via `POST /register-and-broadcast-node`, the receiving node: (1) records the new URL, (2) tells every existing peer to register it via `POST /register-node`, then (3) sends the new node the full peer list via `POST /register-nodes-bulk`. The result is an all-to-all mesh — every node knows every other node. `bitcoin.networkNodes` holds peer URLs (excluding self).

**Transaction flow.** Always enter via `POST /transaction/broadcast` (creates the transaction, adds it locally, then fans out to peers' `POST /transaction` so every node's `pendingTransactions` matches). `POST /transaction` is the internal receive-only endpoint — do not call it directly from clients, or pools will drift.

**Mining flow.** `GET /mine` runs proof-of-work over the current pending transactions, creates the block, broadcasts it to peers via `POST /receive-new-block`, then awards a mining reward by broadcasting a new `12.5` transaction (sender `"00"`). Peers in `receive-new-block` accept a block only if `previousBlockHash` and `index` chain correctly onto their last block; otherwise they reject it.

**Key architectural gaps** (relevant when extending): there is no `/consensus` / longest-chain endpoint, so diverged nodes cannot resolve forks; and transactions are not validated (no signatures or balance checks).
