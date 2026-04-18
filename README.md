<div align="center">
  <img src="https://archivebox.io/icon.png" height="90" alt="ArchiveTeam NFT logo" />
  <h1>ArchiveTeam NFT</h1>
  <p><strong>A decentralized team for preserving the web.</strong></p>
  <p>
    <a href="#quickstart">Quickstart</a> ·
    <a href="#how-it-works">How it works</a> ·
    <a href="#api-reference">API</a> ·
    <a href="#governance">Governance</a> ·
    <a href="#distributed-site-pinning-phase-3b">Distributed Site Pinning</a>
  </p>
</div>

---

## What this project is

ArchiveTeam NFT is a decentralized archiving coordination layer built in the ArchiveBox codebase.

It enables a network of peers to:

- request archives
- claim and process requests
- serve already-archived content
- collaborate through collections
- govern changes through proposal voting
- keep the frontend alive through shared IPFS pinning

The goal is to make web preservation a shared responsibility across many participants, not a single host or operator.

---

## Current status

Implemented in this repo today:

- Identity + authentication
  - Ed25519 keypairs
  - `AT` display-prefixed public keys
  - challenge/signature login
- Request lifecycle
  - submit -> claim -> fulfill
  - `FULL_WARC` and `ZIP_WARC`
  - country preference support
  - 24-hour initial pin window
- Social/collaboration
  - profile metadata
  - collections (create/edit/delete/list/get)
  - owner moderation (approve/deny submissions)
  - forking collections
- Safety baseline
  - blocked URL terms/hosts at request intake
- Governance
  - proposal creation
  - `YES` / `NO` / `ABSTAIN` voting
  - quorum + threshold finalization
- Distributed site pinning (Phase 3b)
  - canonical site CID state
  - node pin attestations
  - pinner discovery + health quorum checks
- HTTP API
  - JSON endpoints under `/api/archiveteam/...`

---

## How it works

### 1) Identity and login

Each participant is represented by a keypair and profile.

1. Register (keypair generated and user profile created)
2. Request login challenge
3. Sign challenge with private key
4. Exchange signature for session token

### 2) Archiving flow

1. User submits URL request (with mode + optional country preference)
2. Online worker claims request
3. Worker fulfills request with content hash + storage URI
4. Archive is discoverable while online hosts can serve it
5. Ratio metrics track contribution vs consumption

### 3) Collections flow

Collection owners can:

- create collections with name/description
- set public/private visibility
- enable or disable submissions
- approve/deny submitted entries
- allow forks (copying collection state)

### 4) Governance flow (GitHub-like)

Participants can propose changes as governance proposals.

Proposal lifecycle:

- `OPEN` -> votes cast -> `APPROVED` / `REJECTED`
- or author closes proposal -> `CLOSED`

Voting options:

- `YES`
- `NO`
- `ABSTAIN`

### 5) Distributed site pinning flow

The network tracks a canonical frontend CID for the site.

- Site releases can be set directly (API) or via approved `SITE_RELEASE` proposal
- Peers attest they pin the current CID
- Health endpoint reports if online pin quorum is met

This enables "everyone keeps the site alive" instead of relying on one host.

---

## Architecture overview

Core module:

- `archivebox/archiveteam/network.py`

HTTP API layer:

- `archivebox/core/archiveteam_api.py`

Routing:

- `archivebox/core/urls.py`

Landing site:

- `website/index.html`
- `website/assets/css/archiveteam.css`

Tests:

- `tests/test_archiveteam_mvp.py`
- `tests/test_archiveteam_api.py`

---

## Quickstart

### Prerequisites

- Python 3.11+ recommended
- Existing repo setup dependencies

### Install and run tests

From repository root:

```bash
source .venv/bin/activate
pytest -q tests/test_archiveteam_mvp.py tests/test_archiveteam_api.py
```

---

## API reference

Base path: `/api/archiveteam`

### Health

- `GET /api/archiveteam/health`

### Identity and auth

- `POST /api/archiveteam/register`
- `POST /api/archiveteam/login/challenge`
- `POST /api/archiveteam/login/complete`
- `GET /api/archiveteam/me`
- `POST /api/archiveteam/profile`
- `POST /api/archiveteam/heartbeat`

### Requests and archives

- `POST /api/archiveteam/requests`
- `GET /api/archiveteam/requests/open`
- `POST /api/archiveteam/requests/claim`
- `POST /api/archiveteam/requests/fulfill`
- `GET /api/archiveteam/archives/search`
- `GET /api/archiveteam/ratio`

### Collections

- `POST /api/archiveteam/collections`
- `GET /api/archiveteam/collections`
- `GET /api/archiveteam/collections/<id>`
- `PATCH /api/archiveteam/collections/<id>`
- `DELETE /api/archiveteam/collections/<id>`
- `POST /api/archiveteam/collections/<id>/archives`
- `POST /api/archiveteam/collections/<id>/submit`
- `POST /api/archiveteam/submissions/<id>/review`
- `POST /api/archiveteam/collections/<id>/fork`

### Governance

- `POST /api/archiveteam/proposals`
- `GET /api/archiveteam/proposals`
- `GET /api/archiveteam/proposals/<id>`
- `POST /api/archiveteam/proposals/<id>/vote`
- `POST /api/archiveteam/proposals/<id>/finalize`
- `POST /api/archiveteam/proposals/<id>/close`

### Distributed Site Pinning (Phase 3b)

- `GET /api/archiveteam/site/current`
- `POST /api/archiveteam/site/release`
- `POST /api/archiveteam/site/pin-attest`
- `GET /api/archiveteam/site/pinners`
- `GET /api/archiveteam/site/health`

---

## CLI (current helper commands)

Namespace:

- `archivebox archiveteam ...`

Examples:

```bash
archivebox archiveteam register --username alice --country US
archivebox archiveteam profile --public-key AT... --bio "node runner"
archivebox archiveteam request --public-key AT... --url https://example.com --mode FULL_WARC
archivebox archiveteam claim --public-key AT...
archivebox archiveteam fulfill --public-key AT... --request-id <id> --content-hash <sha256> --storage-uri ipfs://...
archivebox archiveteam collection-create --owner-public-key AT... --name "Research"
archivebox archiveteam collection-fork --forker-public-key AT... --source-collection-id <id>
```

---

## Governance

Governance is designed to support community-driven evolution.

Proposal fields include:

- title
- description
- change type
- target
- optional patch payload
- quorum
- yes threshold

For site releases, use `change_type=SITE_RELEASE` and include CID payload in proposal patch.

Approved `SITE_RELEASE` proposals automatically update canonical site CID state.

---

## Distributed Site Pinning (Phase 3b)

To keep the frontend alive via peers:

1. Set canonical CID release (`/site/release` or approved governance proposal)
2. Each online node sends pin attestations (`/site/pin-attest`)
3. Query active pinners (`/site/pinners`)
4. Check quorum health (`/site/health?min_online_pinners=N`)

---

## Trust & safety note

Current safety controls are a first-pass URL blocklist.

For production-grade illegal-content defense, you should add:

- trusted hash matching pipelines
- stronger automated media classification
- strict escalation/reporting workflows
- legal/compliance operations

---

## Website and domain

Current redesigned landing page source:

- `website/index.html`
- `website/assets/css/archiveteam.css`

If using Unstoppable Domains + IPFS:

1. Publish static site to IPFS
2. Set domain website records to canonical CID
3. Use site pinning endpoints to ensure peer replication remains healthy

---

## Contributing

This project is evolving quickly. Contributions are welcome in:

- protocol and governance design
- API and node behavior
- frontend UX for decentralized workflows
- trust/safety hardening
- IPFS and peer distribution reliability

Use proposal/voting flow for significant network behavior changes.

---

## License

MIT — see `LICENSE`.
