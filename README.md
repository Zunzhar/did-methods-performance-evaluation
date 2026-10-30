# Decentralized IAM Evaluation Lab

A runnable local evaluation lab based on the paper supplied with the request. It implements a lifecycle-aware IAM API, five deployment-profile simulators, Ed25519-signed credential envelopes, proof-of-possession challenges, direct permission checks, propagation-window behavior, an audit trail, and benchmark workloads.

## Important scope boundary

This evaluation lab **does not connect to public Ethereum, an EVM Layer-2, ION/Sidetree, Hyperledger Indy, or a live `did:web` domain**. The five profiles are pluggable local simulations of the architecture families. Identifiers use `did:prototype:` on purpose; they are synthetic identifiers, not production DIDs for the method families named in the profile picker.

- **Observed latency / throughput:** measured from the local Python + SQLite implementation on the machine that runs it.
- **Network latency, update propagation and cost units:** illustrative configurable assumptions in `app/config.py`, not empirical findings or current fee estimates.
- **Credential envelope:** the app signs a small JSON credential-like object with Ed25519. It is not a full W3C VC Data Model implementation and does not claim conformance.
- **Security:** this is a development implementation. It stores private signing keys in a local SQLite database so credential issuing and demo flows work end-to-end. The browser also holds the newly returned demo key in tab memory. Do not use real identities, secrets, or production workloads. A production design should keep holder keys in a wallet/HSM and isolate issuer signing keys.

These caveats preserve the paper's distinction between a proposed evaluation framework and measured real-network results.

## Features implemented

1. DID create, resolve, key rotation, and deactivation lifecycle.
2. Five configurable profile simulators: public L1 (`did:ethr` family), EVM Layer-2 (`did:ethr` family), Sidetree (`did:ion` family), permissioned ledger (`did:indy` family), and ledger-less (`did:web` family).
3. Independent simulated resolver caches with cold/warm resolution, cache hit tracking, and stale-document detection.
4. Ed25519-signed credential envelopes with signature, issuer/subject state, expiry, and revocation checks.
5. One-time holder proof challenges bound to the DID, expected verifier, and optional credential; replay attempts are rejected.
6. Direct per-DID permissions with resource/action, optional credential requirement, and contextual conditions. Authorization follows `Identity AND holder proof AND Credential (when required) AND Permission AND Context`.
7. Configurable simulated propagation windows for key rotation, deactivation, and credential revocation. A credential can report `revocation_pending` and `stale_acceptance=true` during its simulated window.
8. Normalized audit telemetry for request receipt, method acceptance, publication, finality where applicable, first-resolvable time, observed duration, assumed network latency, version, synthetic cost units, storage, and response class.
9. Four common workload implementations: W1 single operations, W2 enrollment burst, W3 mixed steady state, and W4 fault injection.
10. Dashboard, JSON API, Swagger UI, metrics summary, audit trail, and automated tests.

## Run on Windows

1. Install Python 3.11+ (Python 3.13 is also supported by the tested stack).
2. Extract the ZIP.
3. Double-click `run_windows.bat`, or open PowerShell in this folder and run:

```powershell
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

4. Open <http://127.0.0.1:8000> for the UI or <http://127.0.0.1:8000/docs> for the API explorer.

## Run on Linux / macOS

```bash
./run.sh
```

Or activate your own Python environment, install `requirements.txt`, then run `python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload`.

The default database file is created at `data/prototype.sqlite3`. Set `IAM_DB_PATH` to use another path.

## Run tests

From the project root:

```bash
python -m pytest -q
```

Tests use temporary databases and do not modify the default demo database.

## Main API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/v1/health` | Health and execution mode |
| GET | `/api/v1/profiles` | Five profile definitions and assumptions |
| POST | `/api/v1/identities` | Create synthetic DID and demo wallet key |
| GET | `/api/v1/identities/{did}?cache=cold&resolver=resolver-a` | Resolve and refresh one independent simulated resolver cache |
| GET | `/api/v1/identities/{did}?cache=warm&resolver=resolver-b` | Read another resolver cache and expose stale-cache conditions |
| POST | `/api/v1/identities/{did}/rotate` | Rotate key; old document remains visible during configured delay |
| POST | `/api/v1/identities/{did}/deactivate` | Deactivate DID with a propagation delay |
| POST | `/api/v1/credentials` | Issue signed credential envelope |
| GET | `/api/v1/credentials/{credential_id}` | Inspect credential and status |
| POST | `/api/v1/credentials/{credential_id}/verify` | Verify credential proof and lifecycle |
| POST | `/api/v1/credentials/{credential_id}/revoke` | Revoke credential with modeled propagation |
| POST | `/api/v1/challenges` | Create one-time verifier-bound challenge |
| POST | `/api/v1/permissions` | Grant/update a direct permission |
| DELETE | `/api/v1/permissions/{permission_id}` | Revoke permission |
| POST | `/api/v1/authorize` | Evaluate proof, credential, permission and context |
| POST | `/api/v1/benchmarks/run` | Run one of W1–W4 |
| GET | `/api/v1/metrics/summary` | Summary metrics by profile |
| GET | `/api/v1/audit?limit=100` | Most recent normalized audit events |

## Benchmark workloads

- **W1 — Single operations:** sequential create + resolve cycles.
- **W2 — Enrollment burst:** concurrent identity creation at the requested concurrency levels.
- **W3 — Mixed steady state:** create an issuer and holder, resolve cold/warm, issue and verify a credential, rotate the holder key, and deactivate the holder.
- **W4 — Fault injection:** prime two independent simulated resolver caches, rotate a key, and count how many resolvers still return the previous document.

For each run the response separates observed local latency from synthetic profile assumptions. The configured cost units are intentionally unitless placeholders. To experiment with alternative assumptions, edit `PROFILES` in `app/config.py`; do not present those values as real-network results.

## Suggested next steps for a real empirical evaluation

1. Replace each simulated adapter with a method-specific adapter and publish exact SDK/network versions.
2. Connect independent resolver instances plus a testnet, local Indy pool, feasible ION/Sidetree testbed, and controlled `did:web` hosting.
3. Use synchronized clocks and capture method acceptance, ledger inclusion/publication, finality and first independent resolution separately.
4. Collect native transaction fees and a dated fiat conversion source; add actual on-/off-ledger storage and node/hosting/RPC operating costs.
5. Repeat all workload levels for enough trials, report distributions and failure rates, and treat profile-specific trust assumptions separately from the performance metrics.
