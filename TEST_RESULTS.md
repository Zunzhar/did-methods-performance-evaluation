# Validation report

Validation date: 2026-10-27

## Automated tests

Command: `python -m pytest -q`

Result: **16 passed**.

Coverage includes:

- Health endpoint and all five profile configurations.
- Create/resolve and unknown DID handling.
- Key rotation and published key verification.
- Signed credential verification, revocation and stale-acceptance window.
- Holder proof, context conditions, missing permissions, one-time challenge replay rejection, and verifier binding.
- DID deactivation propagation.
- Cold/warm cache behavior and stale results from two independent simulated resolver instances.
- W1, W2, W3 and W4 benchmark execution and metrics summary.
- Invalid profile rejection.

## Cross-profile workload smoke test

All five simulated profiles were executed through all four workload paths with two iterations and no reported workload failures:

| Workload | Total completed operations across five profiles | Profiles with non-zero failure rate |
|---|---:|---:|
| W1 · Single operations | 20 | 0 |
| W2 · Enrollment burst | 25 | 0 |
| W3 · Mixed steady state | 90 | 0 |
| W4 · Fault injection | 60 | 0 |

The result validates local API and workload behavior only. It is not evidence of real blockchain/DID method performance.
