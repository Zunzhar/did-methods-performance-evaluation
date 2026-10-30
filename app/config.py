from dataclasses import dataclass


@dataclass(frozen=True)
class ProfileSpec:
    id: str
    label: str
    method_family: str
    architecture: str
    simulated_network_latency_ms: float
    update_visibility_delay_ms: float
    synthetic_cost_units: dict[str, float]
    metadata_exposure: tuple[str, ...]
    trust_note: str


# These are illustrative simulation inputs, NOT measurements from real networks.
PROFILES: dict[str, ProfileSpec] = {
    "public_l1": ProfileSpec(
        id="public_l1",
        label="Public L1 · did:ethr family",
        method_family="did:ethr",
        architecture="On-chain / public Layer-1",
        simulated_network_latency_ms=900.0,
        update_visibility_delay_ms=900.0,
        synthetic_cost_units={"create": 5.0, "resolve": 0.15, "rotate": 5.0, "deactivate": 4.5, "credential_revoke": 2.5},
        metadata_exposure=("transaction timing", "public registry address", "operation linkage"),
        trust_note="Public validators and the selected RPC/resolver path are trust dependencies.",
    ),
    "layer2": ProfileSpec(
        id="layer2",
        label="EVM Layer-2 · did:ethr family",
        method_family="did:ethr",
        architecture="Layer-2 registry deployment",
        simulated_network_latency_ms=220.0,
        update_visibility_delay_ms=220.0,
        synthetic_cost_units={"create": 1.2, "resolve": 0.08, "rotate": 1.2, "deactivate": 1.0, "credential_revoke": 0.7},
        metadata_exposure=("sequencer timing", "registry address", "settlement linkage"),
        trust_note="Sequencer, RPC path, bridge/settlement design, and registry contract matter.",
    ),
    "sidetree": ProfileSpec(
        id="sidetree",
        label="Sidetree · did:ion family",
        method_family="did:ion",
        architecture="Batched operations with anchoring",
        simulated_network_latency_ms=550.0,
        update_visibility_delay_ms=550.0,
        synthetic_cost_units={"create": 2.0, "resolve": 0.12, "rotate": 2.0, "deactivate": 1.8, "credential_revoke": 1.1},
        metadata_exposure=("batch/anchor timing", "operation relationships visible to the deployment"),
        trust_note="Batch processing, anchoring, and resolver visibility are separate events.",
    ),
    "permissioned": ProfileSpec(
        id="permissioned",
        label="Permissioned ledger · did:indy family",
        method_family="did:indy",
        architecture="Permissioned validator pool",
        simulated_network_latency_ms=130.0,
        update_visibility_delay_ms=130.0,
        synthetic_cost_units={"create": 0.7, "resolve": 0.06, "rotate": 0.7, "deactivate": 0.6, "credential_revoke": 0.4},
        metadata_exposure=("validator-visible identifiers", "ledger transaction timing"),
        trust_note="Validator membership, governance, and ledger configuration are operational dependencies.",
    ),
    "ledgerless": ProfileSpec(
        id="ledgerless",
        label="Ledger-less · did:web family",
        method_family="did:web",
        architecture="HTTPS/domain-hosted document",
        simulated_network_latency_ms=65.0,
        update_visibility_delay_ms=65.0,
        synthetic_cost_units={"create": 0.25, "resolve": 0.04, "rotate": 0.25, "deactivate": 0.2, "credential_revoke": 0.15},
        metadata_exposure=("domain and request metadata", "hosting/access logs"),
        trust_note="Domain, DNS, HTTPS hosting, and document-serving availability replace ledger assumptions.",
    ),
}


def profile_public_dict(spec: ProfileSpec) -> dict:
    return {
        "id": spec.id,
        "label": spec.label,
        "method_family": spec.method_family,
        "architecture": spec.architecture,
        "simulated_network_latency_ms": spec.simulated_network_latency_ms,
        "update_visibility_delay_ms": spec.update_visibility_delay_ms,
        "synthetic_cost_units": spec.synthetic_cost_units,
        "metadata_exposure": list(spec.metadata_exposure),
        "trust_note": spec.trust_note,
        "execution_mode": "LOCAL SIMULATION — not connected to a real ledger or DID resolver",
    }
