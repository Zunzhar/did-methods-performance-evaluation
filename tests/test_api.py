import base64
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives import serialization

from app.main import create_app


@pytest.fixture
def client(tmp_path: Path):
    application = create_app(str(tmp_path / "test.sqlite3"), {key: 0 for key in ["public_l1", "layer2", "sidetree", "permissioned", "ledgerless"]})
    with TestClient(application) as test_client:
        yield test_client


def create_did(client: TestClient, profile="ledgerless", alias="Test identity"):
    response = client.post("/api/v1/identities", json={"profile": profile, "alias": alias})
    assert response.status_code == 201, response.text
    return response.json()


def sign_message(private_key_b64: str, message: str) -> str:
    private_key = serialization.load_der_private_key(base64.b64decode(private_key_b64), password=None)
    return base64.b64encode(private_key.sign(message.encode("utf-8"))).decode("ascii")


def test_health_and_profiles(client):
    assert client.get("/api/v1/health").json()["status"] == "healthy"
    profiles = client.get("/api/v1/profiles").json()["profiles"]
    assert {p["id"] for p in profiles} == {"public_l1", "layer2", "sidetree", "permissioned", "ledgerless"}
    assert all("SIMULATION" in p["execution_mode"] for p in profiles)


def test_create_and_resolve_did(client):
    created = create_did(client, alias="Library member")
    assert created["did"].startswith("did:prototype:")
    assert created["status"] == "active"
    assert "wallet_private_key" in created
    resolved = client.get(f"/api/v1/identities/{created['did']}")
    assert resolved.status_code == 200
    payload = resolved.json()
    assert payload["document"]["id"] == created["did"]
    assert payload["status"] == "active"


def test_unknown_did_returns_404(client):
    response = client.get("/api/v1/identities/did:prototype:not-real")
    assert response.status_code == 404


def test_key_rotation_publishes_new_key(client):
    created = create_did(client)
    did = created["did"]
    rotated = client.post(f"/api/v1/identities/{did}/rotate", json={"confirm": True})
    assert rotated.status_code == 200, rotated.text
    assert rotated.json()["version"] == 2
    resolved = client.get(f"/api/v1/identities/{did}").json()
    priv = serialization.load_der_private_key(base64.b64decode(rotated.json()["wallet_private_key"]), password=None)
    pub = base64.b64encode(priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    assert resolved["document"]["verificationMethod"][0]["publicKeyBase64"] == pub


def test_credential_signature_verifies_and_revocation_rejects(client):
    issuer = create_did(client, profile="permissioned")
    subject = create_did(client, profile="ledgerless")
    response = client.post("/api/v1/credentials", json={
        "issuer_did": issuer["did"], "subject_did": subject["did"],
        "claims": {"role": "student", "department": "security"}, "expires_in_seconds": 3600,
    })
    assert response.status_code == 201, response.text
    credential_id = response.json()["credential_id"]
    verified = client.post(f"/api/v1/credentials/{credential_id}/verify", json={}).json()
    assert verified["valid"] is True
    revoked = client.post(f"/api/v1/credentials/{credential_id}/revoke", json={"confirm": True})
    assert revoked.status_code == 200
    after = client.post(f"/api/v1/credentials/{credential_id}/verify", json={}).json()
    assert after["valid"] is False
    assert after["status"] == "revoked"


def test_revocation_stale_acceptance_window_is_visible(tmp_path):
    app = create_app(str(tmp_path / "propagation.sqlite3"), {"public_l1": 90, "layer2": 0, "sidetree": 0, "permissioned": 0, "ledgerless": 0})
    with TestClient(app) as client:
        issuer = create_did(client, "public_l1")
        subject = create_did(client, "ledgerless")
        issued = client.post("/api/v1/credentials", json={"issuer_did": issuer["did"], "subject_did": subject["did"], "claims": {"access": "lab"}}).json()
        credential_id = issued["credential_id"]
        client.post(f"/api/v1/credentials/{credential_id}/revoke", json={"confirm": True})
        during = client.post(f"/api/v1/credentials/{credential_id}/verify", json={}).json()
        assert during["valid"] is True
        assert during["status"] == "revocation_pending"
        assert during["stale_acceptance"] is True
        time.sleep(0.12)
        after = client.post(f"/api/v1/credentials/{credential_id}/verify", json={}).json()
        assert after["valid"] is False
        assert after["status"] == "revoked"


def test_authorization_requires_proof_permission_context_and_valid_credential(client):
    issuer = create_did(client, "permissioned", "Issuer")
    holder = create_did(client, "ledgerless", "Holder")
    vc_response = client.post("/api/v1/credentials", json={
        "issuer_did": issuer["did"], "subject_did": holder["did"], "claims": {"role": "student"}
    })
    assert vc_response.status_code == 201, vc_response.text
    credential_id = vc_response.json()["credential_id"]
    grant = client.post("/api/v1/permissions", json={
        "did": holder["did"], "resource": "lab-101", "action": "enter",
        "require_credential": True, "conditions": {"lab_open": True}
    })
    assert grant.status_code == 201, grant.text
    challenge = client.post("/api/v1/challenges", json={
        "did": holder["did"], "verifier_id": "lab-portal", "credential_id": credential_id
    }).json()
    signature = sign_message(holder["wallet_private_key"], challenge["message"])
    request = {"did": holder["did"], "resource": "lab-101", "action": "enter",
               "challenge_id": challenge["challenge_id"], "signature": signature, "verifier_id": "lab-portal",
               "credential_id": credential_id, "context": {"lab_open": True}}
    allowed = client.post("/api/v1/authorize", json=request)
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["decision"] == "ALLOW"
    assert all(allowed.json()["checks"].values())
    replay = client.post("/api/v1/authorize", json=request)
    assert replay.json()["decision"] == "DENY"
    assert any("already been used" in reason for reason in replay.json()["reasons"])

    new_challenge = client.post("/api/v1/challenges", json={
        "did": holder["did"], "verifier_id": "lab-portal", "credential_id": credential_id
    }).json()
    bad_context_request = dict(request, challenge_id=new_challenge["challenge_id"],
                               signature=sign_message(holder["wallet_private_key"], new_challenge["message"]),
                               verifier_id="lab-portal", context={"lab_open": False})
    denied = client.post("/api/v1/authorize", json=bad_context_request).json()
    assert denied["decision"] == "DENY"
    assert denied["checks"]["context_satisfied"] is False


def test_authorization_denies_missing_permission(client):
    holder = create_did(client)
    challenge = client.post("/api/v1/challenges", json={"did": holder["did"], "verifier_id": "test-verifier"}).json()
    signature = sign_message(holder["wallet_private_key"], challenge["message"])
    result = client.post("/api/v1/authorize", json={
        "did": holder["did"], "resource": "secret", "action": "read", "challenge_id": challenge["challenge_id"],
        "signature": signature, "verifier_id": "test-verifier", "context": {}
    }).json()
    assert result["decision"] == "DENY"
    assert result["checks"]["identity_verified"] is True
    assert result["checks"]["permission_granted"] is False


def test_deactivation_propagates_then_rejects_new_challenges(tmp_path):
    app = create_app(str(tmp_path / "deactivation.sqlite3"), {"ledgerless": 40})
    with TestClient(app) as client:
        identity = create_did(client)
        response = client.post(f"/api/v1/identities/{identity['did']}/deactivate", json={"confirm": True})
        assert response.status_code == 200
        assert response.json()["status"] == "deactivation_pending"
        # During the modeled propagation interval, the old active state remains resolvable.
        assert client.get(f"/api/v1/identities/{identity['did']}").json()["status"] == "active"
        time.sleep(0.07)
        assert client.get(f"/api/v1/identities/{identity['did']}").json()["status"] == "deactivated"
        assert client.post("/api/v1/challenges", json={"did": identity["did"], "verifier_id": "test"}).status_code == 409


def test_benchmark_and_metrics(client):
    result = client.post("/api/v1/benchmarks/run", json={"profiles": ["ledgerless", "permissioned"], "iterations": 2, "workload": "single_ops"})
    assert result.status_code == 200, result.text
    payload = result.json()
    assert len(payload["results"]) == 2
    assert all(row["operations_completed"] == 4 for row in payload["results"])
    assert payload["execution_mode"] == "local-simulation"
    metrics = client.get("/api/v1/metrics/summary").json()
    assert metrics["totals"]["identities"] >= 4
    assert "by_profile" in metrics


def test_enrollment_burst_benchmark(client):
    result = client.post("/api/v1/benchmarks/run", json={"profiles": ["ledgerless"], "iterations": 2, "workload": "enrollment_burst", "concurrency_levels": [1, 2]})
    assert result.status_code == 200, result.text
    row = result.json()["results"][0]
    assert len(row["concurrency_results"]) == 2
    assert row["operations_completed"] == 4


def test_invalid_profile_is_rejected(client):
    response = client.post("/api/v1/identities", json={"profile": "mainnet-magic", "alias": "invalid"})
    assert response.status_code == 400


def test_warm_resolver_cache_can_expose_stale_document(client):
    identity = create_did(client, "ledgerless")
    did = identity["did"]
    cold_before = client.get(f"/api/v1/identities/{did}?cache=cold").json()
    old_key = cold_before["document"]["verificationMethod"][0]["publicKeyBase64"]
    rotated = client.post(f"/api/v1/identities/{did}/rotate", json={"confirm": True}).json()
    warm = client.get(f"/api/v1/identities/{did}?cache=warm").json()
    assert warm["cache_hit"] is True
    assert warm["cache_stale"] is True
    assert warm["document"]["verificationMethod"][0]["publicKeyBase64"] == old_key
    cold_after = client.get(f"/api/v1/identities/{did}?cache=cold").json()
    assert cold_after["document"]["verificationMethod"][0]["publicKeyBase64"] != old_key


def test_challenge_is_bound_to_expected_verifier(client):
    holder = create_did(client)
    client.post("/api/v1/permissions", json={"did": holder["did"], "resource": "docs", "action": "read"})
    challenge = client.post("/api/v1/challenges", json={"did": holder["did"], "verifier_id": "verifier-A"}).json()
    signature = sign_message(holder["wallet_private_key"], challenge["message"])
    result = client.post("/api/v1/authorize", json={
        "did": holder["did"], "resource": "docs", "action": "read",
        "challenge_id": challenge["challenge_id"], "signature": signature,
        "verifier_id": "verifier-B", "context": {}
    }).json()
    assert result["decision"] == "DENY"
    assert any("different verifier" in reason for reason in result["reasons"])


def test_mixed_and_fault_benchmarks_run(client):
    mixed = client.post("/api/v1/benchmarks/run", json={"profiles": ["ledgerless"], "iterations": 2, "workload": "mixed_steady_state"})
    assert mixed.status_code == 200, mixed.text
    assert mixed.json()["results"][0]["operations_completed"] == 18
    fault = client.post("/api/v1/benchmarks/run", json={"profiles": ["ledgerless"], "iterations": 2, "workload": "fault_injection"})
    assert fault.status_code == 200, fault.text
    assert fault.json()["results"][0]["operations_completed"] == 12


def test_fault_injection_exposes_stale_state_in_independent_resolvers(client):
    identity = create_did(client, "ledgerless")
    did = identity["did"]
    client.get(f"/api/v1/identities/{did}?cache=cold&resolver=resolver-a")
    client.get(f"/api/v1/identities/{did}?cache=cold&resolver=resolver-b")
    client.post(f"/api/v1/identities/{did}/rotate", json={"confirm": True})
    a = client.get(f"/api/v1/identities/{did}?cache=warm&resolver=resolver-a").json()
    b = client.get(f"/api/v1/identities/{did}?cache=warm&resolver=resolver-b").json()
    assert a["cache_hit"] and b["cache_hit"]
    assert a["cache_stale"] and b["cache_stale"]
    fresh = client.get(f"/api/v1/identities/{did}?cache=cold&resolver=resolver-a").json()
    assert fresh["cache_stale"] is False
