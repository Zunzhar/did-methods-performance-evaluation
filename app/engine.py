import json
import math
import secrets
import sqlite3
import statistics
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from .adapters import AdapterRegistry
from .config import PROFILES, ProfileSpec
from .crypto_utils import canonical_json, generate_key_pair, sign_b64, verify_b64
from .database import Database


def now_ts() -> float:
    return time.time()


def iso_ts(timestamp: float | None) -> str | None:
    if timestamp is None:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(timestamp)) + f".{int((timestamp % 1) * 1000):03d}Z"


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(p * len(ordered)) - 1))
    return round(ordered[index], 3)


class IAMEngine:
    def __init__(self, db: Database, visibility_delay_overrides_ms: dict[str, float] | None = None):
        self.db = db
        self.adapters = AdapterRegistry(visibility_delay_overrides_ms)
        self._resolver_cache: dict[str, dict[str, Any]] = {}
        self.cache_ttl_seconds = 2.0

    def profile(self, profile_id: str) -> ProfileSpec:
        return self.adapters.get(profile_id).spec

    def visibility_delay(self, profile_id: str) -> float:
        return self.adapters.get(profile_id).visibility_delay_ms()

    def _audit(self, *, profile: str | None, operation: str, identifier: str | None,
               received: float, started: float, response_class: str = "success",
               state_version: int | None = None, synthetic_cost_units: float = 0.0,
               storage_bytes: int | None = None, simulated_network_latency_ms: float | None = None,
               metadata: dict[str, Any] | None = None, publish: bool = False,
               finality: bool = False, first_resolvable_at: float | None = None) -> None:
        end = now_ts()
        observed_ms = max(0.0, (time.perf_counter() - started) * 1000.0)
        event_metadata = metadata or {}
        if profile in PROFILES:
            normalized = self.adapters.get(profile).normalize_event(
                operation=operation, request_received_at=received, method_accepted_at=end,
                publication_at=end if publish else None, finality_at=end if finality else None,
                first_resolvable_at=first_resolvable_at, state_version=state_version,
                response_class=response_class, metadata=event_metadata)
            profile = normalized["profile"]
            operation = normalized["operation"]
            event_metadata = normalized["metadata"]
        with self.db.connect() as conn:
            conn.execute(
                """INSERT INTO audit_events(timestamp, profile, operation, identifier,
                   request_received_at, method_accepted_at, publication_at, finality_at,
                   first_resolvable_at, observed_duration_ms, simulated_network_latency_ms,
                   response_class, state_version, synthetic_cost_units, storage_bytes, metadata_json)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (end, profile, operation, identifier, received, end,
                 end if publish else None, end if finality else None,
                 first_resolvable_at, round(observed_ms, 3),
                 simulated_network_latency_ms, response_class, state_version,
                 synthetic_cost_units, storage_bytes, json.dumps(event_metadata, sort_keys=True)),
            )

    def _identity_row(self, did: str) -> sqlite3.Row | None:
        with self.db.connect() as conn:
            return conn.execute("SELECT * FROM identities WHERE did = ?", (did,)).fetchone()

    def _effective_document(self, row: sqlite3.Row, at: float | None = None) -> dict[str, Any]:
        at = now_ts() if at is None else at
        document = row["document_json"]
        if row["previous_document_json"] and at < row["document_visible_at"]:
            document = row["previous_document_json"]
        return json.loads(document)

    def _effective_status(self, row: sqlite3.Row, at: float | None = None) -> str:
        at = now_ts() if at is None else at
        if row["status"] == "deactivated" and at < row["status_visible_at"]:
            return "active"
        return row["status"]

    def create_identity(self, profile_id: str, alias: str = "New identity") -> dict[str, Any]:
        received = now_ts()
        started = time.perf_counter()
        spec = self.profile(profile_id)
        private_key, public_key = generate_key_pair()
        did = f"did:prototype:{uuid.uuid4()}"
        created = now_ts()
        document = {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "verificationMethod": [{
                "id": f"{did}#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyBase64": public_key,
            }],
            "authentication": [f"{did}#key-1"],
            "assertionMethod": [f"{did}#key-1"],
            "prototypeProfile": profile_id,
            "prototypeOnly": True,
        }
        encoded_document = json.dumps(document, sort_keys=True)
        storage_bytes = len(encoded_document.encode("utf-8"))
        with self.db.connect() as conn:
            conn.execute(
                """INSERT INTO identities(did, profile, alias, document_json, public_key_b64,
                   private_key_b64, version, created_at, updated_at, storage_bytes)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (did, profile_id, alias.strip() or "New identity", encoded_document,
                 public_key, private_key, 1, created, created, storage_bytes),
            )
        self._audit(profile=profile_id, operation="did_create", identifier=did,
                    received=received, started=started, state_version=1,
                    synthetic_cost_units=spec.synthetic_cost_units["create"], storage_bytes=storage_bytes,
                    simulated_network_latency_ms=spec.simulated_network_latency_ms,
                    metadata={"alias": alias, "identifier_kind": "synthetic prototype DID"},
                    publish=True, finality=(profile_id in {"permissioned", "public_l1", "layer2"}),
                    first_resolvable_at=created)
        return {
            "did": did,
            "profile": profile_id,
            "profile_label": spec.label,
            "alias": alias.strip() or "New identity",
            "status": "active",
            "version": 1,
            "document": document,
            "wallet_private_key": private_key,
            "warning": "Demo wallet key. This prototype stores signing keys in its local SQLite database; do not use real identities or secrets.",
        }

    def resolve_identity(self, did: str, cache_condition: str = "cold", resolver_id: str = "resolver-a") -> dict[str, Any]:
        if cache_condition not in {"cold", "warm"}:
            raise ValueError("cache must be 'cold' or 'warm'")
        if not resolver_id or len(resolver_id) > 100:
            raise ValueError("resolver_id must contain 1 to 100 characters")
        received = now_ts()
        started = time.perf_counter()
        row = self._identity_row(did)
        if row is None:
            self._audit(profile=None, operation="did_resolve", identifier=did, received=received,
                        started=started, response_class="not_found", metadata={"cache_condition": cache_condition})
            raise LookupError(f"DID not found: {did}")
        spec = self.profile(row["profile"])
        now = now_ts()
        current_doc = self._effective_document(row, now)
        current_status = self._effective_status(row, now)
        current_pending_update = bool(row["previous_document_json"] and now < row["document_visible_at"])
        current_pending_deactivation = row["status"] == "deactivated" and now < row["status_visible_at"]
        current_version = max(1, row["version"] - 1) if current_pending_update else row["version"]
        cache_key = (resolver_id, did)
        cached = self._resolver_cache.get(cache_key)
        cache_hit = bool(cache_condition == "warm" and cached and cached["expires_at"] > now)
        if cache_hit:
            doc = cached["document"]
            status = cached["status"]
            visible_version = cached["version"]
            pending_update = cached["pending_update"]
            pending_deactivation = cached["pending_deactivation"]
            cached_at = cached["cached_at"]
        else:
            doc = current_doc
            status = current_status
            visible_version = current_version
            pending_update = current_pending_update
            pending_deactivation = current_pending_deactivation
            cached_at = now
            self._resolver_cache[cache_key] = {
                "document": doc, "status": status, "version": visible_version,
                "pending_update": pending_update, "pending_deactivation": pending_deactivation,
                "cached_at": now, "expires_at": now + self.cache_ttl_seconds,
            }
        cache_stale = (doc != current_doc or status != current_status or visible_version != current_version)
        self._audit(profile=row["profile"], operation="did_resolve", identifier=did, received=received,
                    started=started, response_class="success", state_version=visible_version,
                    synthetic_cost_units=spec.synthetic_cost_units["resolve"],
                    storage_bytes=row["storage_bytes"], simulated_network_latency_ms=spec.simulated_network_latency_ms,
                    metadata={"pending_update": pending_update, "pending_deactivation": pending_deactivation,
                              "resolver_id": resolver_id, "cache_condition": cache_condition, "cache_hit": cache_hit, "cache_stale": cache_stale,
                              "cache_ttl_seconds": self.cache_ttl_seconds, "cached_at": iso_ts(cached_at)})
        return {
            "did": did,
            "profile": row["profile"],
            "profile_label": spec.label,
            "alias": row["alias"],
            "status": status,
            "version": visible_version,
            "authoritative_version": row["version"],
            "document": doc,
            "updated_at": iso_ts(row["updated_at"]),
            "pending_update": pending_update,
            "pending_deactivation": pending_deactivation,
            "resolver_id": resolver_id,
            "cache_condition": cache_condition,
            "cache_hit": cache_hit,
            "cache_stale": cache_stale,
            "cache_ttl_seconds": self.cache_ttl_seconds,
            "simulated_visibility_delay_ms": self.visibility_delay(row["profile"]),
        }

    def rotate_key(self, did: str) -> dict[str, Any]:
        received = now_ts()
        started = time.perf_counter()
        row = self._identity_row(did)
        if row is None:
            raise LookupError(f"DID not found: {did}")
        status = self._effective_status(row)
        if status != "active":
            raise PermissionError("Cannot rotate a deactivated DID")
        spec = self.profile(row["profile"])
        new_private, new_public = generate_key_pair()
        old_document = row["document_json"]
        new_document = json.loads(old_document)
        new_document["verificationMethod"] = [{
            "id": f"{did}#key-{row['version'] + 1}",
            "type": "Ed25519VerificationKey2020",
            "controller": did,
            "publicKeyBase64": new_public,
        }]
        new_document["authentication"] = [f"{did}#key-{row['version'] + 1}"]
        new_document["assertionMethod"] = [f"{did}#key-{row['version'] + 1}"]
        encoded = json.dumps(new_document, sort_keys=True)
        visible_at = now_ts() + self.visibility_delay(row["profile"]) / 1000.0
        new_version = row["version"] + 1
        with self.db.connect() as conn:
            conn.execute(
                """UPDATE identities SET previous_document_json=?, document_json=?, document_visible_at=?,
                   public_key_b64=?, private_key_b64=?, version=?, updated_at=?, storage_bytes=? WHERE did=?""",
                (old_document, encoded, visible_at, new_public, new_private, new_version, now_ts(), len(encoded.encode()), did),
            )
        self._audit(profile=row["profile"], operation="did_key_rotate", identifier=did, received=received,
                    started=started, state_version=new_version,
                    synthetic_cost_units=spec.synthetic_cost_units["rotate"], storage_bytes=len(encoded.encode()),
                    simulated_network_latency_ms=spec.simulated_network_latency_ms,
                    metadata={"visibility_delay_ms": self.visibility_delay(row["profile"]), "new_key_version": new_version},
                    publish=True, finality=(row["profile"] in {"permissioned", "public_l1", "layer2"}),
                    first_resolvable_at=visible_at)
        return {"did": did, "version": new_version, "status": "update_pending" if visible_at > now_ts() else "active",
                "visible_at": iso_ts(visible_at), "visibility_delay_ms": self.visibility_delay(row["profile"]),
                "wallet_private_key": new_private,
                "warning": "Demo wallet key. Store it in a real client wallet in production; this prototype also stores it locally for demonstration."}

    def deactivate_identity(self, did: str) -> dict[str, Any]:
        received = now_ts()
        started = time.perf_counter()
        row = self._identity_row(did)
        if row is None:
            raise LookupError(f"DID not found: {did}")
        if self._effective_status(row) != "active":
            raise PermissionError("DID is already deactivated or deactivation is pending")
        spec = self.profile(row["profile"])
        visible_at = now_ts() + self.visibility_delay(row["profile"]) / 1000.0
        with self.db.connect() as conn:
            conn.execute("UPDATE identities SET status='deactivated', status_visible_at=?, updated_at=? WHERE did=?",
                         (visible_at, now_ts(), did))
        self._audit(profile=row["profile"], operation="did_deactivate", identifier=did, received=received,
                    started=started, state_version=row["version"],
                    synthetic_cost_units=spec.synthetic_cost_units["deactivate"], storage_bytes=row["storage_bytes"],
                    simulated_network_latency_ms=spec.simulated_network_latency_ms,
                    metadata={"visibility_delay_ms": self.visibility_delay(row["profile"])},
                    publish=True, finality=(row["profile"] in {"permissioned", "public_l1", "layer2"}),
                    first_resolvable_at=visible_at)
        return {"did": did, "status": "deactivation_pending" if visible_at > now_ts() else "deactivated",
                "visible_at": iso_ts(visible_at), "visibility_delay_ms": self.visibility_delay(row["profile"])}

    def issue_credential(self, issuer_did: str, subject_did: str, claims: dict[str, Any],
                         expires_in_seconds: int = 86400) -> dict[str, Any]:
        received = now_ts()
        started = time.perf_counter()
        issuer = self._identity_row(issuer_did)
        subject = self._identity_row(subject_did)
        if issuer is None or subject is None:
            raise LookupError("Issuer DID and subject DID must both exist")
        if self._effective_status(issuer) != "active" or self._effective_status(subject) != "active":
            raise PermissionError("Issuer and subject DIDs must be active")
        if not isinstance(claims, dict) or not claims:
            raise ValueError("claims must be a non-empty JSON object")
        if expires_in_seconds < 60 or expires_in_seconds > 31536000:
            raise ValueError("expires_in_seconds must be between 60 seconds and one year")
        spec = self.profile(issuer["profile"])
        credential_id = f"urn:uuid:{uuid.uuid4()}"
        issued = now_ts()
        expires = issued + expires_in_seconds
        payload = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "id": credential_id,
            "type": ["VerifiableCredential", "PrototypeCredential"],
            "issuer": issuer_did,
            "issuanceDate": iso_ts(issued),
            "expirationDate": iso_ts(expires),
            "credentialSubject": {"id": subject_did, **claims},
            "prototypeOnly": True,
        }
        payload_bytes = canonical_json(payload)
        signature = sign_b64(issuer["private_key_b64"], payload_bytes)
        payload_json = json.dumps(payload, sort_keys=True)
        storage_bytes = len(payload_bytes) + len(signature.encode("ascii"))
        with self.db.connect() as conn:
            conn.execute(
                """INSERT INTO credentials(credential_id, issuer_did, subject_did, payload_json,
                   signature_b64, issued_at, expires_at, storage_bytes) VALUES(?,?,?,?,?,?,?,?)""",
                (credential_id, issuer_did, subject_did, payload_json, signature, issued, expires, storage_bytes),
            )
        self._audit(profile=issuer["profile"], operation="credential_issue", identifier=credential_id,
                    received=received, started=started, state_version=issuer["version"],
                    synthetic_cost_units=spec.synthetic_cost_units["create"], storage_bytes=storage_bytes,
                    simulated_network_latency_ms=spec.simulated_network_latency_ms,
                    metadata={"issuer_did": issuer_did, "subject_did": subject_did, "claims_keys": list(claims.keys())},
                    publish=True, first_resolvable_at=issued)
        return {"credential_id": credential_id, "credential": payload,
                "proof": {"type": "Ed25519Signature2020", "proofPurpose": "assertionMethod",
                          "verificationMethod": f"{issuer_did}#key-{issuer['version']}", "signature": signature},
                "status": "active", "storage_bytes": storage_bytes,
                "warning": "Prototype credential envelope, not a conformance-certified W3C VC implementation."}

    def get_credential(self, credential_id: str) -> dict[str, Any]:
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM credentials WHERE credential_id=?", (credential_id,)).fetchone()
        if row is None:
            raise LookupError(f"Credential not found: {credential_id}")
        status = "active"
        if row["revoked_at"] is not None:
            status = "revoked" if now_ts() >= row["revoked_visible_at"] else "revocation_pending"
        elif now_ts() >= row["expires_at"]:
            status = "expired"
        return {"credential_id": credential_id, "credential": json.loads(row["payload_json"]),
                "issuer_did": row["issuer_did"], "subject_did": row["subject_did"],
                "status": status, "issued_at": iso_ts(row["issued_at"]), "expires_at": iso_ts(row["expires_at"]),
                "revoked_at": iso_ts(row["revoked_at"]), "revocation_visible_at": iso_ts(row["revoked_visible_at"]),
                "storage_bytes": row["storage_bytes"]}

    def revoke_credential(self, credential_id: str) -> dict[str, Any]:
        received = now_ts()
        started = time.perf_counter()
        with self.db.connect() as conn:
            row = conn.execute("""SELECT c.*, i.profile FROM credentials c JOIN identities i ON i.did=c.issuer_did
                               WHERE c.credential_id=?""", (credential_id,)).fetchone()
            if row is None:
                raise LookupError(f"Credential not found: {credential_id}")
            if row["revoked_at"] is not None:
                raise PermissionError("Credential is already revoked or revocation is pending")
            delay_ms = self.visibility_delay(row["profile"])
            revoked_at = now_ts()
            visible_at = revoked_at + delay_ms / 1000.0
            conn.execute("UPDATE credentials SET revoked_at=?, revoked_visible_at=? WHERE credential_id=?",
                         (revoked_at, visible_at, credential_id))
        self._audit(profile=row["profile"], operation="credential_revoke", identifier=credential_id,
                    received=received, started=started, response_class="success", storage_bytes=row["storage_bytes"],
                    synthetic_cost_units=self.profile(row["profile"]).synthetic_cost_units["credential_revoke"],
                    simulated_network_latency_ms=self.profile(row["profile"]).simulated_network_latency_ms,
                    metadata={"visibility_delay_ms": delay_ms, "stale_acceptance_possible": delay_ms > 0},
                    publish=True, first_resolvable_at=visible_at)
        return {"credential_id": credential_id, "status": "revocation_pending" if visible_at > now_ts() else "revoked",
                "revoked_at": iso_ts(revoked_at), "visible_at": iso_ts(visible_at),
                "propagation_delay_ms": delay_ms,
                "note": "The verifier may still accept this credential during the simulated propagation window." if delay_ms else "Revocation is immediately visible in this profile configuration."}

    def verify_credential(self, credential_id: str) -> dict[str, Any]:
        started = time.perf_counter()
        received = now_ts()
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM credentials WHERE credential_id=?", (credential_id,)).fetchone()
        if row is None:
            return {"valid": False, "status": "not_found", "reason": "Credential not found", "credential_id": credential_id}
        payload = json.loads(row["payload_json"])
        issuer = self._identity_row(row["issuer_did"])
        subject = self._identity_row(row["subject_did"])
        if issuer is None or subject is None:
            result = {"valid": False, "status": "invalid_identity", "reason": "Issuer or subject DID not found"}
        elif self._effective_status(issuer) != "active" or self._effective_status(subject) != "active":
            result = {"valid": False, "status": "invalid_identity", "reason": "Issuer or subject DID is deactivated"}
        elif now_ts() >= row["expires_at"]:
            result = {"valid": False, "status": "expired", "reason": "Credential has expired"}
        else:
            doc = self._effective_document(issuer)
            public_key = doc["verificationMethod"][0]["publicKeyBase64"]
            signature_ok = verify_b64(public_key, canonical_json(payload), row["signature_b64"])
            if not signature_ok:
                result = {"valid": False, "status": "invalid_signature", "reason": "Credential signature did not verify against the currently resolved issuer key"}
            elif row["revoked_at"] is not None and now_ts() >= row["revoked_visible_at"]:
                result = {"valid": False, "status": "revoked", "reason": "Credential revocation has propagated"}
            elif row["revoked_at"] is not None:
                result = {"valid": True, "status": "revocation_pending", "reason": "Stale acceptance window: revocation has not yet propagated", "stale_acceptance": True}
            else:
                result = {"valid": True, "status": "active", "reason": "Signature, issuer/subject status, and expiry checks passed", "stale_acceptance": False}
        spec = self.profile(issuer["profile"]) if issuer else None
        self._audit(profile=issuer["profile"] if issuer else None, operation="credential_verify", identifier=credential_id,
                    received=received, started=started, response_class="success" if result["valid"] else "rejected",
                    state_version=issuer["version"] if issuer else None,
                    synthetic_cost_units=spec.synthetic_cost_units["resolve"] if spec else 0,
                    storage_bytes=row["storage_bytes"], simulated_network_latency_ms=spec.simulated_network_latency_ms if spec else None,
                    metadata={"status": result["status"], "stale_acceptance": result.get("stale_acceptance", False)})
        result["credential_id"] = credential_id
        result["issuer_did"] = row["issuer_did"]
        result["subject_did"] = row["subject_did"]
        return result

    def create_challenge(self, did: str, verifier_id: str, credential_id: str | None = None,
                         ttl_seconds: int = 120) -> dict[str, Any]:
        resolved = self.resolve_identity(did)
        if resolved["status"] != "active":
            raise PermissionError("DID is not active")
        if ttl_seconds < 10 or ttl_seconds > 600:
            raise ValueError("ttl_seconds must be between 10 and 600")
        if credential_id:
            cred = self.get_credential(credential_id)
            if cred["subject_did"] != did:
                raise ValueError("Credential does not belong to this DID")
        challenge_id = str(uuid.uuid4())
        nonce = secrets.token_urlsafe(24)
        created = now_ts()
        expires = created + ttl_seconds
        message = f"{did}|{verifier_id}|{credential_id or ''}|{nonce}|{expires:.6f}"
        with self.db.connect() as conn:
            conn.execute("""INSERT INTO challenges(challenge_id,did,verifier_id,credential_id,nonce,message,
                           expires_at,created_at) VALUES(?,?,?,?,?,?,?,?)""",
                         (challenge_id, did, verifier_id, credential_id, nonce, message, expires, created))
        return {"challenge_id": challenge_id, "did": did, "verifier_id": verifier_id,
                "credential_id": credential_id, "nonce": nonce, "message": message,
                "expires_at": iso_ts(expires), "expires_at_unix": expires,
                "note": "Sign the exact message with the DID holder's Ed25519 private key. The challenge is single-use and bound to this verifier and credential."}

    def grant_permission(self, did: str, resource: str, action: str, require_credential: bool = False,
                         conditions: dict[str, Any] | None = None) -> dict[str, Any]:
        row = self._identity_row(did)
        if row is None:
            raise LookupError(f"DID not found: {did}")
        if self._effective_status(row) != "active":
            raise PermissionError("Cannot grant permissions to a deactivated DID")
        if not resource.strip() or not action.strip():
            raise ValueError("resource and action must be non-empty")
        conditions = conditions or {}
        if not isinstance(conditions, dict):
            raise ValueError("conditions must be a JSON object")
        permission_id = str(uuid.uuid4())
        with self.db.connect() as conn:
            existing = conn.execute("SELECT permission_id FROM permissions WHERE did=? AND resource=? AND action=?",
                                     (did, resource.strip(), action.strip())).fetchone()
            if existing:
                permission_id = existing["permission_id"]
                conn.execute("UPDATE permissions SET require_credential=?, conditions_json=?, created_at=? WHERE permission_id=?",
                             (int(require_credential), json.dumps(conditions, sort_keys=True), now_ts(), permission_id))
            else:
                conn.execute("INSERT INTO permissions(permission_id,did,resource,action,require_credential,conditions_json,created_at) VALUES(?,?,?,?,?,?,?)",
                             (permission_id, did, resource.strip(), action.strip(), int(require_credential),
                              json.dumps(conditions, sort_keys=True), now_ts()))
        return {"permission_id": permission_id, "did": did, "resource": resource.strip(), "action": action.strip(),
                "require_credential": require_credential, "conditions": conditions}

    def revoke_permission(self, permission_id: str) -> bool:
        with self.db.connect() as conn:
            cur = conn.execute("DELETE FROM permissions WHERE permission_id=?", (permission_id,))
        return cur.rowcount > 0

    def authorize(self, did: str, resource: str, action: str, challenge_id: str, signature: str,
                  verifier_id: str, credential_id: str | None = None, context: dict[str, Any] | None = None) -> dict[str, Any]:
        received = now_ts()
        started = time.perf_counter()
        context = context or {}
        checks = {"identity_verified": False, "holder_proof_valid": False, "credential_valid": True,
                  "permission_granted": False, "context_satisfied": False}
        reasons: list[str] = []
        row = self._identity_row(did)
        if row is None or self._effective_status(row) != "active":
            reasons.append("Identity does not exist or is not active")
        else:
            checks["identity_verified"] = True
            with self.db.connect() as conn:
                challenge = conn.execute("SELECT * FROM challenges WHERE challenge_id=?", (challenge_id,)).fetchone()
                permission = conn.execute("SELECT * FROM permissions WHERE did=? AND resource=? AND action=?",
                                          (did, resource, action)).fetchone()
                if challenge is not None and challenge["used_at"] is None:
                    conn.execute("UPDATE challenges SET used_at=? WHERE challenge_id=? AND used_at IS NULL", (now_ts(), challenge_id))
            if challenge is None:
                reasons.append("Challenge not found")
            elif challenge["used_at"] is not None:
                reasons.append("Challenge has already been used")
            elif now_ts() > challenge["expires_at"]:
                reasons.append("Challenge expired")
            elif challenge["did"] != did or challenge["credential_id"] != (credential_id or None):
                reasons.append("Challenge is not bound to this DID and credential")
            elif challenge["verifier_id"] != verifier_id:
                reasons.append("Challenge is bound to a different verifier")
            elif not verifier_id.strip():
                reasons.append("Verifier identifier is missing")
            else:
                doc = self._effective_document(row)
                pub = doc["verificationMethod"][0]["publicKeyBase64"]
                checks["holder_proof_valid"] = verify_b64(pub, challenge["message"].encode("utf-8"), signature)
                if not checks["holder_proof_valid"]:
                    reasons.append("Holder signature is invalid or the resolver still exposes an older key")
            if permission is None:
                reasons.append("No permission grants this action on this resource")
            else:
                checks["permission_granted"] = True
                required_conditions = json.loads(permission["conditions_json"])
                checks["context_satisfied"] = all(context.get(key) == value for key, value in required_conditions.items())
                if not checks["context_satisfied"]:
                    reasons.append("One or more contextual conditions are not satisfied")
                requires_credential = bool(permission["require_credential"])
                if requires_credential and not credential_id:
                    checks["credential_valid"] = False
                    reasons.append("This permission requires a verifiable credential")
                elif credential_id:
                    verification = self.verify_credential(credential_id)
                    checks["credential_valid"] = bool(verification.get("valid")) and verification.get("subject_did") == did
                    if not checks["credential_valid"]:
                        reasons.append("Credential is invalid, revoked, expired, or belongs to another DID")
                    if verification.get("stale_acceptance"):
                        reasons.append("Warning: credential accepted inside the modeled revocation propagation window")
            if not permission:
                checks["context_satisfied"] = False
        allowed = all(checks.values())
        decision = {"decision": "ALLOW" if allowed else "DENY", "allowed": allowed, "did": did,
                    "resource": resource, "action": action, "checks": checks, "reasons": reasons,
                    "authorization_rule": "Allow = I AND proof AND V (when required) AND P AND C",
                    "challenge_id": challenge_id, "timestamp": iso_ts(now_ts())}
        spec = self.profile(row["profile"]) if row else None
        self._audit(profile=row["profile"] if row else None, operation="authorize", identifier=did,
                    received=received, started=started, response_class="allowed" if allowed else "denied",
                    state_version=row["version"] if row else None,
                    synthetic_cost_units=spec.synthetic_cost_units["resolve"] if spec else 0,
                    storage_bytes=row["storage_bytes"] if row else None,
                    simulated_network_latency_ms=spec.simulated_network_latency_ms if spec else None,
                    metadata={"decision": decision["decision"], "checks": checks, "resource": resource, "action": action})
        return decision

    def list_audit(self, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(1000, limit))
        with self.db.connect() as conn:
            rows = conn.execute("SELECT * FROM audit_events ORDER BY event_id DESC LIMIT ?", (limit,)).fetchall()
        result = []
        for r in rows:
            result.append({
                "event_id": r["event_id"], "timestamp": iso_ts(r["timestamp"]), "profile": r["profile"],
                "operation": r["operation"], "identifier": r["identifier"],
                "request_received_at": iso_ts(r["request_received_at"]),
                "method_accepted_at": iso_ts(r["method_accepted_at"]), "publication_at": iso_ts(r["publication_at"]),
                "finality_at": iso_ts(r["finality_at"]), "first_resolvable_at": iso_ts(r["first_resolvable_at"]),
                "observed_duration_ms": r["observed_duration_ms"],
                "simulated_network_latency_ms": r["simulated_network_latency_ms"],
                "response_class": r["response_class"], "state_version": r["state_version"],
                "synthetic_cost_units": r["synthetic_cost_units"], "storage_bytes": r["storage_bytes"],
                "metadata": json.loads(r["metadata_json"]),
            })
        return result

    def metrics_summary(self) -> dict[str, Any]:
        with self.db.connect() as conn:
            totals = conn.execute("SELECT COUNT(*) AS total, COUNT(DISTINCT identifier) AS unique_identifiers FROM audit_events").fetchone()
            rows = conn.execute("SELECT profile, operation, observed_duration_ms, synthetic_cost_units, storage_bytes, response_class, simulated_network_latency_ms FROM audit_events").fetchall()
            identities = conn.execute("SELECT COUNT(*) AS c FROM identities").fetchone()["c"]
            credentials = conn.execute("SELECT COUNT(*) AS c FROM credentials").fetchone()["c"]
            active_permissions = conn.execute("SELECT COUNT(*) AS c FROM permissions").fetchone()["c"]
        by_profile: dict[str, dict[str, Any]] = {}
        for profile_id in PROFILES:
            subset = [r for r in rows if r["profile"] == profile_id]
            durations = [float(r["observed_duration_ms"]) for r in subset]
            costs = [float(r["synthetic_cost_units"]) for r in subset]
            storage = [int(r["storage_bytes"]) for r in subset if r["storage_bytes"] is not None]
            by_profile[profile_id] = {
                "label": PROFILES[profile_id].label,
                "operations": len(subset),
                "median_observed_latency_ms": round(statistics.median(durations), 3) if durations else 0,
                "p95_observed_latency_ms": percentile(durations, .95),
                "mean_synthetic_cost_units_per_event": round(statistics.mean(costs), 3) if costs else 0,
                "mean_storage_bytes": round(statistics.mean(storage), 1) if storage else 0,
                "synthetic_network_latency_ms": PROFILES[profile_id].simulated_network_latency_ms,
                "configured_propagation_delay_ms": self.visibility_delay(profile_id),
                "mode": "SIMULATION",
            }
        rejected = sum(1 for r in rows if r["response_class"] in {"rejected", "denied", "not_found", "error"})
        return {"totals": {"audit_events": totals["total"], "identities": identities, "credentials": credentials,
                          "active_permissions": active_permissions, "rejected_or_denied_events": rejected,
                          "overall_failure_rate": round(rejected / len(rows), 4) if rows else 0},
                "by_profile": by_profile,
                "measurement_notice": "Observed values measure this local prototype. Network latency and cost fields are synthetic assumptions, not real DID-network measurements."}

    def run_benchmark(self, profiles: list[str] | None = None, iterations: int = 10,
                      workload: str = "single_ops", concurrency_levels: list[int] | None = None) -> dict[str, Any]:
        allowed_workloads = {"single_ops", "enrollment_burst", "mixed_steady_state", "fault_injection"}
        if workload not in allowed_workloads:
            raise ValueError(f"workload must be one of: {', '.join(sorted(allowed_workloads))}")
        selected = profiles or list(PROFILES.keys())
        for profile_id in selected:
            self.profile(profile_id)
        iterations = max(1, min(200, int(iterations)))
        concurrency_levels = concurrency_levels or [1, 10, 50]
        concurrency_levels = [max(1, min(100, int(c))) for c in concurrency_levels]
        results = []
        for profile_id in selected:
            latencies: list[float] = []
            operation_count = 0
            failures = 0
            storage: list[int] = []
            costs: list[float] = []
            started = time.perf_counter()
            if workload == "enrollment_burst":
                level_rows = []
                for concurrency in concurrency_levels:
                    tasks = max(iterations, concurrency)
                    burst_start = time.perf_counter()
                    def create_one(index: int) -> tuple[float, int, float]:
                        t = time.perf_counter()
                        result = self.create_identity(profile_id, alias=f"benchmark-{profile_id}-{index}")
                        elapsed = (time.perf_counter() - t) * 1000
                        return elapsed, len(json.dumps(result["document"]).encode()), self.profile(profile_id).synthetic_cost_units["create"]
                    with ThreadPoolExecutor(max_workers=concurrency) as pool:
                        futures = [pool.submit(create_one, i) for i in range(tasks)]
                        for future in as_completed(futures):
                            try:
                                ms, size, cost = future.result()
                                latencies.append(ms); storage.append(size); costs.append(cost); operation_count += 1
                            except Exception:
                                failures += 1
                    burst_elapsed = max(0.000001, time.perf_counter() - burst_start)
                    level_rows.append({"concurrency": concurrency, "operations": tasks,
                                       "observed_throughput_ops_sec": round(tasks / burst_elapsed, 2),
                                       "observed_wall_time_ms": round(burst_elapsed * 1000, 3)})
                extra = {"concurrency_results": level_rows}
            else:
                extra = {}
                for index in range(iterations):
                    try:
                        t = time.perf_counter()
                        identity = self.create_identity(profile_id, alias=f"benchmark-{profile_id}-{index}")
                        self.resolve_identity(identity["did"], "cold")
                        profile_costs = self.profile(profile_id).synthetic_cost_units
                        iteration_cost = profile_costs["create"] + profile_costs["resolve"]
                        completed_ops = 2
                        if workload == "mixed_steady_state":
                            holder = self.create_identity(profile_id, alias=f"benchmark-holder-{profile_id}-{index}")
                            self.resolve_identity(holder["did"], "cold")
                            self.resolve_identity(holder["did"], "warm")
                            vc = self.issue_credential(identity["did"], holder["did"], {"purpose": "benchmark"})
                            self.verify_credential(vc["credential_id"])
                            self.rotate_key(holder["did"])
                            self.deactivate_identity(holder["did"])
                            iteration_cost += (2 * profile_costs["create"] + 3 * profile_costs["resolve"] +
                                               profile_costs["rotate"] + profile_costs["deactivate"])
                            completed_ops = 9
                        elif workload == "fault_injection":
                            self.resolve_identity(identity["did"], "cold", "resolver-b")
                            self.rotate_key(identity["did"])
                            resolver_a = self.resolve_identity(identity["did"], "warm", "resolver-a")
                            resolver_b = self.resolve_identity(identity["did"], "warm", "resolver-b")
                            extra.setdefault("stale_state_observations", 0)
                            extra["stale_state_observations"] += int(bool(resolver_a.get("cache_stale"))) + int(bool(resolver_b.get("cache_stale")))
                            iteration_cost += profile_costs["rotate"] + 3 * profile_costs["resolve"]
                            completed_ops = 6
                        latencies.append((time.perf_counter() - t) * 1000)
                        storage.append(len(json.dumps(identity["document"]).encode()))
                        costs.append(iteration_cost)
                        operation_count += completed_ops
                    except Exception as exc:
                        failures += 1
                        extra.setdefault("errors", []).append(str(exc))
            wall_seconds = max(0.000001, time.perf_counter() - started)
            spec = self.profile(profile_id)
            results.append({
                "profile": profile_id, "label": spec.label, "workload": workload,
                "iterations_requested": iterations, "operations_completed": operation_count,
                "observed_wall_time_ms": round(wall_seconds * 1000, 3),
                "observed_throughput_ops_sec": round(operation_count / wall_seconds, 2),
                "median_observed_latency_ms": round(statistics.median(latencies), 3) if latencies else 0,
                "p95_observed_latency_ms": percentile(latencies, .95),
                "failure_rate": round(failures / max(1, failures + len(latencies)), 4),
                "mean_document_storage_bytes": round(statistics.mean(storage), 1) if storage else 0,
                "synthetic_cost_units_per_iteration": round(statistics.mean(costs), 3) if costs else 0,
                "configured_propagation_delay_ms": self.visibility_delay(profile_id),
                "synthetic_network_latency_ms": spec.simulated_network_latency_ms,
                "metadata_exposure_fields": list(spec.metadata_exposure),
                "mode": "LOCAL SIMULATION",
                **extra,
            })
        return {"benchmark_id": str(uuid.uuid4()), "created_at": iso_ts(now_ts()), "workload": workload,
                "results": results,
                "execution_mode": "local-simulation"}
