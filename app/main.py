import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .config import PROFILES, profile_public_dict
from .database import Database
from .engine import IAMEngine

BASE_DIR = Path(__file__).resolve().parent.parent


class CreateIdentityRequest(BaseModel):
    profile: str
    alias: str = Field(default="New identity", max_length=100)

class RotateKeyRequest(BaseModel):
    confirm: bool = True

class IssueCredentialRequest(BaseModel):
    issuer_did: str
    subject_did: str
    claims: dict[str, Any]
    expires_in_seconds: int = Field(default=86400, ge=60, le=31536000)

class RevokeCredentialRequest(BaseModel):
    confirm: bool = True

class ChallengeRequest(BaseModel):
    did: str
    verifier_id: str = Field(min_length=1, max_length=200)
    credential_id: str | None = None
    ttl_seconds: int = Field(default=120, ge=10, le=600)

class PermissionRequest(BaseModel):
    did: str
    resource: str = Field(min_length=1, max_length=300)
    action: str = Field(min_length=1, max_length=100)
    require_credential: bool = False
    conditions: dict[str, Any] = Field(default_factory=dict)

class AuthorizeRequest(BaseModel):
    did: str
    resource: str
    action: str
    challenge_id: str
    signature: str
    verifier_id: str = Field(min_length=1, max_length=200)
    credential_id: str | None = None
    context: dict[str, Any] = Field(default_factory=dict)

class BenchmarkRequest(BaseModel):
    profiles: list[str] | None = None
    iterations: int = Field(default=10, ge=1, le=200)
    workload: str = "single_ops"
    concurrency_levels: list[int] | None = None


def create_app(db_path: str | None = None, visibility_delay_overrides_ms: dict[str, float] | None = None) -> FastAPI:
    chosen_db = db_path or os.getenv("IAM_DB_PATH", str(BASE_DIR / "data" / "prototype.sqlite3"))
    db = Database(chosen_db)
    engine = IAMEngine(db, visibility_delay_overrides_ms)
    app = FastAPI(
        title="Decentralized IAM Evaluation Lab",
        version="0.1.0",
        description=("Lifecycle-aware IAM evaluation lab for comparing DID deployment profiles. "
                     "Profiles run in local simulation mode."),
    )
    app.state.db = db
    app.state.engine = engine
    app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

    @app.get("/", include_in_schema=False)
    def home():
        return FileResponse(BASE_DIR / "static" / "index.html")

    @app.get("/api/v1/health")
    def health():
        return {"status": "healthy", "service": "decentralized-iam-evaluation-lab", "version": app.version,
                "mode": "local-simulation", "real_network_connections": False}

    @app.get("/api/v1/profiles")
    def list_profiles():
        return {"profiles": [profile_public_dict(PROFILES[pid]) | {"configured_visibility_delay_ms": engine.visibility_delay(pid)} for pid in PROFILES],
                "warning": "Profile latency and cost values are illustrative assumptions, not empirical or live network measurements."}

    @app.post("/api/v1/identities", status_code=201)
    def create_identity(body: CreateIdentityRequest):
        try:
            return engine.create_identity(body.profile, body.alias)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/v1/identities/{did:path}")
    def resolve_identity(did: str, cache: str = Query(default="cold", pattern="^(cold|warm)$"),
                         resolver: str = Query(default="resolver-a", min_length=1, max_length=100)):
        try:
            return engine.resolve_identity(did, cache, resolver)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/v1/identities/{did:path}/rotate")
    def rotate_identity(did: str, body: RotateKeyRequest):
        if not body.confirm:
            raise HTTPException(status_code=400, detail="Set confirm=true to rotate the key")
        try:
            return engine.rotate_key(did)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/api/v1/identities/{did:path}/deactivate")
    def deactivate_identity(did: str, body: RotateKeyRequest):
        if not body.confirm:
            raise HTTPException(status_code=400, detail="Set confirm=true to deactivate the DID")
        try:
            return engine.deactivate_identity(did)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/api/v1/credentials", status_code=201)
    def issue_credential(body: IssueCredentialRequest):
        try:
            return engine.issue_credential(body.issuer_did, body.subject_did, body.claims, body.expires_in_seconds)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/v1/credentials/{credential_id:path}")
    def get_credential(credential_id: str):
        try:
            return engine.get_credential(credential_id)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/api/v1/credentials/{credential_id:path}/revoke")
    def revoke_credential(credential_id: str, body: RevokeCredentialRequest):
        if not body.confirm:
            raise HTTPException(status_code=400, detail="Set confirm=true to revoke the credential")
        try:
            return engine.revoke_credential(credential_id)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/api/v1/credentials/{credential_id:path}/verify")
    def verify_credential(credential_id: str):
        return engine.verify_credential(credential_id)

    @app.post("/api/v1/challenges")
    def create_challenge(body: ChallengeRequest):
        try:
            return engine.create_challenge(body.did, body.verifier_id, body.credential_id, body.ttl_seconds)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/v1/permissions", status_code=201)
    def grant_permission(body: PermissionRequest):
        try:
            return engine.grant_permission(body.did, body.resource, body.action,
                                           body.require_credential, body.conditions)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.delete("/api/v1/permissions/{permission_id}")
    def revoke_permission(permission_id: str):
        if not engine.revoke_permission(permission_id):
            raise HTTPException(status_code=404, detail="Permission not found")
        return {"permission_id": permission_id, "revoked": True}

    @app.post("/api/v1/authorize")
    def authorize(body: AuthorizeRequest):
        try:
            return engine.authorize(body.did, body.resource, body.action, body.challenge_id,
                                    body.signature, body.verifier_id, body.credential_id, body.context)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/v1/metrics/summary")
    def metrics_summary():
        return engine.metrics_summary()

    @app.get("/api/v1/audit")
    def list_audit(limit: int = Query(default=100, ge=1, le=1000)):
        return {"events": engine.list_audit(limit)}

    @app.post("/api/v1/benchmarks/run")
    def run_benchmark(body: BenchmarkRequest):
        try:
            return engine.run_benchmark(body.profiles, body.iterations, body.workload, body.concurrency_levels)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    return app


app = create_app()
