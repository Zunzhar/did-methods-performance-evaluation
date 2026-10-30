import sqlite3
from pathlib import Path

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS identities (
    did TEXT PRIMARY KEY,
    profile TEXT NOT NULL,
    alias TEXT NOT NULL,
    document_json TEXT NOT NULL,
    previous_document_json TEXT,
    document_visible_at REAL NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active',
    status_visible_at REAL NOT NULL DEFAULT 0,
    public_key_b64 TEXT NOT NULL,
    private_key_b64 TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    storage_bytes INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS credentials (
    credential_id TEXT PRIMARY KEY,
    issuer_did TEXT NOT NULL,
    subject_did TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    signature_b64 TEXT NOT NULL,
    issued_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    revoked_at REAL,
    revoked_visible_at REAL,
    storage_bytes INTEGER NOT NULL,
    FOREIGN KEY(issuer_did) REFERENCES identities(did),
    FOREIGN KEY(subject_did) REFERENCES identities(did)
);
CREATE TABLE IF NOT EXISTS challenges (
    challenge_id TEXT PRIMARY KEY,
    did TEXT NOT NULL,
    verifier_id TEXT NOT NULL,
    credential_id TEXT,
    nonce TEXT NOT NULL,
    message TEXT NOT NULL,
    expires_at REAL NOT NULL,
    used_at REAL,
    created_at REAL NOT NULL,
    FOREIGN KEY(did) REFERENCES identities(did)
);
CREATE TABLE IF NOT EXISTS permissions (
    permission_id TEXT PRIMARY KEY,
    did TEXT NOT NULL,
    resource TEXT NOT NULL,
    action TEXT NOT NULL,
    require_credential INTEGER NOT NULL DEFAULT 0,
    conditions_json TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL,
    UNIQUE(did, resource, action),
    FOREIGN KEY(did) REFERENCES identities(did)
);
CREATE TABLE IF NOT EXISTS audit_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    profile TEXT,
    operation TEXT NOT NULL,
    identifier TEXT,
    request_received_at REAL NOT NULL,
    method_accepted_at REAL,
    publication_at REAL,
    finality_at REAL,
    first_resolvable_at REAL,
    observed_duration_ms REAL NOT NULL,
    simulated_network_latency_ms REAL,
    response_class TEXT NOT NULL,
    state_version INTEGER,
    synthetic_cost_units REAL NOT NULL DEFAULT 0,
    storage_bytes INTEGER,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_profile ON audit_events(profile, operation);
CREATE INDEX IF NOT EXISTS idx_credentials_subject ON credentials(subject_did);
"""


class Database:
    def __init__(self, path: str | Path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 10000")
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    def initialize(self) -> None:
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    def reset(self) -> None:
        with self.connect() as conn:
            conn.executescript("""
            DROP TABLE IF EXISTS audit_events;
            DROP TABLE IF EXISTS permissions;
            DROP TABLE IF EXISTS challenges;
            DROP TABLE IF EXISTS credentials;
            DROP TABLE IF EXISTS identities;
            """)
            conn.executescript(SCHEMA)
