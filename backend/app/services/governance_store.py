"""Transactional single-host governance ledger; no Kubernetes client or writes.

Immutable review/decision/history rows and a leased outbox share one transaction.
SQLite is the initial durable backend, separate from graph checkpoints and Redis.
Execution approvals remain unavailable until independent preflight, conditional
execution and verification are implemented. No configuration flag bypasses this.
"""
import hashlib
import json
import os
import sqlite3
from contextlib import contextmanager, nullcontext
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from agents.guardian.governance import GovernedDecision
from agents.guardian.work import WorkItem
from backend.app.models.governance import DecisionInput, HoldInput, ReviewPublication


class LedgerError(ValueError):
    def __init__(self, code, status=409):
        super().__init__(code)
        self.code, self.status = code, status


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def digest(value):
    return "sha256:" + hashlib.sha256(encode(value).encode()).hexdigest()


def validate(model, value):
    # Revalidate instances too: Pydantic model_copy/update is not validation.
    return model.model_validate(value.model_dump(mode="json") if isinstance(value, model) else value)


class GovernanceStore:
    execution_available = False

    def __init__(self, path, *, clock=None, review_seconds=86400, execution_seconds=300, queue_capacity=64):
        self.execution_gate = None
        self.path = Path(path).resolve()
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        for value, maximum in ((review_seconds, 604800), (execution_seconds, 300), (queue_capacity, 4096)):
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError("invalid_governance_limit")
        self.review_seconds, self.execution_seconds, self.queue_capacity = review_seconds, execution_seconds, queue_capacity
        if not self.path.parent.exists():
            self.path.parent.mkdir(parents=True, mode=0o700)
        # Pre-create privately so WAL/shared-memory siblings inherit private mode.
        descriptor = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(descriptor)
        with self._connect() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1):
                raise ValueError("unsupported_governance_database_version")
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS reviews (
                    proposal_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, run_id TEXT NOT NULL UNIQUE,
                    revision INTEGER NOT NULL, cluster_id TEXT NOT NULL, namespace TEXT NOT NULL,
                    target_name TEXT NOT NULL, publisher TEXT NOT NULL, content_hash TEXT NOT NULL,
                    payload TEXT NOT NULL, published_at TEXT NOT NULL, review_expires_at TEXT NOT NULL,
                    UNIQUE(case_id, revision)
                );
                CREATE TABLE IF NOT EXISTS review_state (
                    proposal_id TEXT PRIMARY KEY REFERENCES reviews(proposal_id), status TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS decisions (
                    decision_id TEXT PRIMARY KEY, proposal_id TEXT NOT NULL UNIQUE REFERENCES reviews(proposal_id),
                    actor TEXT NOT NULL, idempotency_key TEXT NOT NULL, request_hash TEXT NOT NULL,
                    payload TEXT NOT NULL, note TEXT NOT NULL, UNIQUE(actor, idempotency_key)
                );
                CREATE TABLE IF NOT EXISTS events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT, proposal_id TEXT NOT NULL REFERENCES reviews(proposal_id),
                    kind TEXT NOT NULL, actor TEXT NOT NULL, recorded_at TEXT NOT NULL, details TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS outbox (
                    delivery_id TEXT PRIMARY KEY, proposal_id TEXT NOT NULL REFERENCES reviews(proposal_id),
                    cluster_id TEXT NOT NULL, namespace TEXT NOT NULL, payload TEXT NOT NULL,
                    status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
                    owner TEXT, lease_token TEXT, lease_expires_at TEXT
                );
                CREATE INDEX IF NOT EXISTS outbox_scope ON outbox(cluster_id, namespace, status);
                CREATE TABLE IF NOT EXISTS holds (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT, cluster_id TEXT NOT NULL, namespace TEXT NOT NULL,
                    kind TEXT NOT NULL, active INTEGER NOT NULL, reason TEXT NOT NULL,
                    actor TEXT NOT NULL, recorded_at TEXT NOT NULL
                );
                PRAGMA user_version=1;
                COMMIT;
            """)
            for table in ("reviews", "decisions", "events", "holds"):
                for action in ("UPDATE", "DELETE"):
                    db.execute(f"CREATE TRIGGER IF NOT EXISTS {table}_no_{action.lower()} BEFORE {action} ON {table} "
                               "BEGIN SELECT RAISE(ABORT, 'immutable_governance_record'); END")

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA synchronous=FULL")
        try:
            yield db
        finally:
            db.close()

    @contextmanager
    def transaction(self):
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                yield db
                db.commit()
            except BaseException:
                db.rollback()
                raise

    def now(self):
        value = self.clock()
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("server_clock_must_be_utc")
        return value

    @staticmethod
    def event(db, proposal_id, event_kind, actor, now, **details):
        db.execute("INSERT INTO events(proposal_id,kind,actor,recorded_at,details) VALUES (?,?,?,?,?)",
                   (proposal_id, event_kind, actor, now.isoformat(), encode(details)))

    @staticmethod
    def review_row(db, proposal_id):
        row = db.execute("SELECT r.*,s.status FROM reviews r JOIN review_state s USING(proposal_id) WHERE proposal_id=?",
                         (proposal_id,)).fetchone()
        if row is None:
            raise LedgerError("review_not_found", 404)
        return row

    @staticmethod
    def scoped(principal, row, permission):
        principal.require(permission, row["cluster_id"], row["namespace"])

    def expire(self, db, row, now):
        if row["status"] == "OPEN" and now >= datetime.fromisoformat(row["review_expires_at"]):
            db.execute("UPDATE review_state SET status='EXPIRED' WHERE proposal_id=?", (row["proposal_id"],))
            self.event(db, row["proposal_id"], "review_expired", "backend", now)
            return self.review_row(db, row["proposal_id"])
        return row

    def view(self,row):
        payload = json.loads(row["payload"])
        return {"schema_version": "guardian.review-record.v1", "proposal_id": row["proposal_id"],
                "status": row["status"], "published_at": row["published_at"], "review_expires_at": row["review_expires_at"],
                "publisher": row["publisher"], "content_hash": row["content_hash"],
                "execution_available": bool(self.execution_gate and self.execution_gate.available(row["proposal_id"])),
                "execution_blockers": [] if self.execution_gate and self.execution_gate.available(row["proposal_id"]) else ["governed_executor_unavailable"],
                "proposal": payload["proposal"], "report": payload["report"]}

    def publish_review(self, publication, principal, *, _connection=None):
        publication = validate(ReviewPublication, publication)
        p = publication.proposal
        principal.require("publish", p.target.cluster_id, p.target.namespace)
        if principal.kind != "service":
            raise LedgerError("publisher_must_be_service", 403)
        payload = publication.model_dump(mode="json")
        serialized = encode(payload)
        if len(serialized.encode()) > 2 * 1024 * 1024:
            raise LedgerError("review_too_large", 413)
        if p.execution_window_seconds != self.execution_seconds:
            raise LedgerError("execution_window_policy_mismatch")
        content_hash = digest(payload)
        with (nullcontext(_connection) if _connection is not None else self.transaction()) as db:
            now = self.now()
            existing = db.execute("SELECT proposal_id,content_hash,publisher FROM reviews WHERE proposal_id=?", (p.proposal_id,)).fetchone()
            if existing:
                if (existing["content_hash"], existing["publisher"]) != (content_hash, principal.actor):
                    raise LedgerError("immutable_review_conflict")
                return self.view(self.expire(db, self.review_row(db, p.proposal_id), now))
            previous = db.execute("SELECT * FROM reviews WHERE case_id=? ORDER BY revision DESC LIMIT 1", (p.case_id,)).fetchone()
            expected_revision = previous["revision"] + 1 if previous else 1
            if p.revision != expected_revision:
                raise LedgerError("revision_must_be_next_in_case")
            if previous and (previous["cluster_id"], previous["namespace"], previous["target_name"]) != (
                    p.target.cluster_id, p.target.namespace, p.target.name):
                raise LedgerError("case_scope_cannot_change")
            if db.execute("SELECT 1 FROM reviews WHERE run_id=?", (p.run_id,)).fetchone():
                raise LedgerError("run_already_has_review")
            # The stored proposal remains exactly what the publisher supplied.
            # Review authority uses these independent server-owned timestamps.
            db.execute("INSERT INTO reviews VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (
                p.proposal_id, p.case_id, p.run_id, p.revision, p.target.cluster_id, p.target.namespace,
                p.target.name, principal.actor, content_hash, serialized, now.isoformat(),
                (now + timedelta(seconds=self.review_seconds)).isoformat()))
            db.execute("INSERT INTO review_state VALUES (?,'OPEN')", (p.proposal_id,))
            if previous:
                changed = db.execute("UPDATE review_state SET status='SUPERSEDED' WHERE proposal_id=? AND status='OPEN'",
                                     (previous["proposal_id"],)).rowcount
                if changed:
                    self.event(db, previous["proposal_id"], "review_superseded", principal.actor, now, successor=p.proposal_id)
            self.event(db, p.proposal_id, "review_published", principal.actor, now, content_hash=content_hash)
            return self.view(self.review_row(db, p.proposal_id))

    def get_review(self, proposal_id, principal):
        with self.transaction() as db:
            row = self.review_row(db, proposal_id)
            self.scoped(principal, row, "read")
            return self.view(self.expire(db, row, self.now()))

    def list_reviews(self, cluster_id, namespace, principal, limit=100):
        principal.require("read", cluster_id, namespace)
        if type(limit) is not int or not 1 <= limit <= 100:
            raise LedgerError("invalid_page_limit", 422)
        with self.transaction() as db:
            rows = db.execute("SELECT proposal_id FROM reviews WHERE cluster_id=? AND namespace=? ORDER BY rowid DESC LIMIT ?",
                              (cluster_id, namespace, limit)).fetchall()
            now = self.now()
            summaries = []
            for r in rows:
                row = self.expire(db, self.review_row(db, r["proposal_id"]), now)
                summaries.append({name: row[name] for name in (
                    "proposal_id", "case_id", "run_id", "revision", "cluster_id", "namespace", "target_name",
                    "publisher", "content_hash", "status", "published_at", "review_expires_at")})
            return summaries

    def record_decision(self, proposal_id, request, principal):
        request = validate(DecisionInput, request)
        request_hash = digest({"proposal_id": proposal_id, **request.model_dump(mode="json")})
        ticket = None
        writing = request.kind in ("approve_remediation", "adopt_baseline")
        # Slow Kubernetes/profile checks stay outside the collector's DB lock.
        # The final commit compares a short-lived server ticket and current
        # credential, holds, immutable plan and source revision again.
        if writing:
            with self._connect() as db:
                row=self.review_row(db,proposal_id);self.scoped(principal,row,'review')
                if principal.kind!='human' or principal.actor==row['publisher']:
                    raise LedgerError('human_review_required',403)
                old=db.execute('SELECT * FROM decisions WHERE actor=? AND idempotency_key=?',(principal.actor,request.idempotency_key)).fetchone()
                if old:
                    if old['request_hash']!=request_hash:raise LedgerError('idempotency_conflict')
                    return json.loads(old['payload'])
            if self.execution_gate is not None:
                ticket=self.execution_gate.prepare_decision(proposal_id,request,principal)
        expired = False
        with self.transaction() as db:
            now = self.now()
            row = self.review_row(db, proposal_id)
            self.scoped(principal, row, "review")
            if principal.kind != "human" or principal.actor == row["publisher"]:
                raise LedgerError("human_review_required", 403)
            old = db.execute("SELECT * FROM decisions WHERE actor=? AND idempotency_key=?", (principal.actor, request.idempotency_key)).fetchone()
            if old:
                if old["request_hash"] != request_hash:
                    raise LedgerError("idempotency_conflict")
                return json.loads(old["payload"])
            row = self.expire(db, row, now)
            expired = row["status"] == "EXPIRED"
            if not expired:
                if row["status"] != "OPEN":
                    raise LedgerError("review_not_open")
                p = ReviewPublication.model_validate_json(row["payload"]).proposal
                if (request.expected_revision, request.expected_approval_hash) != (p.revision, p.approval_hash):
                    raise LedgerError("review_revision_or_hash_changed")
                # No backend readiness/preflight/executor exists in phase 1.
                # A publisher's passing gates or a human flag cannot supply it.
                if writing:
                    if self.execution_gate is None:raise LedgerError("governed_executor_unavailable",503)
                    self.execution_gate.check_ticket(db,proposal_id,request,principal,ticket)
                count = db.execute("SELECT count(*) FROM outbox WHERE cluster_id=? AND namespace=? AND status!='ACKED'",
                                   (row["cluster_id"], row["namespace"])).fetchone()[0]
                if count >= self.queue_capacity:
                    raise LedgerError("resume_queue_full", 503)
                decision_id="decision-"+uuid4().hex
                recovery_id=self.execution_gate.commit_authority(db,proposal_id,decision_id,request,principal,now) if writing else None
                decision = GovernedDecision(decision_id=decision_id, proposal_id=proposal_id,
                    revision=p.revision, kind=request.kind, authority="human", actor=principal.actor,
                    approval_hash=p.approval_hash, policy_version=p.policy_version, target_uid=p.target.uid,
                    approved_at=now, execution_expires_at=now+timedelta(seconds=self.execution_seconds) if writing else None,
                    recovery_authority_id=recovery_id)
                value = decision.model_dump(mode="json")
                db.execute("INSERT INTO decisions VALUES (?,?,?,?,?,?,?)", (decision.decision_id, proposal_id,
                    principal.actor, request.idempotency_key, request_hash, encode(value), request.note))
                db.execute("UPDATE review_state SET status='RESOLVED' WHERE proposal_id=?", (proposal_id,))
                work = WorkItem(work_id="resume-" + decision.decision_id, run_id=p.run_id, kind="resume", decision_id=decision.decision_id)
                db.execute("INSERT INTO outbox(delivery_id,proposal_id,cluster_id,namespace,payload,status) VALUES (?,?,?,?,?,'PENDING')",
                           (work.work_id, proposal_id, row["cluster_id"], row["namespace"], work.model_dump_json()))
                self.event(db, proposal_id, "decision_recorded", principal.actor, now,
                           decision_id=decision.decision_id, kind=request.kind, note=request.note)
        if expired:
            # Commit the expiration history even though this request is rejected.
            raise LedgerError("review_expired")
        return value

    def get_decision(self, decision_id, principal):
        with self._connect() as db:
            row = db.execute("SELECT * FROM decisions WHERE decision_id=?", (decision_id,)).fetchone()
            if row is None:
                raise LedgerError("decision_not_found", 404)
            self.scoped(principal, self.review_row(db, row["proposal_id"]), "read")
            value=json.loads(row["payload"])
            if self.execution_gate is not None:
                value['revoked']=bool(db.execute("SELECT 1 FROM execution_revocations WHERE decision_id=? AND kind IN ('forward','all')",(decision_id,)).fetchone())
            return value

    def history(self, proposal_id, principal, after_sequence=0, limit=100):
        if type(after_sequence) is not int or after_sequence < 0 or type(limit) is not int or not 1 <= limit <= 100:
            raise LedgerError("invalid_history_page", 422)
        with self._connect() as db:
            self.scoped(principal, self.review_row(db, proposal_id), "read")
            return [{**dict(row), "details": json.loads(row["details"])} for row in db.execute(
                "SELECT * FROM events WHERE proposal_id=? AND sequence>? ORDER BY sequence LIMIT ?",
                (proposal_id, after_sequence, limit))]

    def claim_deliveries(self, claim, principal):
        principal.require("deliver", claim.cluster_id, claim.namespace)
        if principal.kind != "service":
            raise LedgerError("delivery_requires_service_identity", 403)
        with self.transaction() as db:
            now = self.now()
            owner_filter="proposal_id NOT IN (SELECT proposal_id FROM execution_plans) AND " if self.execution_gate is not None else ""
            rows = db.execute("SELECT * FROM outbox WHERE cluster_id=? AND namespace=? AND "
                +owner_filter+"(status='PENDING' OR (status='CLAIMED' AND lease_expires_at<=?)) ORDER BY rowid LIMIT ?",
                (claim.cluster_id, claim.namespace, now.isoformat(), claim.limit)).fetchall()
            deliveries = []
            for row in rows:
                token = uuid4().hex
                expires = (now + timedelta(seconds=claim.lease_seconds)).isoformat()
                db.execute("UPDATE outbox SET status='CLAIMED',owner=?,lease_token=?,lease_expires_at=?,attempts=attempts+1 WHERE delivery_id=?",
                           (principal.actor, token, expires, row["delivery_id"]))
                deliveries.append({"delivery_id": row["delivery_id"], "lease_token": token, "lease_expires_at": expires,
                                   "attempt": row["attempts"] + 1, "work": json.loads(row["payload"])})
                self.event(db, row["proposal_id"], "resume_claimed", principal.actor, now,
                           delivery_id=row["delivery_id"], attempt=row["attempts"] + 1, lease_expires_at=expires)
            return deliveries

    def acknowledge_delivery(self, delivery_id, token, principal):
        with self.transaction() as db:
            row = db.execute("SELECT * FROM outbox WHERE delivery_id=?", (delivery_id,)).fetchone()
            if row is None:
                raise LedgerError("delivery_not_found", 404)
            self.scoped(principal, row, "deliver")
            if principal.kind != "service" or row["owner"] != principal.actor or row["lease_token"] != token:
                raise LedgerError("delivery_lease_mismatch")
            if row["status"] == "ACKED":
                return {"delivery_id": delivery_id, "status": "ACKED"}
            if row["status"] != "CLAIMED" or self.now() >= datetime.fromisoformat(row["lease_expires_at"]):
                raise LedgerError("delivery_lease_expired")
            db.execute("UPDATE outbox SET status='ACKED' WHERE delivery_id=?", (delivery_id,))
            self.event(db, row["proposal_id"], "resume_acknowledged", principal.actor, self.now(),
                       delivery_id=delivery_id, attempt=row["attempts"])
            return {"delivery_id": delivery_id, "status": "ACKED"}

    def record_hold(self, request, principal):
        request = validate(HoldInput, request)
        principal.require("operate", request.cluster_id, request.namespace)
        if principal.kind != "human":
            raise LedgerError("hold_requires_human_operator", 403)
        with self.transaction() as db:
            cursor = db.execute("INSERT INTO holds(cluster_id,namespace,kind,active,reason,actor,recorded_at) VALUES (?,?,?,?,?,?,?)",
                (request.cluster_id, request.namespace, request.kind, request.active, request.reason, principal.actor, self.now().isoformat()))
            return dict(db.execute("SELECT * FROM holds WHERE sequence=?", (cursor.lastrowid,)).fetchone())

    def get_holds(self, cluster_id, namespace, principal):
        principal.require("read", cluster_id, namespace)
        with self._connect() as db:
            rows = db.execute("SELECT h.* FROM holds h WHERE cluster_id=? AND namespace=? AND sequence IN "
                "(SELECT MAX(sequence) FROM holds WHERE cluster_id=? AND namespace=? GROUP BY kind)",
                (cluster_id, namespace, cluster_id, namespace)).fetchall()
            latest = {r["kind"]: dict(r) for r in rows}
            return {"cluster_id": cluster_id, "namespace": namespace, "pause": bool(latest.get("pause", {}).get("active")),
                    "incident": bool(latest.get("incident", {}).get("active")), "records": latest}
