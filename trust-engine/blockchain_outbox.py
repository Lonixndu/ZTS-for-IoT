"""Durable local audit and ordered delivery; the bridge has no idempotency key."""
import json
from contextlib import contextmanager
from pathlib import Path
import sqlite3
from threading import RLock

from blockchain_client import BridgeError, evidence_hash, make_trust_update


class UncertainDelivery(RuntimeError):
    pass


class BlockchainOutbox:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS deliveries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL, observed_at TEXT NOT NULL,
                decision_json TEXT NOT NULL, payload_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending', tx_id TEXT, last_error TEXT,
                UNIQUE(device_id, observed_at)
            )""")

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def append(self, decision: dict, *, connection=None):
        """Engine logger interface: persist BEFORE advancing in-memory state."""
        payload = make_trust_update(decision)
        try:
            def insert(db):
                db.execute("""INSERT INTO deliveries
                    (device_id, observed_at, decision_json, payload_json) VALUES (?, ?, ?, ?)""",
                    (decision["deviceId"], decision["timestamp"],
                     json.dumps(decision, ensure_ascii=False, allow_nan=False),
                     json.dumps(payload, ensure_ascii=False, allow_nan=False)))
            if connection is not None:
                insert(connection)  # Caller commits event + decision + outbox atomically.
            else:
                with self._lock, self._connect() as db:
                    insert(db)
        except sqlite3.Error as exc:
            raise OSError("could not persist the blockchain decision") from exc

    def latest(self, device_id):
        with self._lock, self._connect() as db:
            row = db.execute("SELECT * FROM deliveries WHERE device_id=? ORDER BY id DESC LIMIT 1",
                             (device_id,)).fetchone()
        return dict(row) if row else None

    def pending(self, device_id):
        with self._lock, self._connect() as db:
            row = db.execute("""SELECT * FROM deliveries WHERE device_id=? AND status!='committed'
                              ORDER BY id LIMIT 1""", (device_id,)).fetchone()
        return dict(row) if row else None

    def for_decision(self, device_id, observed_at):
        with self._lock, self._connect() as db:
            row = db.execute("SELECT * FROM deliveries WHERE device_id=? AND observed_at=?",
                             (device_id, observed_at)).fetchone()
        return dict(row) if row else None

    @staticmethod
    def receipt(row):
        if row is None:
            return None
        payload = json.loads(row["payload_json"])
        return {
            "deliveryId": row["id"], "status": row["status"], "txId": row["tx_id"],
            "error": row["last_error"], "evidenceHash": evidence_hash(payload),
            "ledgerTrustValue": payload["trust_value"], "ledgerThreshold": payload["threshold"],
            "ledgerReasonCode": payload["reason_code"],
        }

    def _mark(self, row, status, tx_id=None, error=None):
        with self._connect() as db:
            db.execute("UPDATE deliveries SET status=?, tx_id=?, last_error=? WHERE id=?",
                       (status, tx_id, error, row["id"]))
        row.update(status=status, tx_id=tx_id, last_error=error)
        return self.receipt(row)

    def deliver(self, client, device_id, *, confirm_uncertain_retry=False):
        with self._lock:
            row = self.pending(device_id)
            if row is None:
                return self.receipt(self.latest(device_id))
            payload = json.loads(row["payload_json"])
            if row["status"] == "uncertain":
                try:
                    tx_id = client.find_commit(payload)
                except BridgeError as exc:
                    return self._mark(row, "uncertain", error=str(exc))
                if tx_id:
                    return self._mark(row, "committed", tx_id=tx_id)
                if not confirm_uncertain_retry:
                    raise UncertainDelivery(
                        "no matching event is visible yet; check the ledger before setting "
                        "confirmUncertainRetry=true, which can create a duplicate event")
            # A process crash after submission must not cause an automatic resend.
            self._mark(row, "uncertain", error="submission started; commit receipt not recorded")
            try:
                tx_id = client.submit(payload)
            except BridgeError as exc:
                return self._mark(row, "uncertain" if exc.uncertain else "failed", error=str(exc))
            return self._mark(row, "committed", tx_id=tx_id)
