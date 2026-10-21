"""Durable event receipts and replayable engine state; one supported API writer.

The engine's logger callback executes before its memory commit. This callback
commits the input, receipt, decision and (when enabled) delivery in one SQLite
transaction. Replaying those inputs restores ALL adaptive history on restart.
"""
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3

from device_state import Observation
from engine import TrustEngine


def json_text(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def fingerprint(value):
    return hashlib.sha256(json_text(value).encode("utf-8")).hexdigest()


class WriterLease:
    """Cross-platform process lock. The service supports one Uvicorn worker."""
    def __init__(self, path):
        self.path, self.stream = Path(str(path) + ".lock"), None

    def acquire(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.stream = self.path.open("a+b")
        self.stream.seek(0)
        if self.path.stat().st_size == 0:
            self.stream.write(b"0")
            self.stream.flush()
        self.stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.stream.close()
            self.stream = None
            raise RuntimeError("state database already has an API writer; use --workers 1") from None

    def release(self):
        if self.stream is not None:
            if os.name == "nt":
                import msvcrt
                self.stream.seek(0)
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.stream.fileno(), fcntl.LOCK_UN)
            self.stream.close()
            self.stream = None


class EventStore:
    def __init__(self, path, config, outbox=None):
        self.path, self.config, self.outbox = Path(path), config, outbox
        self.context = None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS registrations (
                    device_id TEXT PRIMARY KEY, seed_json TEXT NOT NULL, metadata_json TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS event_receipts (
                    event_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, payload_json TEXT NOT NULL,
                    http_status INTEGER NOT NULL, response_json TEXT NOT NULL, received_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS engine_inputs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL,
                    event_id TEXT UNIQUE, observation_json TEXT NOT NULL, decision_json TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS inputs_by_device ON engine_inputs(device_id, id);
                CREATE TABLE IF NOT EXISTS rejections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT, device_id TEXT,
                    reason TEXT NOT NULL, payload_json TEXT NOT NULL, received_at TEXT NOT NULL);
            """)
            wanted = json_text({"storage_version": 1, "algorithm_version": "starter-0.2.0",
                                "engine_config": asdict(config), "blockchain": outbox is not None})
            row = db.execute("SELECT value FROM settings WHERE key='configuration'").fetchone()
            if row is not None and row[0] != wanted:
                raise ValueError("saved configuration differs; use a separate state database for a new experiment")
            db.execute("INSERT OR IGNORE INTO settings VALUES ('configuration', ?)", (wanted,))

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA synchronous=FULL")
            with db:
                yield db
        finally:
            db.close()

    def restore(self):
        engine = TrustEngine(config=self.config)
        with self.connect() as db:
            registrations = db.execute("SELECT * FROM registrations ORDER BY rowid").fetchall()
            for row in registrations:
                seed = json.loads(row["seed_json"])
                if seed.get("last_timestamp"):
                    seed["last_timestamp"] = datetime.fromisoformat(seed["last_timestamp"])
                engine.register_device(**seed)
            for row in db.execute("SELECT * FROM engine_inputs ORDER BY id"):
                observation = json.loads(row["observation_json"])
                observation["timestamp"] = datetime.fromisoformat(observation["timestamp"])
                replayed = engine.evaluate(Observation(**observation)).to_dict()
                saved = json.loads(row["decision_json"])
                for decision in (saved, replayed):
                    decision.pop("latencyMs", None)
                    decision.pop("behaviorEvent", None)
                if saved != replayed:
                    raise ValueError("audit replay differs from the scoring algorithm; keep the database for review")
        engine.logger = self
        return engine

    def registration(self, device_id):
        with self.connect() as db:
            row = db.execute("SELECT * FROM registrations WHERE device_id=?", (device_id,)).fetchone()
        return dict(row) if row else None

    def register(self, seed, metadata):
        serial = dict(seed)
        if serial.get("last_timestamp"):
            serial["last_timestamp"] = serial["last_timestamp"].isoformat()
        with self.connect() as db:
            db.execute("INSERT INTO registrations VALUES (?, ?, ?)",
                       (seed["device_id"], json_text(serial), json_text(metadata)))

    def lookup(self, event_id):
        with self.connect() as db:
            row = db.execute("SELECT * FROM event_receipts WHERE event_id=?", (str(event_id),)).fetchone()
        return dict(row) if row else None

    def reject(self, payload, reason, now, status, *, save_receipt=True):
        response = {"event_id": payload["event_id"], "accepted": False,
                    "device_id": payload["device_id"], "reason": reason}
        with self.connect() as db:
            db.execute("INSERT INTO rejections (event_id, device_id, reason, payload_json, received_at) VALUES (?, ?, ?, ?, ?)",
                       (payload["event_id"], payload["device_id"], reason, json_text(payload), now.isoformat()))
            if save_receipt:
                db.execute("INSERT INTO event_receipts VALUES (?, ?, ?, ?, ?, ?)",
                           (payload["event_id"], fingerprint(payload), json_text(payload), status,
                            json_text(response), now.isoformat()))
        return response

    def evaluate(self, engine, observation, *, event=None, now=None):
        self.context = (observation, event, now or datetime.now(timezone.utc))
        try:
            engine.evaluate(observation)
        finally:
            self.context = None
        return self.history(observation.device_id, 1)[0]

    def append(self, decision):
        if self.context is None:
            raise RuntimeError("use EventStore.evaluate for durable API decisions")
        observation, event, now = self.context
        stored = dict(decision)
        if event is not None:
            stored["behaviorEvent"] = event
        obs = asdict(observation)
        obs["timestamp"] = observation.timestamp.isoformat()
        with self.connect() as db:
            db.execute("INSERT INTO engine_inputs (device_id, event_id, observation_json, decision_json) VALUES (?, ?, ?, ?)",
                       (observation.device_id, event["event_id"] if event else None, json_text(obs), json_text(stored)))
            if event is not None:
                response = {"event_id": event["event_id"], "accepted": True, "device_id": event["device_id"],
                            "reason": "trust_updated", "decision": stored}
                db.execute("INSERT INTO event_receipts VALUES (?, ?, ?, ?, ?, ?)",
                           (event["event_id"], fingerprint(event), json_text(event), 202,
                            json_text(response), now.isoformat()))
            if self.outbox:
                self.outbox.append(stored, connection=db)

    def history(self, device_id, limit):
        with self.connect() as db:
            rows = db.execute("SELECT decision_json FROM engine_inputs WHERE device_id=? ORDER BY id DESC LIMIT ?",
                              (device_id, limit)).fetchall()
        return [json.loads(row[0]) for row in reversed(rows)]
