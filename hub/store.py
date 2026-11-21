"""Transactional SQLite broker store.

Public worker adapter interface: ``claim(worker_id, lease_seconds)``,
``heartbeat(task_id, worker_id, lease_epoch, lease_seconds)``, and
``complete(task_id, worker_id, lease_epoch, result, error=None)``. A claim
returns a fencing epoch; every later worker write must present it. On process
restart, running work becomes ``interrupted`` and requires coordinator review.
The Store never launches workers or retries side effects.
Coordinator-created child tasks may link with ``parent_task_id``; the broker
inherits thread identity and enforces the configured hop bound. Workers report
results through ``complete`` and cannot autonomously dispatch peer tasks.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from contextlib import closing

from .security import redact


class HubError(Exception):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code, self.status = code, status


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


class Store:
    _workspace_guard = threading.RLock()
    _process_workspaces = set()
    _process_databases = set()
    def __init__(self, db_path: str | Path, *, max_depth=100, max_timeout=3600,
                 max_cost=100.0, cost_limit=500.0, rate_limit=30, rate_window=60, allowed_workspaces=None, max_hops=8):
        self.db_path = str(Path(db_path).expanduser().resolve())
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.max_depth, self.max_timeout = int(max_depth), int(max_timeout)
        self.max_hops = int(max_hops)
        self.max_cost, self.cost_limit = float(max_cost), float(cost_limit)
        self.rate_limit, self.rate_window = int(rate_limit), int(rate_window)
        roots = allowed_workspaces if allowed_workspaces is not None else [x for x in os.environ.get("HUB_ALLOWED_WORKSPACE_ROOTS", "").split(os.pathsep) if x]
        self.allowed_workspaces = [str(Path(x).expanduser().resolve()) for x in roots]
        self._lock = threading.RLock()
        self._workspace_locks = {}
        self._db_lock_handle = None
        self._acquire_db_lock()
        self._initialize()
        self.recover_after_restart()

    def _acquire_db_lock(self):
        with self._workspace_guard:
            if self.db_path in self._process_databases:
                raise HubError("broker_owned", "Database already has a broker writer", 409)
            self._process_databases.add(self.db_path)
        handle = open(self.db_path + ".writer.lock", "a+b")
        try:
            handle.seek(0, os.SEEK_END)
            if not handle.tell(): handle.write(b"\0"); handle.flush()
            handle.seek(0)
            if os.name == "nt":
                import msvcrt
                try: msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError: raise HubError("broker_owned", "Database already has a broker writer", 409)
            else:
                import fcntl
                try: fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError: raise HubError("broker_owned", "Database already has a broker writer", 409)
            self._db_lock_handle = handle
        except Exception:
            handle.close()
            with self._workspace_guard: self._process_databases.discard(self.db_path)
            raise

    def close(self):
        """Release process locks during orderly broker shutdown."""
        for workspace, handle in list(self._workspace_locks.items()):
            try:
                if os.name == "nt":
                    import msvcrt
                    handle.seek(0); msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            finally: handle.close()
            with self._workspace_guard: self._process_workspaces.discard(workspace)
        if self._db_lock_handle:
            handle = self._db_lock_handle
            try:
                if os.name == "nt":
                    import msvcrt
                    handle.seek(0); msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            finally: handle.close()
            with self._workspace_guard: self._process_databases.discard(self.db_path)
        self._workspace_locks.clear(); self._db_lock_handle = None

    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _tx(self):
        conn = self._connect()
        conn.execute("BEGIN IMMEDIATE")
        return conn

    def _initialize(self):
        with self._lock, closing(self._connect()) as c:
            c.executescript("""
                CREATE TABLE IF NOT EXISTS workspaces(
                    workspace TEXT PRIMARY KEY, db_path TEXT NOT NULL, created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS tasks(
                    id TEXT PRIMARY KEY, workspace TEXT NOT NULL, thread_id TEXT NOT NULL,
                    correlation_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, task_digest TEXT NOT NULL,
                    parent_task_id TEXT, depth INTEGER NOT NULL DEFAULT 0,
                    payload TEXT NOT NULL, action_class TEXT NOT NULL, state TEXT NOT NULL,
                    target_worker TEXT, cancellation_requested INTEGER NOT NULL DEFAULT 0,
                    created REAL NOT NULL, started_at REAL, updated REAL NOT NULL, timeout_seconds INTEGER NOT NULL,
                    cost_reserved REAL NOT NULL, reserved INTEGER NOT NULL DEFAULT 1,
                    approval_digest TEXT, approved_by TEXT, approval_note TEXT,
                    worker_id TEXT, lease_epoch INTEGER NOT NULL DEFAULT 0, lease_until REAL,
                    result TEXT, error TEXT, handover TEXT,
                    UNIQUE(workspace,idempotency_key));
                CREATE TABLE IF NOT EXISTS controls(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, task_id TEXT, at REAL NOT NULL,
                    actor TEXT NOT NULL, event TEXT NOT NULL, data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS rate_events(at REAL NOT NULL, principal TEXT NOT NULL);
                INSERT OR IGNORE INTO controls(key,value) VALUES('emergency_stop','0');
                INSERT OR IGNORE INTO controls(key,value) VALUES('reserved_cost','0');
            """)
            columns = {row["name"] for row in c.execute("PRAGMA table_info(tasks)")}
            if "priority" not in columns:
                c.execute("ALTER TABLE tasks ADD COLUMN priority INTEGER NOT NULL DEFAULT 0")
            if "depends_on" not in columns:
                c.execute("ALTER TABLE tasks ADD COLUMN depends_on TEXT NOT NULL DEFAULT '[]'")
            c.executescript("""
                CREATE INDEX IF NOT EXISTS task_claim_idx ON tasks(state,priority DESC,created);
                CREATE TABLE IF NOT EXISTS task_dependencies(
                    task_id TEXT NOT NULL REFERENCES tasks(id), dependency_id TEXT NOT NULL REFERENCES tasks(id),
                    PRIMARY KEY(task_id,dependency_id), CHECK(task_id != dependency_id));
                CREATE INDEX IF NOT EXISTS task_dependency_ref_idx ON task_dependencies(dependency_id);
                CREATE TABLE IF NOT EXISTS relay_deliveries(
                    source TEXT NOT NULL, delivery_id TEXT NOT NULL, payload_digest TEXT NOT NULL,
                    sender_id TEXT, task_id TEXT NOT NULL UNIQUE REFERENCES tasks(id), created REAL NOT NULL,
                    PRIMARY KEY(source,delivery_id));
                CREATE TABLE IF NOT EXISTS relay_outbox(
                    id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(id),
                    source TEXT NOT NULL, delivery_id TEXT NOT NULL, approval_digest TEXT NOT NULL,
                    payload TEXT NOT NULL, state TEXT NOT NULL, created REAL NOT NULL, updated REAL NOT NULL,
                    worker_id TEXT, lease_epoch INTEGER NOT NULL DEFAULT 0, lease_until REAL,
                    error TEXT, UNIQUE(source,delivery_id));
                CREATE TABLE IF NOT EXISTS drive_messages(
                    message_key TEXT PRIMARY KEY, message_id TEXT NOT NULL, source_agent TEXT NOT NULL,
                    destination_agent TEXT NOT NULL, kind TEXT NOT NULL, thread_id TEXT NOT NULL,
                    message_digest TEXT NOT NULL, payload TEXT NOT NULL, imported_at REAL NOT NULL,
                    state TEXT NOT NULL DEFAULT 'received', task_id TEXT UNIQUE REFERENCES tasks(id));
                CREATE INDEX IF NOT EXISTS drive_message_state_idx ON drive_messages(state,imported_at);
                CREATE TABLE IF NOT EXISTS drive_exports(
                    task_id TEXT PRIMARY KEY REFERENCES tasks(id), peer TEXT NOT NULL,
                    request_digest TEXT NOT NULL, request_json TEXT NOT NULL,
                    exported_at REAL NOT NULL, reply_digest TEXT, replied_at REAL);
                CREATE TABLE IF NOT EXISTS drive_sync_state(
                    id INTEGER PRIMARY KEY CHECK(id=1), last_sync REAL, imported INTEGER NOT NULL DEFAULT 0,
                    error TEXT, cursor_agent_b TEXT NOT NULL DEFAULT '',
                    cursor_agent_c TEXT NOT NULL DEFAULT '', has_more INTEGER NOT NULL DEFAULT 0);
                INSERT OR IGNORE INTO drive_sync_state(id) VALUES(1);
                CREATE INDEX IF NOT EXISTS relay_outbox_state_idx ON relay_outbox(state,created);
            """)
            outbox_columns={row["name"] for row in c.execute("PRAGMA table_info(relay_outbox)")}
            if "kind" not in outbox_columns:
                c.execute("ALTER TABLE relay_outbox ADD COLUMN kind TEXT NOT NULL DEFAULT 'result'")
            if "receipt" not in outbox_columns:
                c.execute("ALTER TABLE relay_outbox ADD COLUMN receipt TEXT")
            drive_sync_columns={row["name"] for row in c.execute("PRAGMA table_info(drive_sync_state)")}
            for column in ("cursor_agent_b","cursor_agent_c"):
                if column not in drive_sync_columns:
                    c.execute(f"ALTER TABLE drive_sync_state ADD COLUMN {column} TEXT NOT NULL DEFAULT ''")
            if "has_more" not in drive_sync_columns:
                c.execute("ALTER TABLE drive_sync_state ADD COLUMN has_more INTEGER NOT NULL DEFAULT 0")
            table_sql = c.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='relay_outbox'").fetchone()[0]
            if re.search(r"task_id\s+TEXT\s+NOT\s+NULL\s+UNIQUE", table_sql, re.I):
                # Migrate the original one-result-per-task table to hold bounded
                # lifecycle proposals as well as the terminal result proposal.
                c.execute("DROP INDEX IF EXISTS relay_outbox_state_idx")
                c.execute("ALTER TABLE relay_outbox RENAME TO relay_outbox_single")
                c.execute("""CREATE TABLE relay_outbox(
                    id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(id),
                    source TEXT NOT NULL, delivery_id TEXT NOT NULL, approval_digest TEXT NOT NULL,
                    payload TEXT NOT NULL, state TEXT NOT NULL, created REAL NOT NULL, updated REAL NOT NULL,
                    worker_id TEXT, lease_epoch INTEGER NOT NULL DEFAULT 0, lease_until REAL,
                    error TEXT, UNIQUE(source,delivery_id))""")
                c.execute("INSERT INTO relay_outbox SELECT * FROM relay_outbox_single")
                c.execute("DROP TABLE relay_outbox_single")
                c.execute("CREATE INDEX relay_outbox_state_idx ON relay_outbox(state,created)")

    def _event(self, c, task_id, actor, event, data=None):
        c.execute("INSERT INTO events(task_id,at,actor,event,data) VALUES(?,?,?,?,?)",
                  (task_id, time.time(), actor, event, canonical(redact(data or {}))))

    @staticmethod
    def _dict(row):
        if row is None: return None
        out = dict(row)
        for field in ("payload", "result", "error", "handover", "depends_on"):
            if out.get(field):
                out[field] = json.loads(out[field])
        return out

    def _view(self, c, row):
        task = self._dict(row)
        if task is None: return None
        dependency_ids = task.get("depends_on", [])
        if not dependency_ids:
            task["dependency_state"], task["blocked_by"], task["dependency_states"] = "ready", [], []
            return task
        marks = ",".join("?" for _ in dependency_ids)
        states = {r["id"]:r["state"] for r in c.execute(
            f"SELECT id,state FROM tasks WHERE id IN ({marks})", dependency_ids).fetchall()}
        dependency_states = [{"id":dep,"state":states.get(dep,"missing")} for dep in dependency_ids]
        blocked = [dep for dep in dependency_ids if states.get(dep) in (None,"failed","cancelled","interrupted")]
        task["dependency_states"] = dependency_states
        task["blocked_by"] = blocked
        task["dependency_state"] = "blocked" if blocked else ("ready" if all(states.get(dep)=="completed" for dep in dependency_ids) else "waiting")
        return task

    def _task(self, c, task_id):
        return c.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()

    def import_drive_message(self, message, kind, *, message_digest):
        """Persist a strictly validated Drive message as data, never as approval."""
        key=f"{message['from']}:{message['id']}:{kind}"
        encoded=canonical(redact(message)); now=time.time()
        c=self._tx()
        try:
            old=c.execute("SELECT * FROM drive_messages WHERE message_key=?",(key,)).fetchone()
            if old:
                if old["message_digest"] != message_digest or old["payload"] != encoded:
                    raise HubError("drive_message_conflict","Drive message ID was reused with changed content",409)
                c.commit(); return dict(old)
            c.execute("INSERT INTO drive_messages(message_key,message_id,source_agent,destination_agent,kind,thread_id,message_digest,payload,imported_at,state) VALUES(?,?,?,?,?,?,?,?,?,'received')",
                (key,message["id"],message["from"],message["to"],kind,message["thread"],message_digest,encoded,now))
            c.execute("UPDATE drive_sync_state SET last_sync=?,imported=imported+1,error=NULL WHERE id=1",(now,))
            c.commit(); return dict(c.execute("SELECT * FROM drive_messages WHERE message_key=?",(key,)).fetchone())
        except Exception: c.rollback(); raise
        finally: c.close()

    def list_drive_messages(self, *, state=None, limit=50, offset=0, thread_id=None):
        limit=max(1,min(int(limit),100)); offset=max(0,min(int(offset),1000000))
        with closing(self._connect()) as c:
            clauses=[]; params=[]
            if state:
                if state not in {"received","promoted","correlated"}: raise HubError("invalid_state","Unknown Drive message state")
                clauses.append("state=?"); params.append(state)
            if thread_id:
                clauses.append("thread_id=?"); params.append(thread_id)
            where=(" WHERE "+" AND ".join(clauses)) if clauses else ""
            rows=c.execute("SELECT * FROM drive_messages"+where+" ORDER BY imported_at DESC,message_key LIMIT ? OFFSET ?",(*params,limit,offset)).fetchall()
            return [self._drive_message_view(r) for r in rows]

    def drive_status(self):
        with closing(self._connect()) as c:
            sync=c.execute("SELECT * FROM drive_sync_state WHERE id=1").fetchone()
            counts=dict(c.execute("SELECT state,count(*) n FROM drive_messages GROUP BY state").fetchall())
            return {"polling":False,"last_sync":sync["last_sync"],"last_sync_imported":sync["imported"],
                    "last_sync_error":sync["error"],"message_counts":counts,
                    "continuation_required":bool(sync["has_more"])}

    def get_drive_cursor(self, peer):
        if peer not in {"agent-b","agent-c"}: raise HubError("invalid_peer","Drive peer is not allowlisted")
        column="cursor_"+peer.replace("-", "_")
        with closing(self._connect()) as c:
            return c.execute(f"SELECT {column} FROM drive_sync_state WHERE id=1").fetchone()[0]

    def set_drive_cursor(self, peer, cursor):
        if peer not in {"agent-b","agent-c"} or not isinstance(cursor,str) or len(cursor)>255:
            raise HubError("invalid_cursor","Drive continuation cursor is invalid")
        column="cursor_"+peer.replace("-", "_")
        c=self._tx()
        try:
            c.execute(f"UPDATE drive_sync_state SET {column}=? WHERE id=1",(cursor,))
            c.commit()
        except Exception: c.rollback(); raise
        finally: c.close()

    def finish_drive_sync(self, imported_count=0, error=None, *, has_more=False):
        c=self._tx()
        try:
            c.execute("UPDATE drive_sync_state SET last_sync=?,imported=?,error=?,has_more=? WHERE id=1",
                      (time.time(),int(imported_count),redact(error) if error else None,int(bool(has_more))))
            c.commit()
        except Exception: c.rollback(); raise
        finally: c.close()

    def get_drive_export(self, task_id):
        with closing(self._connect()) as c:
            row=c.execute("SELECT * FROM drive_exports WHERE task_id=?",(task_id,)).fetchone()
            if not row: return None
            out=dict(row); out["request_json"]=json.loads(out["request_json"]); return out

    @staticmethod
    def _drive_message_view(row):
        if not row: return None
        out=dict(row); out["payload"]=json.loads(out["payload"]); return out

    def get_drive_message(self, message_id):
        with closing(self._connect()) as c:
            rows=c.execute("SELECT * FROM drive_messages WHERE message_id=? ORDER BY imported_at",(message_id,)).fetchall()
            if len(rows)>1: raise HubError("drive_message_ambiguous","Multiple Drive messages share this ID; use its source and type",409)
            return self._drive_message_view(rows[0]) if rows else None

    def promote_drive_message(self, message_id, *, request_digest, workspace, target_worker,
                              cost_reserved, timeout_seconds=300, principal="coordinator"):
        message=self.get_drive_message(message_id)
        if not message: raise HubError("not_found","Drive message not found",404)
        if message["message_digest"] != request_digest: raise HubError("digest_mismatch","Drive message digest does not match",409)
        if message["kind"] != "task": raise HubError("invalid_message","Only task messages can be promoted",409)
        envelope=message["payload"]
        prior=None
        with closing(self._connect()) as c:
            row=c.execute("SELECT task_id FROM drive_messages WHERE message_key=?",(message["message_key"],)).fetchone()
            if row and row["task_id"]: return self.get_task(row["task_id"])
            prev=c.execute("SELECT task_id FROM drive_messages WHERE source_agent=? AND thread_id=? AND task_id IS NOT NULL ORDER BY imported_at DESC LIMIT 1",
                           (message["source_agent"],message["thread_id"])).fetchone()
            prior=prev["task_id"] if prev else None
        payload={"adapter":"agent-b" if target_worker.startswith("worker-") else "drive-peer",
                 "prompt":envelope["content"],"drive_message_id":message_id,
                 "drive_message_digest":message["message_digest"],"drive_source":message["source_agent"],
                 "drive_thread_id":message["thread_id"],"title":envelope["task"],
                 "limits":envelope["limits"]}
        task=self.dispatch(workspace=workspace,payload=payload,idempotency_key="drive-message:"+message["message_key"],
            thread_id=message["thread_id"] if prior is None else None,correlation_id=message_id,
            action_class="analysis",timeout_seconds=timeout_seconds,cost_reserved=cost_reserved,
            target_worker=target_worker,parent_task_id=prior,principal=principal)
        c=self._tx()
        try:
            current=c.execute("SELECT task_id FROM drive_messages WHERE message_key=?",(message["message_key"],)).fetchone()
            if current["task_id"] and current["task_id"] != task["id"]: raise HubError("drive_message_conflict","Drive message is linked to another task",409)
            c.execute("UPDATE drive_messages SET task_id=?,state='promoted' WHERE message_key=?",(task["id"],message["message_key"]))
            c.commit(); return self.get_task(task["id"])
        except Exception: c.rollback(); raise
        finally: c.close()

    def prepare_drive_export(self, task_id, peer, request_digest, request_json, *, principal="coordinator"):
        c=self._tx()
        try:
            row=self._task(c,task_id)
            if not row: raise HubError("not_found","Task not found",404)
            old=c.execute("SELECT * FROM drive_exports WHERE task_id=?",(task_id,)).fetchone()
            if old:
                if old["peer"]!=peer or old["request_digest"]!=request_digest or old["request_json"]!=request_json:
                    raise HubError("drive_export_conflict","Task already has a different immutable Drive export",409)
                c.commit(); return dict(old)
            if row["state"]!="queued" or row["approval_digest"]!=row["task_digest"] or row["target_worker"]!=f"drive:{peer}":
                raise HubError("invalid_state","Only approved queued tasks targeted to this peer can be exported",409)
            if c.execute("SELECT value FROM controls WHERE key='emergency_stop'").fetchone()[0] == "1":
                raise HubError("emergency_stop","Broker emergency stop blocks new peer exports",423)
            active=c.execute("SELECT id,state FROM tasks WHERE workspace=? AND state IN ('running','interrupted') AND id<>? LIMIT 1",
                             (row["workspace"],task_id)).fetchone()
            if active: raise HubError("workspace_busy","Workspace has active or interrupted work; peer export is blocked",409)
            if row["cancellation_requested"]:
                raise HubError("cancellation_requested","Cancelled task cannot be exported",409)
            if time.time() >= row["created"] + row["timeout_seconds"]:
                raise HubError("task_expired","Approved task exceeded its execution timeout before export",409)
            dependencies=c.execute("SELECT d.dependency_id,t.state FROM task_dependencies d LEFT JOIN tasks t ON t.id=d.dependency_id WHERE d.task_id=?",
                                   (task_id,)).fetchall()
            if any(dep["state"]!="completed" for dep in dependencies):
                raise HubError("dependencies_incomplete","Peer task dependencies must be completed before export",409)
            # Broker timeout includes scheduled peer pickup time; the envelope's
            # max_seconds limits peer execution only. Both remain independently
            # bounded (broker max_timeout <= 3600, protocol max_seconds <= 300).
            lease_seconds=int(row["timeout_seconds"])
            now=time.time(); epoch=row["lease_epoch"]+1; lease_until=now+max(1,lease_seconds)
            # Export consumes the canonical workspace slot. This is a fenced broker lease,
            # not evidence that the remote peer has picked up or started the task.
            c.execute("UPDATE tasks SET state='running',worker_id=?,lease_epoch=?,lease_until=?,started_at=?,updated=? WHERE id=? AND state='queued'",
                      (f"drive:{peer}",epoch,lease_until,now,now,task_id))
            c.execute("INSERT INTO drive_exports(task_id,peer,request_digest,request_json,exported_at) VALUES(?,?,?,?,?)",
                (task_id,peer,request_digest,request_json,time.time()))
            self._queue_relay_status(c,task_id,"drive_exported_waiting_for_peer")
            self._event(c,task_id,principal,"drive_export_prepared",{"peer":peer,"request_digest":request_digest})
            c.commit(); return dict(c.execute("SELECT * FROM drive_exports WHERE task_id=?",(task_id,)).fetchone())
        except Exception: c.rollback(); raise
        finally: c.close()

    def complete_external_drive_task(self, task_id, peer, request_digest, reply_digest, *, result, failed=False):
        c=self._tx()
        try:
            task=self._task(c,task_id); export=c.execute("SELECT * FROM drive_exports WHERE task_id=?",(task_id,)).fetchone()
            if not task or not export or export["peer"]!=peer or export["request_digest"]!=request_digest:
                raise HubError("drive_reply_unmatched","Drive reply does not match an exported task",409)
            if export["reply_digest"]:
                if export["reply_digest"]!=reply_digest: raise HubError("drive_reply_conflict","Task already has a different correlated reply",409)
                c.commit(); return self.get_task(task_id)
            if (task["state"]!="running" or task["worker_id"]!=f"drive:{peer}"
                    or (task["lease_until"] or 0)<time.time() or task["cancellation_requested"]
                    or task["target_worker"]!=f"drive:{peer}" or task["approval_digest"]!=task["task_digest"]):
                self._event(c,task_id,"drive:"+peer,"late_drive_reply_held",{"reply_digest":reply_digest,"state":task["state"]})
                c.commit(); raise HubError("drive_reply_late","Task is no longer awaiting an external peer result",409)
            state="failed" if failed else "completed"
            c.execute("UPDATE tasks SET state=?,result=?,updated=? WHERE id=?",
                      (state,canonical(redact(result)),time.time(),task_id))
            c.execute("UPDATE drive_exports SET reply_digest=?,replied_at=? WHERE task_id=?",(reply_digest,time.time(),task_id))
            self._release_reservation(c,task)
            c.execute("UPDATE drive_messages SET state='correlated' WHERE message_id=? AND source_agent=? AND kind='reply'",
                      (task_id,peer))
            self._event(c,task_id,"drive:"+peer,"external_result_received",{"state":state,"reply_digest":reply_digest})
            c.commit(); return self.get_task(task_id)
        except Exception: c.rollback(); raise
        finally: c.close()

    def _release_reservation(self, c, row):
        if row["reserved"]:
            current = float(c.execute("SELECT value FROM controls WHERE key='reserved_cost'").fetchone()[0])
            c.execute("UPDATE controls SET value=? WHERE key='reserved_cost'", (str(max(0.0, current-row["cost_reserved"])),))
            c.execute("UPDATE tasks SET reserved=0 WHERE id=?", (row["id"],))

    @staticmethod
    def relay_sources_allowed(source):
        allowed = {value.strip() for value in os.environ.get("HUB_RELAY_ALLOWED_SOURCES", "").split(",") if value.strip()}
        return bool(allowed) and source in allowed

    def get_relay_delivery(self, source, delivery_id):
        with closing(self._connect()) as c:
            row=c.execute("SELECT * FROM relay_deliveries WHERE source=? AND delivery_id=?",(source,delivery_id)).fetchone()
            return dict(row) if row else None

    def get_relay_task(self, source, task_id):
        with closing(self._connect()) as c:
            row=c.execute("SELECT t.* FROM tasks t JOIN relay_deliveries r ON r.task_id=t.id WHERE r.source=? AND t.id=?",(source,task_id)).fetchone()
            task=self._view(c,row)
            if task:
                task["relay_outbox"]=[self._outbox_view(item) for item in c.execute(
                    "SELECT * FROM relay_outbox WHERE task_id=? ORDER BY created DESC,id DESC LIMIT 20",(task_id,)).fetchall()]
            return task

    def _queue_relay_status(self, c, task_id, transition):
        row=c.execute("SELECT t.*,r.source,r.delivery_id AS source_delivery_id FROM tasks t "
                      "JOIN relay_deliveries r ON r.task_id=t.id WHERE t.id=?",(task_id,)).fetchone()
        if not row: return None
        # A newer state makes older unclaimed proposals stale. In-flight posts
        # remain fenced by their lease and require readback after ambiguity.
        older=c.execute("SELECT id FROM relay_outbox WHERE task_id=? AND kind='status' AND state IN ('awaiting_approval','ready')",
                        (task_id,)).fetchall()
        for item in older:
            c.execute("UPDATE relay_outbox SET state='superseded',updated=? WHERE id=?",(time.time(),item["id"]))
        task_payload=json.loads(row["payload"])
        snapshot=redact({"kind":"status","task_id":task_id,"task_digest":row["task_digest"],"source":row["source"],
            "source_delivery_id":row["source_delivery_id"],"relay_destination":task_payload.get("relay_destination"),
            "state":row["state"],"cancellation_requested":bool(row["cancellation_requested"]),
            "transition":transition,"result":json.loads(row["result"]) if row["result"] else None,
            "error":json.loads(row["error"]) if row["error"] else None})
        approval_digest=digest(snapshot); out_id=str(uuid.uuid4()); now=time.time()
        delivery_id=f"{row['source_delivery_id']}:status:{transition}:{now:.6f}"
        c.execute("INSERT INTO relay_outbox(id,task_id,source,delivery_id,approval_digest,payload,state,created,updated,kind) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (out_id,task_id,row["source"],delivery_id,approval_digest,canonical(snapshot),"awaiting_approval",now,now,"status"))
        self._event(c,task_id,"broker","relay_status_awaiting_approval",{"outbox_id":out_id,"approval_digest":approval_digest,"transition":transition})
        return out_id

    def register_workspace(self, workspace: str):
        resolved = str(Path(workspace).expanduser().resolve())
        if not self.allowed_workspaces or not any(os.path.commonpath([resolved, root]) == root for root in self.allowed_workspaces):
            raise HubError("workspace_not_allowed", "Workspace is outside configured allowed roots", 403)
        if not Path(resolved).is_dir():
            raise HubError("workspace_missing", "Workspace must be an existing isolated directory", 400)
        with self._workspace_guard:
            if resolved in self._process_workspaces and resolved not in self._workspace_locks:
                raise HubError("workspace_owned", "Workspace already has a broker writer", 409)
            if resolved not in self._workspace_locks:
                self._process_workspaces.add(resolved)
        if resolved not in self._workspace_locks:
            lock_path = Path(resolved) / ".local-agent-hub.writer.lock"
            handle = open(lock_path, "a+b")
            try:
                handle.seek(0, os.SEEK_END)
                if handle.tell() == 0:
                    handle.write(b"\0"); handle.flush()
                handle.seek(0)
                if os.name == "nt":
                    import msvcrt
                    try: msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    except OSError: raise HubError("workspace_owned", "Workspace already has a broker writer", 409)
                else:
                    import fcntl
                    try: fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except OSError: raise HubError("workspace_owned", "Workspace already has a broker writer", 409)
                self._workspace_locks[resolved] = handle
            except Exception:
                handle.close()
                with self._workspace_guard: self._process_workspaces.discard(resolved)
                raise
        c = self._tx()
        try:
            existing = c.execute("SELECT db_path FROM workspaces WHERE workspace=?", (resolved,)).fetchone()
            if existing and existing["db_path"] != self.db_path:
                raise HubError("workspace_owned", "Workspace already has a broker writer", 409)
            c.execute("INSERT OR IGNORE INTO workspaces VALUES(?,?,?)", (resolved, self.db_path, time.time()))
            c.commit()
            return resolved
        except Exception:
            c.rollback(); raise
        finally: c.close()

    def _rate(self, c, principal):
        now = time.time()
        c.execute("DELETE FROM rate_events WHERE at<?", (now-self.rate_window,))
        count = c.execute("SELECT count(*) FROM rate_events WHERE principal=?", (principal,)).fetchone()[0]
        if count >= self.rate_limit:
            raise HubError("rate_limited", "Request rate limit exceeded", 429)
        c.execute("INSERT INTO rate_events VALUES(?,?)", (now, principal))

    def rate_request(self, principal):
        c=self._tx()
        try:
            self._rate(c, principal); c.commit()
        except Exception: c.rollback(); raise
        finally: c.close()

    def dispatch(self, *, workspace, payload, idempotency_key, thread_id=None,
                 correlation_id=None, action_class="analysis", timeout_seconds=300,
                 cost_reserved=0.0, target_worker=None, parent_task_id=None, priority=0, depends_on=None,
                 relay_source=None, relay_delivery_id=None, relay_payload_digest=None, relay_sender_id=None,
                 principal="coordinator"):
        workspace = self.register_workspace(workspace)
        payload = redact(payload)
        timeout_seconds, cost_reserved = int(timeout_seconds), float(cost_reserved)
        if not idempotency_key or len(idempotency_key) > 200: raise HubError("invalid_idempotency", "A bounded idempotency key is required")
        if timeout_seconds < 1 or timeout_seconds > self.max_timeout: raise HubError("timeout_limit", "Timeout exceeds configured bound")
        if not math.isfinite(cost_reserved) or cost_reserved < 0 or cost_reserved > self.max_cost: raise HubError("cost_limit", "Cost reservation exceeds per-task bound")
        if isinstance(priority, bool) or not isinstance(priority, int) or not -100 <= priority <= 100:
            raise HubError("priority_limit", "Priority must be an integer from -100 through 100")
        depends_on = depends_on or []
        if not isinstance(depends_on, list) or len(depends_on) > 32 or any(not isinstance(item, str) or not item or len(item) > 100 for item in depends_on):
            raise HubError("dependency_limit", "At most 32 bounded task IDs may be dependencies")
        if len(set(depends_on)) != len(depends_on): raise HubError("dependency_duplicate", "A task dependency may appear only once")
        depends_on = sorted(depends_on)
        if relay_source is not None or relay_delivery_id is not None or relay_payload_digest is not None:
            if not all((relay_source, relay_delivery_id, relay_payload_digest)):
                raise HubError("relay_mapping_required", "Relay source, delivery ID, and payload digest are all required")
            if not all(isinstance(x,str) for x in (relay_source,relay_delivery_id,relay_payload_digest)) or len(relay_source) > 200 or len(relay_delivery_id) > 200 or not re.fullmatch(r"[a-fA-F0-9]{64}", relay_payload_digest):
                raise HubError("relay_mapping_invalid", "Relay mapping fields are invalid")
            relay_payload_digest = relay_payload_digest.lower()
        if relay_sender_id is not None and (not isinstance(relay_sender_id, str) or len(relay_sender_id) > 200):
            raise HubError("relay_sender_invalid", "Relay sender ID is invalid")
        c = self._tx()
        try:
            depth=0
            if parent_task_id:
                parent=c.execute("SELECT workspace,thread_id,depth FROM tasks WHERE id=?",(parent_task_id,)).fetchone()
                if not parent: raise HubError("parent_not_found","Parent task not found",404)
                if parent["workspace"] != workspace: raise HubError("lineage_workspace","Parent task belongs to another workspace",409)
                if thread_id is not None and thread_id != parent["thread_id"]:
                    raise HubError("lineage_thread","Child must inherit its parent thread ID",409)
                thread_id=parent["thread_id"]
                depth=parent["depth"]+1
                if depth > self.max_hops: raise HubError("hop_limit","Task lineage exceeds configured hop limit",429)
            dependency_rows = []
            for dependency_id in depends_on:
                dependency = c.execute("SELECT id,workspace FROM tasks WHERE id=?",(dependency_id,)).fetchone()
                if not dependency: raise HubError("dependency_not_found", f"Dependency {dependency_id} not found",404)
                if dependency["workspace"] != workspace:
                    raise HubError("dependency_workspace", "Dependencies must belong to the same workspace",409)
                dependency_rows.append(dependency)
            request = {"workspace":workspace,"payload":payload,"action_class":action_class,
                       "timeout_seconds":timeout_seconds,"cost_reserved":cost_reserved,"target_worker":target_worker,
                       "parent_task_id":parent_task_id,"depth":depth,"priority":priority,
                       "depends_on":depends_on,"relay_source":relay_source,
                       "relay_delivery_id":relay_delivery_id,"relay_payload_digest":relay_payload_digest,
                       "relay_sender_id":relay_sender_id}
            task_digest = digest(request)
            relay_old = None
            if relay_source:
                relay_old = c.execute("SELECT r.*,t.* FROM relay_deliveries r JOIN tasks t ON t.id=r.task_id WHERE r.source=? AND r.delivery_id=?",
                                      (relay_source,relay_delivery_id)).fetchone()
                if relay_old:
                    if relay_old["payload_digest"] != relay_payload_digest or relay_old["task_digest"] != task_digest:
                        raise HubError("relay_delivery_conflict", "Source delivery ID was reused with changed content",409)
                    if thread_id is not None and thread_id != relay_old["thread_id"]:
                        raise HubError("relay_delivery_conflict", "Source delivery replay supplied a different thread ID",409)
                    if correlation_id is not None and correlation_id != relay_old["correlation_id"]:
                        raise HubError("relay_delivery_conflict", "Source delivery replay supplied a different correlation ID",409)
                    c.commit(); return self._view(c,relay_old)
            old = c.execute("SELECT * FROM tasks WHERE workspace=? AND idempotency_key=?", (workspace,idempotency_key)).fetchone()
            if old:
                if old["task_digest"] != task_digest: raise HubError("idempotency_conflict", "Idempotency key was used with different task content", 409)
                if thread_id is not None and thread_id != old["thread_id"]:
                    raise HubError("idempotency_conflict", "Idempotency replay supplied a different thread ID", 409)
                if correlation_id is not None and correlation_id != old["correlation_id"]:
                    raise HubError("idempotency_conflict", "Idempotency replay supplied a different correlation ID", 409)
                c.commit(); return self._view(c,old)
            if not parent_task_id and thread_id and c.execute("SELECT 1 FROM tasks WHERE thread_id=? LIMIT 1",(thread_id,)).fetchone():
                raise HubError("parent_required","Continuing an existing thread requires a parent task ID",409)
            thread_id=thread_id or str(uuid.uuid4())
            if c.execute("SELECT value FROM controls WHERE key='emergency_stop'").fetchone()[0] == "1":
                raise HubError("emergency_stop", "Broker is stopped", 423)
            queue_count = c.execute("SELECT count(*) FROM tasks WHERE state IN ('awaiting_approval','queued','running')").fetchone()[0]
            if queue_count >= self.max_depth: raise HubError("queue_full", "Queue depth limit reached", 429)
            reserved = float(c.execute("SELECT value FROM controls WHERE key='reserved_cost'").fetchone()[0])
            if reserved + cost_reserved > self.cost_limit: raise HubError("cost_budget", "Cost reservation budget exhausted", 429)
            tid = str(uuid.uuid4()); now = time.time()
            c.execute("INSERT INTO tasks(id,workspace,thread_id,correlation_id,idempotency_key,task_digest,parent_task_id,depth,payload,action_class,state,target_worker,created,updated,timeout_seconds,cost_reserved,priority,depends_on) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                      (tid,workspace,thread_id,correlation_id or str(uuid.uuid4()),idempotency_key,task_digest,parent_task_id,depth,canonical(payload),action_class,"awaiting_approval",target_worker,now,now,timeout_seconds,cost_reserved,priority,canonical(depends_on)))
            for dependency in dependency_rows:
                c.execute("INSERT INTO task_dependencies(task_id,dependency_id) VALUES(?,?)",(tid,dependency["id"]))
            if relay_source:
                c.execute("INSERT INTO relay_deliveries(source,delivery_id,payload_digest,sender_id,task_id,created) VALUES(?,?,?,?,?,?)",
                          (relay_source,relay_delivery_id,relay_payload_digest.lower(),relay_sender_id,tid,now))
                self._queue_relay_status(c,tid,"awaiting_approval")
            c.execute("UPDATE controls SET value=? WHERE key='reserved_cost'", (str(reserved+cost_reserved),))
            self._event(c,tid,principal,"dispatched",{"digest":task_digest,"action_class":action_class})
            c.commit(); return self.get_task(tid)
        except Exception:
            c.rollback(); raise
        finally: c.close()

    def approve(self, task_id, *, task_digest, principal="coordinator", note=""):
        c=self._tx()
        try:
            row=self._task(c,task_id)
            if not row: raise HubError("not_found","Task not found",404)
            if row["task_digest"] != task_digest: raise HubError("digest_mismatch","Approval digest does not match immutable task",409)
            if row["state"] != "awaiting_approval": raise HubError("invalid_state","Task is not awaiting approval",409)
            c.execute("UPDATE tasks SET state='queued',approval_digest=?,approved_by=?,approval_note=?,updated=? WHERE id=?",
                      (task_digest,principal,redact(note),time.time(),task_id))
            self._queue_relay_status(c,task_id,"queued")
            self._event(c,task_id,principal,"approved",{"digest":task_digest,"note":note})
            c.commit(); return self.get_task(task_id)
        except Exception: c.rollback(); raise
        finally: c.close()

    def claim(self, worker_id, lease_seconds=60):
        c=self._tx()
        try:
            if c.execute("SELECT value FROM controls WHERE key='emergency_stop'").fetchone()[0] == "1":
                raise HubError("emergency_stop","Broker is stopped",423)
            expired=c.execute("SELECT * FROM tasks WHERE state='running' AND lease_until<?",(time.time(),)).fetchall()
            for old in expired:
                c.execute("UPDATE tasks SET state='interrupted',updated=?,lease_epoch=lease_epoch+1 WHERE id=?",
                          (time.time(),old["id"]))
                self._event(c,old["id"],"broker","expired_lease_needs_review",
                            {"previous_worker":old["worker_id"],"lease_epoch":old["lease_epoch"]+1})
            candidates=c.execute("""SELECT candidate.* FROM tasks candidate
                WHERE candidate.state='queued'
                  AND (candidate.target_worker IS NULL OR candidate.target_worker=?)
                  AND NOT EXISTS (
                    SELECT 1 FROM tasks active
                    WHERE active.workspace=candidate.workspace
                      AND active.state IN ('running','interrupted'))
                ORDER BY candidate.priority DESC,candidate.created ASC""",(worker_id,)).fetchall()
            row=None
            for candidate in candidates:
                dependencies=c.execute("SELECT d.dependency_id,t.state FROM task_dependencies d LEFT JOIN tasks t ON t.id=d.dependency_id WHERE d.task_id=?",
                                       (candidate["id"],)).fetchall()
                if all(dep["state"]=="completed" for dep in dependencies):
                    row=candidate; break
            if not row: c.commit(); return None
            epoch=row["lease_epoch"]+1; until=time.time()+max(5,min(int(lease_seconds),300))
            c.execute("UPDATE tasks SET state='running',worker_id=?,lease_epoch=?,lease_until=?,started_at=?,updated=? WHERE id=? AND state='queued'",
                      (worker_id,epoch,until,time.time(),time.time(),row["id"]))
            self._queue_relay_status(c,row["id"],"running")
            self._event(c,row["id"],worker_id,"claimed",{"lease_epoch":epoch})
            c.commit()
            out=self.get_task(row["id"]); out["lease_epoch"]=epoch; out["lease_until"]=until
            return out
        except Exception: c.rollback(); raise
        finally: c.close()

    def heartbeat(self, task_id, worker_id, lease_epoch, lease_seconds=60):
        c=self._tx()
        try:
            row=self._task(c,task_id)
            if not row: raise HubError("not_found","Task not found",404)
            if row["state"]!="running" or row["worker_id"]!=worker_id or row["lease_epoch"]!=lease_epoch or (row["lease_until"] or 0)<time.time():
                raise HubError("stale_lease","Worker lease is stale or fenced",409)
            if time.time() >= row["started_at"] + row["timeout_seconds"]:
                if not row["cancellation_requested"]:
                    c.execute("UPDATE tasks SET cancellation_requested=1,updated=? WHERE id=?",(time.time(),task_id))
                    self._queue_relay_status(c,task_id,"timeout_cancellation_requested")
                row=self._task(c,task_id)
            until=time.time()+max(5,min(int(lease_seconds),300))
            c.execute("UPDATE tasks SET lease_until=?,updated=? WHERE id=?",(until,time.time(),task_id))
            self._event(c,task_id,worker_id,"heartbeat",{"lease_epoch":lease_epoch,"cancellation_requested":bool(row["cancellation_requested"])})
            c.commit(); return {"task_id":task_id,"lease_until":until,"lease_epoch":lease_epoch,"cancellation_requested":bool(row["cancellation_requested"])}
        except Exception: c.rollback(); raise
        finally: c.close()

    def complete(self, task_id, worker_id, lease_epoch, result=None, error=None, cancelled=False):
        c=self._tx()
        try:
            row=self._task(c,task_id)
            if not row: raise HubError("not_found","Task not found",404)
            if row["state"]!="running" or row["worker_id"]!=worker_id or row["lease_epoch"]!=lease_epoch or (row["lease_until"] or 0)<time.time():
                raise HubError("stale_lease","Worker lease is stale or fenced",409)
            timed_out = time.time() >= row["started_at"] + row["timeout_seconds"]
            if (row["cancellation_requested"] or timed_out) and not cancelled:
                raise HubError("cancel_ack_required","Worker must confirm termination before cancellation completes",409)
            if cancelled and not (row["cancellation_requested"] or timed_out):
                raise HubError("unexpected_cancel_ack","No cancellation or timeout is pending",409)
            state="cancelled" if cancelled else ("failed" if error is not None else "completed")
            c.execute("UPDATE tasks SET state=?,result=?,error=?,updated=? WHERE id=?",
                      (state,canonical(redact(result)) if result is not None else None,canonical(redact(error)) if error is not None else None,time.time(),task_id))
            self._release_reservation(c,row)
            mapping=c.execute("SELECT source,delivery_id FROM relay_deliveries WHERE task_id=?",(task_id,)).fetchone()
            if mapping:
                task_payload=json.loads(row["payload"])
                out_payload=redact({"kind":"result","task_id":task_id,"task_digest":row["task_digest"],"source":mapping["source"],
                                    "source_delivery_id":mapping["delivery_id"],
                                    "relay_destination":task_payload.get("relay_destination"),
                                    "state":state,"result":result,"error":error})
                approval_digest=digest(out_payload); out_id=str(uuid.uuid4()); now=time.time()
                c.execute("INSERT INTO relay_outbox(id,task_id,source,delivery_id,approval_digest,payload,state,created,updated,kind) VALUES(?,?,?,?,?,?,?,?,?,?)",
                          (out_id,task_id,mapping["source"],mapping["delivery_id"],approval_digest,canonical(out_payload),"awaiting_approval",now,now,"result"))
                self._event(c,task_id,"broker","relay_outbox_awaiting_approval",{"outbox_id":out_id,"approval_digest":approval_digest})
            self._event(c,task_id,worker_id,state,{"result":result,"error":error,"cancelled":cancelled})
            c.commit(); return self.get_task(task_id)
        except Exception: c.rollback(); raise
        finally: c.close()

    def recover_after_restart(self):
        c=self._tx()
        try:
            rows=c.execute("SELECT * FROM tasks WHERE state='running'").fetchall()
            for row in rows:
                if self._preserve_external_drive_lease(c, row, time.time()):
                    # A Drive export has no local child process to interrupt.
                    # Keep its original fencing epoch and deadline so a later
                    # correlated reply can be imported, without re-exporting.
                    continue
                c.execute("UPDATE tasks SET state='interrupted',updated=?,lease_epoch=lease_epoch+1 WHERE id=?",(time.time(),row["id"]))
                self._event(c,row["id"],"broker","interrupted_needs_review",{"previous_worker":row["worker_id"],"lease_epoch":row["lease_epoch"]+1})
                self._queue_relay_status(c,row["id"],"interrupted")
            outbox=c.execute("SELECT * FROM relay_outbox WHERE state='running'").fetchall()
            for item in outbox:
                c.execute("UPDATE relay_outbox SET state='interrupted',updated=?,lease_epoch=lease_epoch+1,error=? WHERE id=?",
                          (time.time(),"Broker restarted during relay delivery; review required",item["id"]))
                self._event(c,item["task_id"],"broker","relay_delivery_interrupted",{"outbox_id":item["id"],"lease_epoch":item["lease_epoch"]+1})
            c.commit(); return len(rows)
        except Exception: c.rollback(); raise
        finally: c.close()

    @staticmethod
    def _preserve_external_drive_lease(c, row, now):
        """Return true only for an intact, live, approved Drive peer lease."""
        worker = row["worker_id"] or ""
        if (not worker.startswith("drive:") or worker not in {"drive:agent-b", "drive:agent-c"}
                or row["target_worker"] != worker or row["cancellation_requested"]
                or row["approval_digest"] != row["task_digest"]
                or not row["started_at"] or not row["lease_until"]
                or row["lease_until"] <= now or row["started_at"] + row["timeout_seconds"] <= now
                or c.execute("SELECT value FROM controls WHERE key='emergency_stop'").fetchone()[0] == "1"):
            return False
        export = c.execute("SELECT * FROM drive_exports WHERE task_id=?", (row["id"],)).fetchone()
        if not export or export["peer"] != worker.split(":", 1)[1]:
            return False
        try:
            envelope = json.loads(export["request_json"])
            if (canonical(envelope) != export["request_json"] or envelope.get("schema_version") != 1
                    or envelope.get("id") != row["id"] or envelope.get("thread") != row["thread_id"]
                    or envelope.get("from") != "agent-a" or envelope.get("to") != export["peer"]
                    or envelope.get("request_digest") != export["request_digest"]):
                return False
            unsigned = {key: value for key, value in envelope.items() if key != "request_digest"}
            actual = hashlib.sha256(canonical(unsigned).encode("utf-8")).hexdigest()
            return actual == export["request_digest"]
        except (TypeError, ValueError, json.JSONDecodeError):
            return False

    def recover_expired_leases(self):
        """Fence expired work into review state; never put it back on the queue."""
        c=self._tx()
        try:
            rows=c.execute("SELECT * FROM tasks WHERE state='running' AND lease_until<?",(time.time(),)).fetchall()
            for row in rows:
                c.execute("UPDATE tasks SET state='interrupted',updated=?,lease_epoch=lease_epoch+1 WHERE id=?",
                          (time.time(),row["id"]))
                self._event(c,row["id"],"broker","expired_lease_needs_review",
                            {"previous_worker":row["worker_id"],"lease_epoch":row["lease_epoch"]+1})
                self._queue_relay_status(c,row["id"],"interrupted")
            outbox=c.execute("SELECT * FROM relay_outbox WHERE state='running' AND lease_until<?",(time.time(),)).fetchall()
            for item in outbox:
                c.execute("UPDATE relay_outbox SET state='interrupted',updated=?,lease_epoch=lease_epoch+1,error=? WHERE id=?",
                          (time.time(),"Relay lease expired; review required",item["id"]))
                self._event(c,item["task_id"],"broker","relay_lease_interrupted",{"outbox_id":item["id"],"lease_epoch":item["lease_epoch"]+1})
            c.commit(); return len(rows)
        except Exception: c.rollback(); raise
        finally: c.close()

    def get_task(self, task_id):
        with closing(self._connect()) as c: return self._view(c,c.execute("SELECT * FROM tasks WHERE id=?",(task_id,)).fetchone())

    def status(self):
        with closing(self._connect()) as c:
            return {"counts":dict(c.execute("SELECT state,count(*) n FROM tasks GROUP BY state").fetchall()),
                    "emergency_stop":c.execute("SELECT value FROM controls WHERE key='emergency_stop'").fetchone()[0]=="1",
                    "reserved_cost":float(c.execute("SELECT value FROM controls WHERE key='reserved_cost'").fetchone()[0]),
                    "drive":self.drive_status()}

    def inbox(self, workspace=None, limit=50, states=None, offset=0):
        limit=max(1,min(int(limit),200))
        offset=max(0,min(int(offset),1000000))
        valid_states={"awaiting_approval","queued","running","interrupted","completed","failed","cancelled"}
        if states is not None:
            if not isinstance(states,(list,tuple,set)) or not states or any(s not in valid_states for s in states):
                raise HubError("invalid_states","Inbox states must be a non-empty list of known task states")
            states=list(dict.fromkeys(states))
        with closing(self._connect()) as c:
            clauses=[]; params=[]
            if workspace:
                w=str(Path(workspace).expanduser().resolve())
                clauses.append("workspace=?"); params.append(w)
            if states is not None:
                clauses.append("state IN ("+",".join("?" for _ in states)+")"); params.extend(states)
            where=(" WHERE "+" AND ".join(clauses)) if clauses else ""
            rows=c.execute("SELECT * FROM tasks"+where+" ORDER BY created DESC,id LIMIT ? OFFSET ?",(*params,limit,offset)).fetchall()
            return [self._view(c,row) for row in rows]

    def thread(self, thread_id):
        with closing(self._connect()) as c:
            return [self._view(c,r) for r in c.execute("SELECT * FROM tasks WHERE thread_id=? ORDER BY created",(thread_id,)).fetchall()]

    def logs(self, task_id, limit=200):
        limit=max(1,min(int(limit),500))
        with closing(self._connect()) as c:
            rows=c.execute("SELECT id,task_id,at,actor,event,data FROM events WHERE task_id=? ORDER BY id LIMIT ?",(task_id,limit)).fetchall()
            return [{**dict(row),"data":json.loads(row["data"])} for row in rows]

    @staticmethod
    def _outbox_view(row):
        if not row: return None
        out=dict(row); out["payload"]=json.loads(out["payload"])
        if out.get("error"):
            try: out["error"]=json.loads(out["error"])
            except (TypeError,json.JSONDecodeError): pass
        if out.get("receipt"):
            try: out["receipt"]=json.loads(out["receipt"])
            except (TypeError,json.JSONDecodeError): pass
        return out

    def list_outbox(self, limit=50, state=None):
        limit=max(1,min(int(limit),200))
        with closing(self._connect()) as c:
            if state:
                rows=c.execute("SELECT * FROM relay_outbox WHERE state=? ORDER BY created LIMIT ?",(state,limit)).fetchall()
            else:
                rows=c.execute("SELECT * FROM relay_outbox ORDER BY created DESC LIMIT ?",(limit,)).fetchall()
            return [self._outbox_view(row) for row in rows]

    def approve_outbox(self, outbox_id, approval_digest, *, principal="coordinator", note=""):
        c=self._tx()
        try:
            row=c.execute("SELECT * FROM relay_outbox WHERE id=?",(outbox_id,)).fetchone()
            if not row: raise HubError("not_found","Relay outbox item not found",404)
            if row["approval_digest"] != approval_digest: raise HubError("digest_mismatch","Relay approval digest does not match immutable result",409)
            if row["state"] != "awaiting_approval": raise HubError("invalid_state","Relay outbox item is not awaiting approval",409)
            c.execute("UPDATE relay_outbox SET state='ready',updated=? WHERE id=?",(time.time(),outbox_id))
            self._event(c,row["task_id"],principal,"relay_result_approved",{"outbox_id":outbox_id,"approval_digest":approval_digest,"note":note})
            c.commit(); return self.get_outbox(outbox_id)
        except Exception: c.rollback(); raise
        finally: c.close()

    def get_outbox(self, outbox_id):
        with closing(self._connect()) as c:
            return self._outbox_view(c.execute("SELECT * FROM relay_outbox WHERE id=?",(outbox_id,)).fetchone())

    def claim_outbox(self, worker_id, lease_seconds=60):
        c=self._tx()
        try:
            if c.execute("SELECT value FROM controls WHERE key='emergency_stop'").fetchone()[0] == "1":
                raise HubError("emergency_stop","Broker is stopped",423)
            sources=sorted({value.strip() for value in os.environ.get("HUB_RELAY_ALLOWED_SOURCES","").split(",") if value.strip()})
            if not sources: raise HubError("relay_source_forbidden","No relay sources are allowlisted",403)
            row=c.execute("SELECT * FROM relay_outbox WHERE state='ready' AND source IN ("+",".join("?" for _ in sources)+") ORDER BY created LIMIT 1",sources).fetchone()
            if not row: c.commit(); return None
            epoch=row["lease_epoch"]+1; until=time.time()+max(5,min(int(lease_seconds),300)); now=time.time()
            c.execute("UPDATE relay_outbox SET state='running',worker_id=?,lease_epoch=?,lease_until=?,updated=? WHERE id=? AND state='ready'",
                      (worker_id,epoch,until,now,row["id"]))
            self._event(c,row["task_id"],worker_id,"relay_delivery_claimed",{"outbox_id":row["id"],"lease_epoch":epoch})
            c.commit(); out=self.get_outbox(row["id"]); out["lease_epoch"]=epoch; out["lease_until"]=until; return out
        except Exception: c.rollback(); raise
        finally: c.close()

    def resolve_relay_outbox_id(self, reference):
        if not isinstance(reference,str) or not reference: raise HubError("invalid_outbox_reference","Outbox reference is invalid")
        sources=sorted({value.strip() for value in os.environ.get("HUB_RELAY_ALLOWED_SOURCES","").split(",") if value.strip()})
        if not sources: raise HubError("relay_source_forbidden","No relay sources are allowlisted",403)
        with closing(self._connect()) as c:
            rows=c.execute("SELECT id FROM relay_outbox WHERE (id=? OR delivery_id=?) AND source IN ("+",".join("?" for _ in sources)+")",[reference,reference,*sources]).fetchall()
        if not rows: raise HubError("not_found","Relay outbox item not found",404)
        if len(rows)>1: raise HubError("ambiguous_outbox_reference","Use the outbox UUID for a non-unique delivery reference",409)
        return rows[0]["id"]

    def heartbeat_outbox(self, outbox_id, worker_id, lease_epoch, lease_seconds=60):
        c=self._tx()
        try:
            if c.execute("SELECT value FROM controls WHERE key='emergency_stop'").fetchone()[0] == "1":
                raise HubError("emergency_stop","Broker is stopped",423)
            row=c.execute("SELECT * FROM relay_outbox WHERE id=?",(outbox_id,)).fetchone()
            if not row: raise HubError("not_found","Relay outbox item not found",404)
            if row["source"] not in {value.strip() for value in os.environ.get("HUB_RELAY_ALLOWED_SOURCES","").split(",") if value.strip()}:
                raise HubError("relay_source_forbidden","Relay source is not allowlisted",403)
            if row["state"]!="running" or row["worker_id"]!=worker_id or row["lease_epoch"]!=lease_epoch or (row["lease_until"] or 0)<time.time():
                raise HubError("stale_lease","Relay delivery lease is stale or fenced",409)
            until=time.time()+max(5,min(int(lease_seconds),300))
            c.execute("UPDATE relay_outbox SET lease_until=?,updated=? WHERE id=?",(until,time.time(),outbox_id))
            self._event(c,row["task_id"],worker_id,"relay_delivery_heartbeat",{"outbox_id":outbox_id,"lease_epoch":lease_epoch})
            c.commit(); return {"delivery_id":row["delivery_id"],"lease_epoch":lease_epoch,"lease_until":until,"allowed":True}
        except Exception: c.rollback(); raise
        finally: c.close()

    @staticmethod
    def _validate_delivery_receipt(receipt):
        expected={"comment_id","comment_node_id","comment_url","body_sha256","verification"}
        if not isinstance(receipt,dict) or set(receipt)!=expected:
            raise HubError("delivery_receipt_required","A complete verified GitHub comment receipt is required")
        comment_id=receipt["comment_id"]
        node_id=receipt["comment_node_id"]
        comment_url=receipt["comment_url"]
        body_hash=receipt["body_sha256"]
        if isinstance(comment_id,bool) or not isinstance(comment_id,int) or comment_id<1:
            raise HubError("delivery_receipt_invalid","Comment ID must be a positive integer")
        if not isinstance(node_id,str) or not node_id or len(node_id)>200:
            raise HubError("delivery_receipt_invalid","Comment node ID is invalid")
        if not isinstance(comment_url,str) or len(comment_url)>500:
            raise HubError("delivery_receipt_invalid","Comment URL is invalid")
        match=re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/issues/[1-9][0-9]*#issuecomment-([1-9][0-9]*)",comment_url)
        if not match or int(match.group(1))!=comment_id:
            raise HubError("delivery_receipt_invalid","Comment URL must be a GitHub issue comment URL matching comment_id")
        if not isinstance(body_hash,str) or not re.fullmatch(r"[a-fA-F0-9]{64}",body_hash):
            raise HubError("delivery_receipt_invalid","Comment body hash must be SHA-256")
        if receipt["verification"]!="github_graphql_readback":
            raise HubError("delivery_receipt_invalid","GitHub GraphQL readback verification is required")
        return redact({**receipt,"body_sha256":body_hash.lower()})

    def complete_outbox(self, outbox_id, worker_id, lease_epoch, *, delivered, error=None, receipt=None):
        verified_receipt=self._validate_delivery_receipt(receipt) if delivered else None
        if not delivered and receipt is not None:
            raise HubError("delivery_receipt_invalid","A receipt may accompany only a verified delivered acknowledgment")
        c=self._tx()
        try:
            row=c.execute("SELECT * FROM relay_outbox WHERE id=?",(outbox_id,)).fetchone()
            if not row: raise HubError("not_found","Relay outbox item not found",404)
            if row["state"]!="running" or row["worker_id"]!=worker_id or row["lease_epoch"]!=lease_epoch or (row["lease_until"] or 0)<time.time():
                raise HubError("stale_lease","Relay delivery lease is stale or fenced",409)
            state="delivered" if delivered else "failed"
            safe_error=redact(error) if error is not None else None
            c.execute("UPDATE relay_outbox SET state=?,error=?,receipt=?,updated=? WHERE id=?",
                      (state,canonical(safe_error) if safe_error is not None else None,
                       canonical(verified_receipt) if verified_receipt is not None else None,time.time(),outbox_id))
            self._event(c,row["task_id"],worker_id,"relay_"+state,
                        {"outbox_id":outbox_id,"error":safe_error,"receipt":verified_receipt})
            c.commit(); return self.get_outbox(outbox_id)
        except Exception: c.rollback(); raise
        finally: c.close()

    def reconcile_interrupted(self, task_id, *, task_digest, process_termination_confirmed,
                              evidence_note, principal="coordinator"):
        """Resolve an interrupted task as cancelled after explicit human attestation.

        This never records completion or retries execution. The evidence is an
        operator statement, not independently verified process/native receipt.
        """
        if process_termination_confirmed is not True:
            raise HubError("termination_confirmation_required","Explicit process termination confirmation is required")
        if not isinstance(evidence_note,str) or not evidence_note.strip() or len(evidence_note)>2000:
            raise HubError("evidence_required","A bounded non-empty evidence note is required")
        c=self._tx()
        try:
            row=self._task(c,task_id)
            if not row: raise HubError("not_found","Task not found",404)
            if row["task_digest"] != task_digest: raise HubError("digest_mismatch","Task digest does not match immutable task",409)
            if row["state"] != "interrupted": raise HubError("invalid_state","Only interrupted tasks can be reconciled",409)
            safe_note=redact(evidence_note.strip())
            now=time.time()
            c.execute("UPDATE tasks SET state='cancelled',error=?,updated=?,lease_epoch=lease_epoch+1,lease_until=NULL WHERE id=?",
                      (canonical({"reconciliation":"cancelled_after_operator_confirmation","evidence_note":safe_note}),now,task_id))
            self._release_reservation(c,row)
            self._event(c,task_id,principal,"reconciled_cancelled_after_user_confirmation",
                {"task_digest":task_digest,"process_termination_confirmed":True,"evidence_note":safe_note,
                 "note":"Operator attestation is recorded; process termination and native receipt were not independently verified."})
            self._queue_relay_status(c,task_id,"reconciled_cancelled")
            c.commit(); return self.get_task(task_id)
        except Exception: c.rollback(); raise
        finally: c.close()

    def abandon_interrupted_outbox(self, outbox_id, *, approval_digest, publication_checked,
                                   evidence_note, principal="coordinator"):
        """Close an ambiguous publication as unknown; never mark delivered or retry."""
        if publication_checked is not True:
            raise HubError("publication_check_required","Explicit publication readback confirmation is required")
        if not isinstance(evidence_note,str) or not evidence_note.strip() or len(evidence_note)>2000:
            raise HubError("evidence_required","A bounded non-empty evidence note is required")
        c=self._tx()
        try:
            row=c.execute("SELECT * FROM relay_outbox WHERE id=?",(outbox_id,)).fetchone()
            if not row: raise HubError("not_found","Relay outbox item not found",404)
            if row["approval_digest"] != approval_digest:
                raise HubError("digest_mismatch","Outbox approval digest does not match immutable payload",409)
            if row["state"] != "interrupted":
                raise HubError("invalid_state","Only interrupted outbox items can be abandoned",409)
            safe_note=redact(evidence_note.strip())
            evidence={"outcome":"unknown","publication_checked":True,"evidence_note":safe_note,
                      "note":"Readback confirmation is an operator attestation; delivery was not independently verified."}
            c.execute("UPDATE relay_outbox SET state='abandoned',updated=?,lease_epoch=lease_epoch+1,lease_until=NULL,worker_id=NULL,error=? WHERE id=?",
                      (time.time(),canonical(evidence),outbox_id))
            self._event(c,row["task_id"],principal,"relay_delivery_abandoned_after_operator_readback",
                {"outbox_id":outbox_id,"approval_digest":approval_digest,**evidence})
            c.commit(); return self.get_outbox(outbox_id)
        except Exception: c.rollback(); raise
        finally: c.close()

    def request_relay_cancel(self, task_id, *, source, sender_id, reason=""):
        allowed={value.strip() for value in os.environ.get("HUB_RELAY_ALLOWED_CANCEL_SENDERS","").split(",") if value.strip()}
        if not allowed or sender_id not in allowed:
            raise HubError("relay_cancel_forbidden","Relay cancellation sender is not allowlisted",403)
        c=self._tx()
        try:
            row=c.execute("SELECT t.* FROM tasks t JOIN relay_deliveries r ON r.task_id=t.id WHERE t.id=? AND r.source=? AND r.sender_id=?",
                          (task_id,source,sender_id)).fetchone()
            if not row: raise HubError("not_found","Mapped relay task not found for this sender",404)
            if row["state"] in ("awaiting_approval","queued"):
                c.execute("UPDATE tasks SET state='cancelled',error=?,updated=?,lease_epoch=lease_epoch+1 WHERE id=?",
                          (canonical({"reason":redact(reason)}),time.time(),task_id))
                self._release_reservation(c,row); self._event(c,task_id,"relay","relay_cancelled",{"sender_id":sender_id,"reason":reason})
                self._queue_relay_status(c,task_id,"cancelled")
            elif row["state"] == "running":
                c.execute("UPDATE tasks SET cancellation_requested=1,updated=? WHERE id=?",(time.time(),task_id))
                self._event(c,task_id,"relay","relay_cancellation_requested",{"sender_id":sender_id,"reason":reason})
                self._queue_relay_status(c,task_id,"cancellation_requested")
            else:
                raise HubError("cancel_review_required","Interrupted or terminal work needs coordinator review",409)
            c.commit(); return self.get_task(task_id)
        except Exception: c.rollback(); raise
        finally: c.close()

    def cancel(self, task_id, principal="coordinator", reason=""):
        c=self._tx()
        try:
            row=self._task(c,task_id)
            if not row: raise HubError("not_found","Task not found",404)
            if row["state"] in ("awaiting_approval","queued"):
                c.execute("UPDATE tasks SET state='cancelled',error=?,updated=?,lease_epoch=lease_epoch+1 WHERE id=?",
                          (canonical({"reason":redact(reason)}),time.time(),task_id))
                self._release_reservation(c,row); self._event(c,task_id,principal,"cancelled",{"reason":reason})
                self._queue_relay_status(c,task_id,"cancelled")
            elif row["state"] == "running":
                c.execute("UPDATE tasks SET cancellation_requested=1,updated=? WHERE id=?",(time.time(),task_id))
                self._event(c,task_id,principal,"cancellation_requested",{"reason":reason})
                self._queue_relay_status(c,task_id,"cancellation_requested")
            else:
                raise HubError("cancel_review_required","Interrupted or terminal work needs coordinator review",409)
            c.commit(); return self.get_task(task_id)
        except Exception: c.rollback(); raise
        finally: c.close()

    def handover(self, task_id, handover, principal="coordinator"):
        c=self._tx()
        try:
            row=self._task(c,task_id)
            if not row: raise HubError("not_found","Task not found",404)
            c.execute("UPDATE tasks SET handover=?,updated=? WHERE id=?",(canonical(redact(handover)),time.time(),task_id))
            self._event(c,task_id,principal,"handover",handover); c.commit(); return self.get_task(task_id)
        except Exception: c.rollback(); raise
        finally: c.close()

    def emergency_stop(self, stopped, principal="coordinator"):
        c=self._tx()
        try:
            c.execute("UPDATE controls SET value=? WHERE key='emergency_stop'",("1" if stopped else "0",))
            self._event(c,None,principal,"emergency_stop",{"stopped":bool(stopped)})
            if stopped:
                rows=c.execute("SELECT * FROM tasks WHERE state IN ('queued','awaiting_approval')").fetchall()
                for row in rows:
                    c.execute("UPDATE tasks SET state='cancelled',updated=?,lease_epoch=lease_epoch+1 WHERE id=?",(time.time(),row["id"]))
                    self._release_reservation(c,row)
                    self._queue_relay_status(c,row["id"],"cancelled")
                running=c.execute("SELECT id FROM tasks WHERE state='running'").fetchall()
                for row in running:
                    c.execute("UPDATE tasks SET cancellation_requested=1,updated=? WHERE id=?",(time.time(),row["id"]))
                    self._event(c,row["id"],principal,"emergency_cancellation_requested")
                    self._queue_relay_status(c,row["id"],"cancellation_requested")
            c.commit(); return self.status()
        except Exception: c.rollback(); raise
        finally: c.close()
