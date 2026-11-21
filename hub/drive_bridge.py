"""Single-host Drive-folder queue adapter. Sync folders are not distributed locks.

Files are untrusted requests. This module executes only a task whose exact id and
digest were separately approved by the local operator. It never treats a Drive
file as approval, command, path, or tool instruction.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

MAX_TASK_BYTES = 64 * 1024
MAX_REPLY_BYTES = 256 * 1024
ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
MAX_SECONDS = 300
MAX_OUTPUT_CHARS = 6000
THREAD_RE = re.compile(r"^[A-Za-z0-9._:-]+$")


class BridgeError(ValueError):
    pass


def canonical(obj: object) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def request_digest(task: dict) -> str:
    unsigned = {k: v for k, v in task.items() if k != "request_digest"}
    return hashlib.sha256(canonical(unsigned)).hexdigest()


def _no_reparse(path: Path) -> None:
    # Resolve every existing component and reject Windows reparse points/symlinks.
    cur = Path(path.anchor)
    for part in path.parts[1:]:
        cur = cur / part
        if not cur.exists():
            continue
        if cur.is_symlink() or (getattr(cur.lstat(), "st_file_attributes", 0) & 0x400):
            raise BridgeError("reparse point or symlink is not allowed")


def _read_stable(path: Path) -> bytes:
    _no_reparse(path)
    if not path.is_file() or path.stat().st_size > MAX_TASK_BYTES:
        raise BridgeError("task file missing or exceeds size limit")
    first = path.read_bytes()
    time.sleep(0.20)
    second = path.read_bytes()
    if first != second:
        raise BridgeError("task file is still changing")
    return second


def validate_task(raw: bytes, *, expected_id: str | None = None) -> dict:
    if len(raw) > MAX_TASK_BYTES:
        raise BridgeError("task exceeds size limit")
    try:
        task = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise BridgeError("task is not valid UTF-8 JSON") from None
    keys = {"schema_version", "id", "thread", "from", "to", "task", "content",
            "created_at", "limits", "request_digest"}
    if not isinstance(task, dict) or set(task) != keys:
        raise BridgeError("task has unknown or missing fields")
    if task["schema_version"] != 1 or not isinstance(task["id"], str) or not ID_RE.fullmatch(task["id"]):
        raise BridgeError("unsupported schema or invalid task id")
    if expected_id and task["id"].lower() != expected_id.lower():
        raise BridgeError("filename and task id do not match")
    if task["to"] != "agent-b" or task["from"] not in ("agent-a", "agent-c"):
        raise BridgeError("task recipient or sender is not allowed")
    for key, limit in (("thread", 128), ("task", 160), ("content", 12000)):
        if not isinstance(task[key], str) or not task[key].strip() or len(task[key]) > limit:
            raise BridgeError(f"invalid {key}")
    if not THREAD_RE.fullmatch(task["thread"]):
        raise BridgeError("invalid thread")
    try:
        stamp = datetime.fromisoformat(task["created_at"].replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            raise ValueError
    except (ValueError, AttributeError):
        raise BridgeError("created_at must include a timezone") from None
    limits = task["limits"]
    if (not isinstance(limits, dict) or set(limits) != {"max_seconds", "max_output_chars"}
            or type(limits["max_seconds"]) is not int or not 1 <= limits["max_seconds"] <= MAX_SECONDS
            or type(limits["max_output_chars"]) is not int or not 1 <= limits["max_output_chars"] <= MAX_OUTPUT_CHARS):
        raise BridgeError("limits outside local bounds")
    digest = task["request_digest"]
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) or digest != request_digest(task):
        raise BridgeError("request digest mismatch")
    return task


def _extract_text(stdout: bytes) -> str:
    # Agent B --format json emits JSON event lines; retain only assistant text.
    text_parts: list[str] = []
    for line in stdout.decode("utf-8", errors="replace").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        part = event.get("part") or {}
        if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
            text_parts.append(part["text"])
        elif event.get("type") in ("text", "message") and isinstance(event.get("text"), str):
            text_parts.append(event["text"])
    return "\n".join(text_parts).strip()


def _atomic_new(path: Path, data: bytes) -> None:
    if path.exists():
        raise BridgeError("immutable reply already exists")
    tmp = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with tmp.open("xb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        # Atomic replacement is local-filesystem behavior only; Drive sync is not a distributed lock.
        if path.exists():
            raise BridgeError("immutable reply already exists")
        os.replace(tmp, path)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def _agent_dir(root: Path, agent: str, leaf: str) -> Path:
    if agent not in {"agent-a", "agent-b", "agent-c"} or leaf not in {"inbox", "outbox", "status"}:
        raise BridgeError("agent path is not allowlisted")
    path = root / "agents" / agent / leaf
    _no_reparse(path)
    if not path.is_dir():
        raise BridgeError("configured Drive agent directory is missing")
    return path


def validate_inbound(raw: bytes, *, peer: str):
    """Validate only peer-authored outbox data addressed to agent-a."""
    if len(raw) > MAX_TASK_BYTES:
        raise BridgeError("message exceeds size limit")
    try: msg=json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError,json.JSONDecodeError): raise BridgeError("message is not valid UTF-8 JSON") from None
    if not isinstance(msg,dict): raise BridgeError("message must be a JSON object")
    if msg.get("schema_version") != 1 or msg.get("from") != peer or msg.get("to") != "agent-a":
        raise BridgeError("message source, recipient, or schema is invalid")
    if not isinstance(msg.get("id"),str) or not ID_RE.fullmatch(msg["id"]): raise BridgeError("message id is invalid")
    if not isinstance(msg.get("thread"),str) or not THREAD_RE.fullmatch(msg["thread"]) or len(msg["thread"])>128:
        raise BridgeError("message thread is invalid")
    if "reply_to" in msg:
        required={"schema_version","id","thread","from","to","reply_to","request_digest","status","content","created_at","limits"}
        if set(msg)!=required or msg["reply_to"]!=msg["id"] or not re.fullmatch(r"[a-f0-9]{64}",str(msg["request_digest"])):
            raise BridgeError("reply correlation fields are invalid")
        if msg["status"] not in {"completed","failed","waiting"}: raise BridgeError("reply status is invalid")
        if not isinstance(msg["content"],str) or len(msg["content"])>6000: raise BridgeError("reply content exceeds bound")
        _validate_limits(msg["limits"])
        kind="reply"
    else:
        required={"schema_version","id","thread","from","to","task","content","created_at","limits","request_digest"}
        if set(msg)!=required: raise BridgeError("task has unknown or missing fields")
        for k,limit in (("task",160),("content",12000)):
            if not isinstance(msg[k],str) or not msg[k].strip() or len(msg[k])>limit: raise BridgeError(f"invalid {k}")
        _validate_limits(msg["limits"])
        if not re.fullmatch(r"[a-f0-9]{64}",str(msg["request_digest"])) or msg["request_digest"]!=request_digest(msg):
            raise BridgeError("task request digest mismatch")
        kind="task"
    try:
        stamp=datetime.fromisoformat(msg["created_at"].replace("Z","+00:00"))
        if stamp.tzinfo is None: raise ValueError
    except (ValueError,AttributeError,TypeError): raise BridgeError("created_at must include a timezone") from None
    return msg, kind


def _validate_limits(limits):
    if (not isinstance(limits,dict) or set(limits)!={"max_seconds","max_output_chars"}
            or type(limits["max_seconds"]) is not int or not 1<=limits["max_seconds"]<=300
            or type(limits["max_output_chars"]) is not int or not 1<=limits["max_output_chars"]<=6000):
        raise BridgeError("message limits outside local bounds")


def sync_drive_once(store, root: Path, *, limit=20):
    """Explicit one-shot import. No polling thread and no execution/approval."""
    if not 1<=int(limit)<=50: raise BridgeError("sync limit must be from 1 through 50")
    root=root.resolve(strict=True); imported=[]; correlated=[]; errors=[]; continuation_required=False
    for peer in ("agent-b","agent-c"):
        folder=_agent_dir(root,peer,"outbox")
        files=sorted(folder.glob("*.json"),key=lambda item:item.name)
        cursor=store.get_drive_cursor(peer)
        remaining=[item for item in files if not cursor or item.name>cursor]
        batch=remaining[:limit]
        more=len(remaining)>len(batch)
        next_cursor=batch[-1].name if more and batch else ""
        continuation_required=continuation_required or more
        for path in batch:
            try:
                raw=_read_stable(path); msg,kind=validate_inbound(raw,peer=peer)
                if path.name != f"{msg['id']}.json": raise BridgeError("filename and message id do not match")
                file_digest=hashlib.sha256(canonical(msg)).hexdigest()
                record=store.import_drive_message(msg,kind,message_digest=file_digest)
                imported.append({"message_id":msg["id"],"source":peer,"kind":kind,"state":record["state"]})
                if kind=="reply":
                    export=store.get_drive_export(msg["id"])
                    if export and export["peer"]==peer and export["request_digest"]==msg["request_digest"]:
                        expected=export["request_json"]
                        if expected["thread"]!=msg["thread"]: raise BridgeError("reply thread does not match exported task")
                        if msg["status"] in {"completed","failed"}:
                            task=store.complete_external_drive_task(msg["id"],peer,msg["request_digest"],file_digest,
                                result={"text":msg["content"],"external_status":msg["status"]},failed=msg["status"]=="failed")
                            correlated.append({"message_id":msg["id"],"task_id":task["id"],"state":task["state"]})
            except Exception as exc:
                # Never echo raw message bodies or provider diagnostics into API responses.
                error = str(exc)[:180] if isinstance(exc,BridgeError) else getattr(exc,"code",type(exc).__name__)
                errors.append({"file":path.name[:80],"error":error or "import_failed"})
        # Advance only after this bounded page has been fully attempted. A crash
        # before this point replays the page, which is safe via message digests.
        store.set_drive_cursor(peer,next_cursor)
    store.finish_drive_sync(len(imported),error="some files were rejected" if errors else None,
                            has_more=continuation_required)
    return {"imported":imported,"correlated":correlated,"rejected":errors,
            "auto_approved":False,"execution_started":False,"polling":False,
            "has_more":continuation_required,"next_sync_continues":continuation_required}


def export_approved_task(store, root: Path, task_id: str, *, principal="coordinator"):
    """Publish only a broker-approved queued task targeted at a named peer."""
    task=store.get_task(task_id)
    if not task: raise BridgeError("task not found")
    target=task.get("target_worker") or ""
    if target not in {"drive:agent-b","drive:agent-c"}: raise BridgeError("task is not explicitly targeted to a Drive peer")
    saved=store.get_drive_export(task_id)
    if saved and (task["state"] not in {"running","completed","failed"}
                  or task.get("cancellation_requested") or (task["state"]=="running" and (task.get("lease_until") or 0)<time.time())):
        raise BridgeError("existing external export is fenced; coordinator review is required")
    peer=target.split(":",1)[1]; payload=task.get("payload") or {}; prompt=payload.get("prompt")
    title=payload.get("title") or "Coordinator-approved task"
    if not isinstance(prompt,str) or not prompt.strip() or len(prompt)>12000: raise BridgeError("task prompt missing or too large")
    if not isinstance(title,str) or not title.strip() or len(title)>160: raise BridgeError("task title invalid")
    thread=task["thread_id"]
    if not isinstance(thread,str) or not THREAD_RE.fullmatch(thread) or len(thread)>128: raise BridgeError("task thread is incompatible with Drive protocol")
    limits=payload.get("limits") or {"max_seconds":min(300,int(task["timeout_seconds"])),"max_output_chars":6000}
    _validate_limits(limits)
    if saved:
        envelope=saved["request_json"]
        if saved["peer"]!=peer or envelope.get("content")!=prompt or envelope.get("thread")!=thread:
            raise BridgeError("stored export differs from approved task; refusing resend")
    else:
        envelope={"schema_version":1,"id":task_id,"thread":thread,"from":"agent-a","to":peer,
                  "task":title,"content":prompt,"created_at":datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),
                  "limits":limits}
        envelope["request_digest"]=request_digest(envelope)
    target_dir=_agent_dir(root.resolve(strict=True),peer,"inbox")
    path=target_dir/(task_id+".json"); expected=canonical(envelope)
    if saved and not path.exists(): raise BridgeError("previous export file is missing; refusing ambiguous resend")
    existing = None
    if path.exists():
        existing=_read_stable(path)
        try: old=json.loads(existing.decode("utf-8"))
        except Exception: raise BridgeError("existing peer task cannot be verified; refusing resend") from None
        if old!=envelope:
            if saved: raise BridgeError("existing peer task conflicts with stored export; refusing resend")
            expected_content={k:v for k,v in envelope.items() if k not in {"created_at","request_digest"}}
            old_content={k:v for k,v in old.items() if k not in {"created_at","request_digest"}}
            if old_content!=expected_content or old.get("request_digest")!=request_digest(old):
                raise BridgeError("existing peer task conflicts with approved task; refusing resend")
            envelope=old
    record=store.prepare_drive_export(task_id,peer,envelope["request_digest"],canonical(envelope).decode("utf-8"),principal=principal)
    if existing is None: _atomic_new(path,expected)
    return {"task_id":task_id,"peer":peer,"state":"exported_waiting_for_peer","request_digest":record["request_digest"],
            "broker_state":store.get_task(task_id)["state"],"pickup":"unknown","remote_execution_confirmed":False}


def process_approved(*args, **kwargs):
    """Standalone execution is retired; use the canonical broker lifecycle."""
    raise BridgeError("standalone Drive execution is disabled; use broker approval, claim, and completion")
