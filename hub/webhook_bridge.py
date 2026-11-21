"""One-shot, approval-gated peer webhook bridge.

The PowerShell entry point decrypts the per-user DPAPI settings file and pipes
settings plus request content to this module through stdin. Secrets and task
content are never accepted as command-line arguments or written to receipts.
"""

from __future__ import annotations

import hashlib
import base64
import http.client
import ipaddress
import json
import os
import re
import secrets
import signal
import socket
import ssl
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

VERIFIED_INBOX_ROOT = r"C:\agent-hub\inbox"
MAX_CONTENT_CHARS = 20_000
MAX_REPLY_BYTES = 256_000
MAX_WAIT_SECONDS = 180
MAX_REQUEST_BYTES = 1_000_000
ID_RE = re.compile(r"^T[0-9a-f]{32}$")
HEADER_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$")
FORBIDDEN_HEADERS = {
    "host", "content-length", "connection", "transfer-encoding", "cookie",
    "set-cookie", "proxy-authorization", "proxy-connection", "expect", "upgrade",
}


class BridgeError(Exception):
    """Safe-to-report bridge failure; message contains no secrets or payload."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_inbox(path: str, expected_root: str = VERIFIED_INBOX_ROOT) -> Path:
    given = os.path.abspath(path)
    expected = os.path.abspath(expected_root)
    if os.path.normcase(given) != os.path.normcase(expected):
        raise BridgeError("configured inbox does not match the verified local inbox")
    root = Path(given)
    if not root.is_dir() or _is_reparse(root):
        raise BridgeError("verified inbox is unavailable or is a reparse point")
    return root


def _is_reparse(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return True
    if path.is_symlink():
        return True
    return bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _validate_settings(settings: dict[str, Any], expected_inbox: str) -> tuple[Any, str, str, str]:
    if settings.get("format_version") != 1:
        raise BridgeError("webhook settings format is unsupported")
    url = settings.get("endpoint_url")
    host = settings.get("allowed_host")
    name = settings.get("header_name")
    prefix = settings.get("header_value_prefix")
    key = settings.get("sender_key")
    inbox = settings.get("inbox_root")
    if not all(isinstance(v, str) and v for v in (url, host, name, key, inbox)) or not isinstance(prefix, str):
        raise BridgeError("webhook settings are incomplete")
    if any(any(ord(ch) < 32 or ord(ch) == 127 for ch in value) for value in (name, prefix, key)):
        raise BridgeError("webhook auth settings contain invalid characters")
    if not HEADER_RE.fullmatch(name) or name.lower() in FORBIDDEN_HEADERS:
        raise BridgeError("webhook header name is invalid or reserved")
    auth_value = prefix + key
    if len(auth_value) > 8192:
        raise BridgeError("webhook auth value exceeds the size limit")
    parsed = urlsplit(url)
    if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise BridgeError("webhook endpoint must be an HTTPS URL without user information")
    if parsed.fragment or parsed.hostname.lower().rstrip(".") != host.lower().rstrip("."):
        raise BridgeError("webhook endpoint host does not match the pinned host")
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        pass
    else:
        raise BridgeError("webhook endpoint must use a configured DNS hostname")
    if parsed.hostname.lower() in {"localhost", "metadata.google.internal"} or parsed.hostname.lower().endswith((".localhost", ".local", ".internal", ".test")):
        raise BridgeError("webhook host is local or reserved")
    _safe_inbox(inbox, expected_inbox)
    return parsed, name, auth_value, inbox


def _public_addresses(host: str, port: int, resolver: Callable[..., Any] = socket.getaddrinfo) -> list[str]:
    try:
        records = resolver(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise BridgeError("webhook host DNS lookup failed") from exc
    addresses: list[str] = []
    for record in records:
        address = record[4][0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError as exc:
            raise BridgeError("webhook DNS returned an invalid address") from exc
        if not ip.is_global:
            raise BridgeError("webhook host resolves to a non-public address")
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise BridgeError("webhook host has no usable public address")
    return addresses


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname: str, port: int, address: str, timeout: float):
        super().__init__(hostname, port=port, timeout=timeout, context=ssl.create_default_context())
        self._pinned_address = address

    def connect(self) -> None:
        sock = socket.create_connection((self._pinned_address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _post_once(parsed: Any, header_name: str, auth_value: str, payload: dict[str, str], timeout: float = 20.0) -> int:
    host = parsed.hostname
    port = parsed.port or 443
    addresses = _public_addresses(host, port)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    conn = _PinnedHTTPSConnection(host, port, addresses[0], timeout)
    try:
        conn.request("POST", path, body=body, headers={
            "Content-Type": "application/json; charset=utf-8",
            "Accept": "application/json",
            "Connection": "close",
            header_name: auth_value,
        })
        response = conn.getresponse()
        # Drain only a bounded amount; never surface webhook response text.
        response.read(4096)
        return response.status
    except (OSError, ssl.SSLError, http.client.HTTPException, TimeoutError) as exc:
        raise BridgeError("webhook POST outcome is ambiguous; automatic retry is disabled") from exc
    finally:
        conn.close()


def _digest(payload: dict[str, str]) -> str:
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise BridgeError("receipt cannot be read") from exc
    if len(data) > 32_000:
        raise BridgeError("receipt exceeds the size limit")
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BridgeError("receipt is invalid") from exc
    if not isinstance(value, dict):
        raise BridgeError("receipt is invalid")
    return value


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, path)
    except OSError as exc:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise BridgeError("receipt could not be persisted") from exc


def _reply_path(root: Path, source: str, task_id: str) -> Path:
    if source not in {"agent-a", "agent-b"} or not ID_RE.fullmatch(task_id):
        raise BridgeError("reply correlation is invalid")
    name = f"FOR-{source.upper()}-{task_id}.md"
    target = root / name
    if target.parent != root or target.name != name:
        raise BridgeError("reply path escaped the verified inbox")
    return target


def _read_stable_reply(path: Path, delay: float = 0.35) -> tuple[str, str] | None:
    try:
        if _is_reparse(path) or not path.is_file():
            return None
        first = path.read_bytes()
        if len(first) > MAX_REPLY_BYTES:
            raise BridgeError("reply exceeds the size limit")
        time.sleep(delay)
        if _is_reparse(path) or not path.is_file():
            return None
        second = path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError:
        return None
    if len(second) > MAX_REPLY_BYTES:
        raise BridgeError("reply exceeds the size limit")
    if not second.strip():
        raise BridgeError("reply is empty")
    digest = hashlib.sha256(second).hexdigest()
    if first != second:
        return None
    try:
        text = second.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise BridgeError("reply is not valid UTF-8") from exc
    return text, digest


def _run_transaction_locked(
    envelope: dict[str, Any],
    *,
    receipt_dir: str | Path,
    expected_inbox: str = VERIFIED_INBOX_ROOT,
    sender: Callable[[Any, str, str, dict[str, str]], int] = _post_once,
    now: Callable[[], str] = _utc_now,
    wait: Callable[[float], None] = time.sleep,
    reply_reader: Callable[[Path], tuple[str, str] | None] = _read_stable_reply,
) -> dict[str, Any]:
    settings = envelope.get("settings")
    source = envelope.get("source")
    content = envelope.get("content")
    approval = envelope.get("approval_digest")
    wait_seconds = envelope.get("wait_seconds", 120)
    if not isinstance(settings, dict) or source not in {"agent-a", "agent-b"}:
        raise BridgeError("request is invalid")
    if not isinstance(content, str) or not content.strip() or len(content) > MAX_CONTENT_CHARS:
        raise BridgeError("review content is empty or exceeds the limit")
    if isinstance(wait_seconds, bool) or not isinstance(wait_seconds, int) or not 1 <= wait_seconds <= MAX_WAIT_SECONDS:
        raise BridgeError("wait timeout is outside the allowed range")
    parsed, header_name, auth_value, inbox_setting = _validate_settings(settings, expected_inbox)
    root = _safe_inbox(inbox_setting, expected_inbox)
    receipts = Path(receipt_dir)
    receipt = receipts / "peer-webhook-pending.json"
    pending = _read_json(receipt)
    if pending and pending.get("state") in {"reply_received", "http_rejected"}:
        old_id = pending.get("task_id")
        if not isinstance(old_id, str) or not ID_RE.fullmatch(old_id):
            raise BridgeError("completed receipt is invalid")
        archive = receipts / f"peer-webhook-{old_id}.json"
        if archive.exists():
            raise BridgeError("completed receipt archive already exists")
        try:
            os.replace(receipt, archive)
        except OSError as exc:
            raise BridgeError("completed receipt could not be archived") from exc
        pending = None
    if pending is None:
        task_id = "T" + secrets.token_hex(16)
        task_content = content.rstrip() + "\n\nCorrelation ID: " + task_id
        payload = {"id": task_id, "from": source, "task": "review", "content": task_content}
        reply = _reply_path(root, source, task_id)
        if reply.exists():
            raise BridgeError("new correlation id unexpectedly collides with an existing reply")
        digest = _digest(payload)
        pending = {
            "task_id": task_id,
            "source": source,
            "task": "review",
            "payload_sha256": digest,
            "reply_filename": reply.name,
            "created_at": now(),
            "state": "prepared",
            "http_status": None,
            "reply_sha256": None,
            "reply_received_at": None,
        }
        _write_json(receipt, pending)
        return {"state": "prepared", "task_id": task_id, "payload_sha256": digest, "reply_filename": reply.name}
    task_id = pending.get("task_id")
    if pending.get("source") != source or not isinstance(task_id, str) or not ID_RE.fullmatch(task_id):
        raise BridgeError("pending task does not match this request")
    payload = {"id": task_id, "from": source, "task": "review", "content": content.rstrip() + "\n\nCorrelation ID: " + task_id}
    digest = _digest(payload)
    if digest != pending.get("payload_sha256"):
        raise BridgeError("request content changed after preparation")
    if pending.get("state") == "prepared":
        if not isinstance(approval, str) or not re.fullmatch(r"[0-9a-f]{64}", approval) or not secrets.compare_digest(approval, digest):
            return {"state": "approval_required", "task_id": task_id, "payload_sha256": digest, "reply_filename": pending["reply_filename"]}
        reply = _reply_path(root, source, task_id)
        if reply.exists():
            raise BridgeError("correlated reply path already exists before send")
        try:
            reply.lstat()
        except FileNotFoundError:
            pass
        else:
            raise BridgeError("correlated reply path already exists before send")
        pending["state"] = "send_started"
        pending["send_started_at"] = now()
        _write_json(receipt, pending)
        try:
            status = sender(parsed, header_name, auth_value, payload)
        except BridgeError:
            pending["state"] = "send_ambiguous"
            _write_json(receipt, pending)
            raise
        pending["http_status"] = status
        if not 200 <= status < 300:
            pending["state"] = "http_rejected"
            _write_json(receipt, pending)
            raise BridgeError(f"webhook returned HTTP {status}; automatic retry is disabled")
        pending["state"] = "http_accepted_waiting_reply"
        pending["http_accepted_at"] = now()
        _write_json(receipt, pending)
    elif pending.get("state") not in {"send_started", "send_ambiguous", "http_accepted_waiting_reply", "reply_wait_timeout", "reply_wait_cancelled"}:
        raise BridgeError("pending task state is not resumable")
    elif approval is not None and approval != pending.get("payload_sha256"):
        raise BridgeError("approval digest does not match the pending task")
    reply = _reply_path(root, source, task_id)
    deadline = time.monotonic() + wait_seconds
    try:
        while time.monotonic() < deadline:
            result = reply_reader(reply)
            if result is not None:
                text, reply_hash = result
                pending["state"] = "reply_received"
                pending["reply_sha256"] = reply_hash
                pending["reply_received_at"] = now()
                _write_json(receipt, pending)
                return {
                    "state": "reply_received",
                    "task_id": task_id,
                    "payload_sha256": digest,
                    "http_status": pending.get("http_status"),
                    "reply_filename": reply.name,
                    "reply_sha256": reply_hash,
                    "reply_text_untrusted": text,
                }
            wait(min(0.5, max(0.0, deadline - time.monotonic())))
    except KeyboardInterrupt:
        pending["state"] = "reply_wait_cancelled"
        _write_json(receipt, pending)
        return {"state": "reply_wait_cancelled", "task_id": task_id, "reply_filename": reply.name}
    pending["state"] = "reply_wait_timeout"
    pending["wait_timed_out_at"] = now()
    _write_json(receipt, pending)
    return {"state": "reply_wait_timeout", "task_id": task_id, "reply_filename": reply.name, "http_status": pending.get("http_status")}


@contextmanager
def _receipt_lock(receipt_dir: Path):
    receipt_dir.mkdir(parents=True, exist_ok=True)
    lock = receipt_dir / "peer-webhook.lock"
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise BridgeError("another webhook transaction is active") from exc
    try:
        os.write(descriptor, str(os.getpid()).encode("ascii"))
        yield
    finally:
        os.close(descriptor)
        try:
            lock.unlink()
        except OSError:
            pass


def run_transaction(
    envelope: dict[str, Any],
    *,
    receipt_dir: str | Path,
    expected_inbox: str = VERIFIED_INBOX_ROOT,
    sender: Callable[[Any, str, str, dict[str, str]], int] = _post_once,
    now: Callable[[], str] = _utc_now,
    wait: Callable[[float], None] = time.sleep,
    reply_reader: Callable[[Path], tuple[str, str] | None] = _read_stable_reply,
) -> dict[str, Any]:
    with _receipt_lock(Path(receipt_dir)):
        return _run_transaction_locked(
            envelope,
            receipt_dir=receipt_dir,
            expected_inbox=expected_inbox,
            sender=sender,
            now=now,
            wait=wait,
            reply_reader=reply_reader,
        )


def main() -> int:
    try:
        encoded = sys.stdin.buffer.read(MAX_REQUEST_BYTES * 2)
        if len(encoded) > MAX_REQUEST_BYTES * 2 - 1:
            raise BridgeError("request exceeds the size limit")
        raw = base64.b64decode(encoded.strip(), validate=True)
        if len(raw) > MAX_REQUEST_BYTES:
            raise BridgeError("request exceeds the size limit")
        envelope = json.loads(raw)
        project_root = Path(__file__).resolve().parents[1]
        result = run_transaction(
            envelope,
            receipt_dir=project_root / "state" / "control-receipts",
        )
        output = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        print(base64.b64encode(output).decode("ascii"))
        return 0
    except BridgeError as exc:
        output = json.dumps({"state": "error", "error": str(exc)}, separators=(",", ":")).encode("utf-8")
        print(base64.b64encode(output).decode("ascii"), file=sys.stderr)
        return 2
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError, ValueError):
        print(base64.b64encode(b'{"state":"error","error":"invalid bridge input"}').decode("ascii"), file=sys.stderr)
        return 2
    except Exception:
        print(base64.b64encode(b'{"state":"error","error":"unexpected bridge failure; details suppressed"}').decode("ascii"), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
