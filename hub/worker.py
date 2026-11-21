"""Opt-in polling worker. Merely importing this module does not start work."""
from __future__ import annotations

import ipaddress
import argparse
import json
import os
import tempfile
import time
import threading
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from .adapters import AdapterCancelled, AdapterError, make_adapter


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _local_opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def _url() -> str:
    value = os.environ.get("HUB_BROKER_URL", "http://127.0.0.1:8765").rstrip("/")
    from urllib.parse import urlsplit
    parsed = urlsplit(value)
    if parsed.scheme != "http" or parsed.username or parsed.password or not parsed.hostname:
        raise RuntimeError("broker URL must be plain HTTP on loopback")
    try:
        if not ipaddress.ip_address(parsed.hostname).is_loopback:
            raise RuntimeError("broker URL must use a loopback IP literal")
    except ValueError:
        raise RuntimeError("broker URL must use a loopback IP literal") from None
    return value


def _request(path: str, token: str, payload: dict | None = None) -> dict:
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(_url() + path, data=data,
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
        method="POST" if payload is not None else "GET")
    try:
        with _local_opener().open(req, timeout=5) as response:
            return json.loads(response.read(1_000_001))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"broker HTTP {exc.code}: {exc.read(2048).decode(errors='replace')}") from None


def _is_confirmed_cancellation(error: Exception, heartbeat_error: list[Exception]) -> bool:
    return isinstance(error, AdapterCancelled) and not heartbeat_error


def run_once(config: dict) -> bool:
    """Claim and execute at most one task; return False when queue is empty."""
    token = os.environ.get("HUB_WORKER_TOKEN", "")
    worker_id = str(config.get("worker_id", "worker-1"))
    if not token:
        raise RuntimeError("HUB_WORKER_TOKEN is required")
    if not config.get("enabled"):
        raise RuntimeError("worker is disabled in configuration")
    if not config.get("allow_unverified_provider_cost", False):
        raise RuntimeError("unverified provider cost is not explicitly allowed for this approved task")
    lease = int(config.get("lease_seconds", 120))
    task = _request("/v1/worker/claim", token, {"lease_seconds": lease})
    if not task or task.get("task") is None:
        # Current broker returns a raw task object, or null when empty.
        if not task or not task.get("id"):
            return False
    task = task.get("task", task)
    task_id, epoch = task["id"], task["lease_epoch"]
    heartbeat_error: list[Exception] = []
    digest = task.get("payload") or {}
    adapter_name = digest.get("adapter")
    adapters = config.get("adapters", {})
    budget = float(config.get("cost_limit", 0))
    reservation = float(task.get("cost_reserved", 0))
    if reservation > budget or reservation <= 0:
        error = "task has no positive cost reservation within configured budget"
        _request("/v1/worker/complete", token, {"task_id": task_id, "worker_id": worker_id,
            "lease_epoch": epoch, "error": error})
        return True
    try:
        adapter_config = adapters.get(str(adapter_name), {})
        native_agent_b_profile = (str(adapter_name) == "agent-b" and
                                   adapter_config.get("use_native_profile") is True)
        if not adapter_config.get("provider_key_env") and not native_agent_b_profile:
            raise AdapterError("explicit provider credential environment name is required")
        adapter = make_adapter(str(adapter_name), adapter_config)
        prompt = digest.get("prompt")
        if not isinstance(prompt, str):
            raise AdapterError("payload.prompt must be plain text")
        package_root = Path(config.get("_package_root", Path(__file__).resolve().parents[1])).resolve()
        configured_root = Path(config.get("task_root") or "private-tasks")
        root = (package_root / configured_root).resolve() if not configured_root.is_absolute() else configured_root.resolve()
        if package_root not in root.parents:
            raise RuntimeError("task_root must be inside the local-agent-hub package")
        root.mkdir(parents=True, exist_ok=True)
        root = root.resolve(strict=True)
        if package_root not in root.parents:
            raise RuntimeError("task_root escaped the package directory")
        task_dir = (root / uuid.uuid4().hex).resolve()
        task_dir.mkdir()
        if root.resolve() not in task_dir.parents:
            raise RuntimeError("task directory escaped configured task root")
        # Workspace ids are metadata; their paths are never used as process working dirs.
        cancelled = threading.Event()
        def renew() -> None:
            while not cancelled.wait(min(5, max(1, lease // 3))):
                try:
                    state = _request("/v1/worker/heartbeat", token,
                        {"task_id": task_id, "worker_id": worker_id,
                         "lease_epoch": epoch, "lease_seconds": lease})
                    if state.get("cancellation_requested"):
                        cancelled.set()
                except Exception as exc:
                    heartbeat_error.append(exc)
                    cancelled.set()
        hb = threading.Thread(target=renew, daemon=True)
        hb.start()
        try:
            result = adapter.run(prompt, cwd=task_dir,
                timeout_seconds=int(task.get("timeout_seconds", 300)), cancel_event=cancelled)
            if cancelled.is_set():
                if heartbeat_error:
                    raise AdapterError("execution stopped after broker heartbeat failure")
                raise AdapterError("process tree termination unconfirmed: cancellation raced with adapter return")
        finally:
            cancelled.set()
            hb.join(timeout=5)
        _request("/v1/worker/complete", token, {"task_id": task_id,
            "worker_id": worker_id, "lease_epoch": epoch, "result": {"text": result}})
    except Exception as exc:
        is_cancel = _is_confirmed_cancellation(exc, heartbeat_error)
        _request("/v1/worker/complete", token, {"task_id": task_id, "worker_id": worker_id,
            "lease_epoch": epoch, "cancelled": is_cancel,
            "error": None if is_cancel else (str(heartbeat_error[0]) if heartbeat_error else str(exc))[:2000]})
    return True


def run_forever(config: dict) -> None:
    while True:
        if not run_once(config):
            time.sleep(max(1, int(config.get("poll_seconds", 3))))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    with open(args.config, "r", encoding="utf-8") as stream:
        config = json.load(stream)
    worker_config = config.get("worker", {})
    worker_config["_package_root"] = str(Path(__file__).resolve().parents[1])
    run_forever(worker_config)


if __name__ == "__main__":
    main()

