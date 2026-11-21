import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlsplit
from unittest.mock import patch

from fastapi.testclient import TestClient

from hub.adapters import AdapterConfig, AdapterError, CLIAdapter
from hub.api import create_app
from hub.store import Store
from hub import worker


import secrets as _secrets

COORD_TOKEN = _secrets.token_hex(16)  # generated per run; never a real credential
WORKER_TOKEN = _secrets.token_hex(16)  # generated per run; never a real credential


class SimulatedTextWorker(CLIAdapter):
    """Fixture process only; it never calls a model or network service."""
    name = "fixture"
    def argv(self):
        return ["-c", "import sys; print('fixture-result:' + sys.stdin.read())"]


class Response:
    def __init__(self, response): self.content = response.content
    def read(self, size=-1): return self.content if size < 0 else self.content[:size]
    def __enter__(self): return self
    def __exit__(self, *args): return False


class WorkerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / "broker.sqlite3", allowed_workspaces=[self.temp.name])
        self.client = TestClient(create_app(self.store))
        self.env = patch.dict(os.environ, {"HUB_COORDINATOR_TOKEN": COORD_TOKEN,
            "HUB_WORKER_TOKENS": WORKER_TOKEN, "HUB_ENABLE_WORKERS": "1",
            "HUB_BROKER_URL": "http://127.0.0.1:8765", "HUB_WORKER_TOKEN": WORKER_TOKEN})
        self.env.start()
        self.http = patch("urllib.request.build_opener", self.build_opener)
        self.http.start()

    def tearDown(self):
        self.http.stop()
        self.env.stop()
        self.store.close()
        self.temp.cleanup()

    def build_opener(self, *handlers):
        return self.InProcessOpener(self)

    class InProcessOpener:
        def __init__(self, case): self.case = case
        def open(self, request, timeout=10): return self.case.request(request)

    def request(self, request):
        parsed = urlsplit(request.full_url)
        response = self.client.request(request.method,
            parsed.path + ("?" + parsed.query if parsed.query else ""), content=request.data,
            headers=dict(request.header_items()))
        if response.status_code >= 400:
            from urllib.error import HTTPError
            raise HTTPError(request.full_url, response.status_code, response.text, response.headers, None)
        return Response(response)

    def test_simulated_worker_claims_executes_and_completes(self):
        coordinator = {"Authorization": "Bearer " + COORD_TOKEN}
        created = self.client.post("/v1/dispatch", headers=coordinator, json={
            "workspace": self.temp.name,
            "payload": {"adapter": "fixture", "prompt": "hello"},
            "idempotency_key": "worker-test", "target_worker": "worker-1",
            "cost_reserved": 0.1, "timeout_seconds": 20}).json()
        approved = self.client.post("/v1/approve/" + created["id"], headers=coordinator,
            json={"task_digest": created["task_digest"]})
        self.assertEqual(approved.status_code, 200)
        config = {"enabled": True, "allow_unverified_provider_cost": True,
            "cost_limit": 0.2, "lease_seconds": 9, "task_root": "private-tasks",
            "_package_root": self.temp.name,
            "adapters": {"fixture": {"enabled": True, "executable": sys.executable,
                "timeout_seconds": 20, "max_output_bytes": 1024, "provider_key_env": "PROVIDER_A_API_KEY"}}}
        with patch.object(worker, "make_adapter", side_effect=lambda name, cfg:
                SimulatedTextWorker(AdapterConfig(name, cfg["executable"], True,
                    cfg["timeout_seconds"], cfg["max_output_bytes"]))):
            self.assertTrue(worker.run_once(config))
        finished = self.store.get_task(created["id"])
        self.assertEqual(finished["state"], "completed")
        self.assertEqual(finished["result"]["text"].strip(), "fixture-result:hello")
        self.assertEqual(finished["worker_id"], "worker-1")
        self.assertIn("claimed", {event["event"] for event in self.store.logs(created["id"])})
        self.assertIn("completed", {event["event"] for event in self.store.logs(created["id"])})

    def test_unavailable_adapter_failure_is_recorded_on_claimed_task(self):
        coordinator = {"Authorization": "Bearer " + COORD_TOKEN}
        created = self.client.post("/v1/dispatch", headers=coordinator, json={
            "workspace": self.temp.name,
            "payload": {"adapter": "unknown", "prompt": "hello"},
            "idempotency_key": "worker-unavailable-adapter", "target_worker": "worker-1",
            "cost_reserved": 0.1, "timeout_seconds": 20}).json()
        approved = self.client.post("/v1/approve/" + created["id"], headers=coordinator,
            json={"task_digest": created["task_digest"]})
        self.assertEqual(approved.status_code, 200)
        config = {"enabled": True, "allow_unverified_provider_cost": True,
            "cost_limit": 0.2, "lease_seconds": 9,
            "adapters": {"unknown": {"provider_key_env": "PROVIDER_A_API_KEY"}}}
        with patch.object(worker, "make_adapter", side_effect=AdapterError("unknown adapter")):
            self.assertTrue(worker.run_once(config))
        failed = self.store.get_task(created["id"])
        self.assertEqual(failed["state"], "failed")
        self.assertIn("unknown adapter", failed["error"])
        self.assertEqual(failed["worker_id"], "worker-1")

    def test_unconfigured_provider_key_fails_closed_by_default(self):
        coordinator = {"Authorization": "Bearer " + COORD_TOKEN}
        created = self.client.post("/v1/dispatch", headers=coordinator, json={
            "workspace": self.temp.name,
            "payload": {"adapter": "agent-b", "prompt": "hello"},
            "idempotency_key": "worker-no-native-profile", "target_worker": "worker-1",
            "cost_reserved": 0.1, "timeout_seconds": 20}).json()
        self.client.post("/v1/approve/" + created["id"], headers=coordinator,
            json={"task_digest": created["task_digest"]})
        config = {"enabled": True, "allow_unverified_provider_cost": True,
            "cost_limit": 0.2, "lease_seconds": 9,
            "adapters": {"agent-b": {"enabled": True}}}
        self.assertTrue(worker.run_once(config))
        failed = self.store.get_task(created["id"])
        self.assertEqual(failed["state"], "failed")
        self.assertIn("explicit provider credential", failed["error"])

    def test_explicit_native_agent_b_profile_allows_scoped_auth_route(self):
        coordinator = {"Authorization": "Bearer " + COORD_TOKEN}
        created = self.client.post("/v1/dispatch", headers=coordinator, json={
            "workspace": self.temp.name,
            "payload": {"adapter": "agent-b", "prompt": "hello"},
            "idempotency_key": "worker-native-agent-b-profile", "target_worker": "worker-1",
            "cost_reserved": 0.1, "timeout_seconds": 20}).json()
        self.client.post("/v1/approve/" + created["id"], headers=coordinator,
            json={"task_digest": created["task_digest"]})
        config = {"enabled": True, "allow_unverified_provider_cost": True,
            "cost_limit": 0.2, "lease_seconds": 9, "task_root": "private-tasks",
            "_package_root": self.temp.name,
            "adapters": {"agent-b": {"enabled": True, "use_native_profile": True}}}
        seen = {}
        def factory(name, adapter_config):
            seen["name"] = name
            seen.update(adapter_config)
            return SimulatedTextWorker(AdapterConfig("fixture", sys.executable, True,
                timeout_seconds=20, max_output_bytes=1024))
        with patch.object(worker, "make_adapter", side_effect=factory):
            self.assertTrue(worker.run_once(config))
        finished = self.store.get_task(created["id"])
        self.assertEqual(finished["state"], "completed")
        self.assertEqual(seen["name"], "agent-b")
        self.assertIs(seen["use_native_profile"], True)


if __name__ == "__main__":
    unittest.main()
