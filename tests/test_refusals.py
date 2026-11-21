"""Authentication, malformed-input, loopback, adapter and worker refusal paths.

Everything here runs in process: TestClient for HTTP, temporary directories for state, and fakes
for anything that could reach a network. Tokens are generated at run time.
"""
from __future__ import annotations

import json
import os
import secrets
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from hub import mcp_server, worker
from hub.adapters import AdapterConfig, AdapterError, AgentAAdapter, AgentBAdapter, CLIAdapter, make_adapter
from hub.api import create_app
from hub.github_client import GitHubClient
from hub.relay import RelayBrokerClient, RelayError, parse_envelope
from hub.security import authenticate, redact, token_fingerprint
from hub.store import Store

ENV_KEYS = ("HUB_COORDINATOR_TOKEN", "HUB_WORKER_TOKENS", "HUB_ENABLE_WORKERS", "HUB_ENABLE_RELAY",
            "HUB_RELAY_TOKEN", "HUB_ENABLE_DRIVE", "HUB_DRIVE_ROOT", "HUB_RELAY_ALLOWED_SOURCES")


class ApiCase(unittest.TestCase):
    workers_enabled = "1"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.coordinator_token = secrets.token_hex(16)
        self.worker_token = secrets.token_hex(16)
        self.env = patch.dict(os.environ, {"HUB_COORDINATOR_TOKEN": self.coordinator_token,
                                           "HUB_WORKER_TOKENS": self.worker_token,
                                           "HUB_ENABLE_WORKERS": self.workers_enabled})
        self.env.start()
        for key in ("HUB_ENABLE_RELAY", "HUB_RELAY_TOKEN", "HUB_ENABLE_DRIVE", "HUB_DRIVE_ROOT"):
            os.environ.pop(key, None)
        self.workspace = Path(self.tmp.name) / "ws"
        self.workspace.mkdir()
        self.store = Store(Path(self.tmp.name) / "api.sqlite3", rate_limit=1000,
                           allowed_workspaces=[self.tmp.name])
        self.client = TestClient(create_app(self.store))
        self.coordinator = {"Authorization": "Bearer " + self.coordinator_token}
        self.worker = {"Authorization": "Bearer " + self.worker_token}

    def tearDown(self):
        self.store.close()
        self.env.stop()
        self.tmp.cleanup()

    def body(self, key="k1", **extra):
        value = {"workspace": str(self.workspace), "payload": {"prompt": "x"}, "idempotency_key": key}
        value.update(extra)
        return value


class AuthenticationRefusalTests(ApiCase):
    ROUTES = (("GET", "/v1/status"), ("POST", "/v1/dispatch"), ("POST", "/v1/emergency-stop"),
              ("POST", "/v1/worker/claim"), ("GET", "/v1/relay/outbox"), ("GET", "/v1/inbox"))

    def call(self, method, path, headers):
        kwargs = {"json": self.body()} if path == "/v1/dispatch" else {}
        if path == "/v1/worker/claim":
            kwargs = {"json": {"lease_seconds": 30}}
        return self.client.request(method, path, headers=headers, **kwargs)

    def test_missing_wrong_and_malformed_credentials_get_401_on_every_family(self):
        wrong = secrets.token_hex(16)
        variants = ({}, {"Authorization": "Bearer " + wrong}, {"Authorization": "Basic " + self.coordinator_token},
                    {"Authorization": self.coordinator_token}, {"Authorization": "Bearer"},
                    {"Authorization": "Bearer "}, {"Authorization": ""})
        for method, path in self.ROUTES:
            for headers in variants:
                with self.subTest(path=path, headers=sorted(headers)):
                    self.assertEqual(self.call(method, path, headers).status_code, 401)

    def test_worker_token_is_refused_on_every_coordinator_route(self):
        for method, path in (("POST", "/v1/dispatch"), ("POST", "/v1/emergency-stop"), ("GET", "/v1/status"),
                             ("GET", "/v1/inbox"), ("GET", "/v1/relay/outbox")):
            with self.subTest(path=path):
                self.assertEqual(self.call(method, path, self.worker).status_code, 403)

    def test_coordinator_token_is_refused_on_worker_and_relay_routes(self):
        self.assertEqual(self.client.post("/v1/worker/claim", headers=self.coordinator,
                                          json={"lease_seconds": 30}).status_code, 403)
        os.environ["HUB_ENABLE_RELAY"] = "1"
        self.assertEqual(self.client.post("/v1/relay/outbox/claim", headers=self.coordinator,
                                          json={"lease_seconds": 30}).status_code, 403)

    def test_one_workers_token_cannot_act_as_another_worker(self):
        second = secrets.token_hex(16)
        os.environ["HUB_WORKER_TOKENS"] = self.worker_token + "," + second
        response = self.client.post("/v1/worker/heartbeat", headers={"Authorization": "Bearer " + second},
                                    json={"task_id": "t", "worker_id": "worker-1", "lease_epoch": 1})
        self.assertEqual(response.status_code, 403)

    def test_interactive_documentation_and_schema_are_not_served(self):
        for path in ("/docs", "/redoc", "/openapi.json"):
            self.assertEqual(self.client.get(path).status_code, 404)

    def test_health_is_the_only_unauthenticated_route_and_leaks_no_secrets(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.json()), {"ok", "worker_execution_enabled", "relay_enabled"})

    def test_request_rate_limit_returns_429_after_the_window_is_spent(self):
        limited = Store(Path(self.tmp.name) / "limited.sqlite3", rate_limit=3, allowed_workspaces=[self.tmp.name])
        try:
            client = TestClient(create_app(limited))
            codes = [client.get("/v1/status", headers=self.coordinator).status_code for _ in range(5)]
        finally:
            limited.close()
        self.assertEqual(codes, [200, 200, 200, 429, 429])


class WorkerEndpointsDisabledTests(ApiCase):
    workers_enabled = "0"

    def test_valid_worker_token_gets_423_until_workers_are_enabled(self):
        response = self.client.post("/v1/worker/claim", headers=self.worker, json={"lease_seconds": 30})
        self.assertEqual(response.status_code, 423)


class SecurityHelperTests(unittest.TestCase):
    def test_no_environment_means_no_credential_resolves(self):
        with patch.dict(os.environ):
            for key in ENV_KEYS:
                os.environ.pop(key, None)
            for candidate in (None, "", secrets.token_hex(8)):
                self.assertIsNone(authenticate(candidate))

    def test_relay_token_is_inert_unless_the_relay_is_enabled(self):
        token = secrets.token_hex(16)
        with patch.dict(os.environ, {"HUB_RELAY_TOKEN": token}):
            os.environ.pop("HUB_ENABLE_RELAY", None)
            self.assertIsNone(authenticate(token))
            os.environ["HUB_ENABLE_RELAY"] = "1"
            self.assertEqual(authenticate(token).role, "relay")

    def test_blank_worker_token_entries_never_match_an_empty_token(self):
        with patch.dict(os.environ, {"HUB_WORKER_TOKENS": " , ,"}):
            os.environ.pop("HUB_COORDINATOR_TOKEN", None)
            self.assertIsNone(authenticate(""))
            self.assertIsNone(authenticate(" "))

    def test_fingerprint_is_short_and_does_not_contain_the_token(self):
        token = secrets.token_hex(16)
        fingerprint = token_fingerprint(token)
        self.assertEqual(len(fingerprint), 16)
        self.assertNotIn(token, fingerprint)

    def test_redact_masks_sensitive_keys_nested_values_and_credential_shapes(self):
        bearer = secrets.token_hex(12)
        prefixed = "sk-" + secrets.token_hex(12)
        field = "password"  # a credential-shaped key=value pair, built at run time
        out = redact({"api_key": "visible", "Password": "visible", "nested": [{"note": "Bearer " + bearer}],
                      "text": f"{field}={bearer} and {prefixed}", "count": 3, "keep": "plain"})
        flat = json.dumps(out)
        for secret in (bearer, prefixed, "visible"):
            self.assertNotIn(secret, flat)
        self.assertEqual((out["count"], out["keep"]), (3, "plain"))

    def test_redact_masks_configured_tokens_even_when_embedded(self):
        token = secrets.token_hex(16)
        with patch.dict(os.environ, {"HUB_COORDINATOR_TOKEN": token}):
            self.assertEqual(redact("prefix-" + token + "-suffix"), "prefix-[REDACTED]-suffix")


class MalformedInputTests(ApiCase):
    def test_dispatch_validation_failures_are_422(self):
        cases = {"empty key": self.body(key=""), "long key": self.body(key="k" * 201),
                 "priority too high": self.body(priority=101), "priority not a number": self.body(priority="high"),
                 "too many dependencies": self.body(depends_on=["d%d" % i for i in range(33)]),
                 "payload is a list": self.body(payload=["x"]),
                 "no payload": {"workspace": str(self.workspace), "idempotency_key": "k"}}
        for label, body in cases.items():
            with self.subTest(label):
                self.assertEqual(self.client.post("/v1/dispatch", headers=self.coordinator, json=body).status_code, 422)

    def test_dispatch_semantic_refusals_carry_exact_error_codes(self):
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        cases = (("workspace outside allowed roots", {"workspace": outside.name}, 403, "workspace_not_allowed"),
                 ("workspace missing", {"workspace": str(Path(self.tmp.name) / "absent")}, 400, "workspace_missing"),
                 ("zero timeout", {"timeout_seconds": 0}, 400, "timeout_limit"),
                 ("huge timeout", {"timeout_seconds": 3601}, 400, "timeout_limit"),
                 ("negative cost", {"cost_reserved": -1}, 400, "cost_limit"),
                 ("cost above per-task bound", {"cost_reserved": 100.5}, 400, "cost_limit"),
                 ("unknown parent", {"parent_task_id": "no-such-task"}, 404, "parent_not_found"),
                 ("unknown dependency", {"depends_on": ["no-such-task"]}, 404, "dependency_not_found"),
                 ("duplicate dependency", {"depends_on": ["a", "a"]}, 400, "dependency_duplicate"))
        for index, (label, extra, status, code) in enumerate(cases):
            with self.subTest(label):
                response = self.client.post("/v1/dispatch", headers=self.coordinator,
                                            json=self.body(key="sem-%d" % index, **extra))
                self.assertEqual(response.status_code, status)
                self.assertEqual(response.json()["detail"]["error"], code)

    def test_non_json_and_non_finite_bodies_never_create_a_task(self):
        headers = {**self.coordinator, "Content-Type": "application/json"}
        self.assertEqual(self.client.post("/v1/dispatch", headers=headers, content=b"not json").status_code, 422)
        text = json.dumps(self.body(key="nan"))[:-1] + ', "cost_reserved": NaN}'
        response = self.client.post("/v1/dispatch", headers=headers, content=text.encode())
        self.assertIn(response.status_code, (400, 422))
        self.assertEqual(self.store.status()["counts"], {})

    def test_approve_and_worker_bodies_must_be_well_formed(self):
        self.assertEqual(self.client.post("/v1/approve/x", headers=self.coordinator, json={}).status_code, 422)
        self.assertEqual(self.client.post("/v1/worker/claim", headers=self.worker,
                                          json={"lease_seconds": "soon"}).status_code, 422)
        self.assertEqual(self.client.post("/v1/worker/heartbeat", headers=self.worker, json={
            "task_id": "t", "worker_id": "worker-1", "lease_epoch": "first"}).status_code, 422)
        self.assertEqual(self.client.post("/v1/worker/complete", headers=self.worker,
                                          json={"task_id": "t"}).status_code, 422)

    def test_worker_cannot_complete_a_task_it_does_not_hold(self):
        created = self.client.post("/v1/dispatch", headers=self.coordinator, json=self.body()).json()
        response = self.client.post("/v1/worker/complete", headers=self.worker, json={
            "task_id": created["id"], "worker_id": "worker-1", "lease_epoch": 1, "result": {"text": "x"}})
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["detail"]["error"], "stale_lease")
        self.assertEqual(self.store.get_task(created["id"])["state"], "awaiting_approval")

    def test_unknown_task_ids_are_404(self):
        for path in ("/v1/status/nope", "/v1/logs/nope"):
            self.assertEqual(self.client.get(path, headers=self.coordinator).status_code, 404)

    def test_reconcile_requires_real_booleans(self):
        created = self.client.post("/v1/dispatch", headers=self.coordinator, json=self.body()).json()
        response = self.client.post("/v1/reconcile/" + created["id"], headers=self.coordinator, json={
            "task_digest": created["task_digest"], "process_termination_confirmed": "yes", "evidence_note": "n"})
        self.assertEqual(response.status_code, 422)


class LoopbackRefusalTests(unittest.TestCase):
    """The server trusts its bind address; every in-repo client refuses non-loopback URLs."""
    REFUSED = ("http://example.com:8765", "https://127.0.0.1:8765", "http://user" + "@127.0.0.1:8765",
               "http://localhost:8765", "http://0.0.0.0:8765", "http://192.0.2.10:8765", "ftp://127.0.0.1:8765",
               "http://:8765")
    ACCEPTED = ("http://127.0.0.1:8765", "http://[::1]:8765")

    def check(self, resolver):
        for url in self.REFUSED:
            with self.subTest(url=url), patch.dict(os.environ, {"HUB_BROKER_URL": url}):
                with self.assertRaises(RuntimeError):
                    resolver()
        for url in self.ACCEPTED:
            with self.subTest(url=url), patch.dict(os.environ, {"HUB_BROKER_URL": url}):
                self.assertEqual(resolver(), url)

    def test_mcp_entry_refuses_non_loopback_broker_urls(self):
        self.check(mcp_server._broker_url)

    def test_worker_refuses_non_loopback_broker_urls(self):
        self.check(worker._url)

    def test_relay_client_constructor_refuses_non_loopback_urls_and_empty_tokens(self):
        token = secrets.token_hex(8)
        for url in self.REFUSED[:7] + ("http://127.0.0.1:8765/prefix",):
            with self.subTest(url=url), self.assertRaises(ValueError):
                RelayBrokerClient(url, token)
        with self.assertRaises(ValueError):
            RelayBrokerClient("http://127.0.0.1:8765", "")

    def test_relay_client_never_calls_outside_the_relay_api(self):
        class Opener:
            calls = 0

            def open(self, *_args, **_kwargs):
                Opener.calls += 1
                raise AssertionError("must not be reached")

        client = RelayBrokerClient("http://127.0.0.1:8765", secrets.token_hex(8), opener=Opener())
        for path in ("/v1/approve/x", "/v1/relay/../approve/x", "//v1/relay/x", "/v1/relay/x#frag"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                client.call("POST", path, {})
        self.assertEqual(Opener.calls, 0)

    def test_github_client_refuses_paths_that_could_leave_the_fixed_api_host(self):
        class Opener:
            def open(self, *_args, **_kwargs):
                raise AssertionError("must not be reached")

        client = GitHubClient(secrets.token_hex(8), opener=Opener())
        for path in ("//evil.example.com/x", "relative", "/repos/../x", "/x#frag"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                client.request("GET", path)


class _Trivial(CLIAdapter):
    name = "fixture"

    def argv(self):
        return ["-c", "print('ok')"]


class AdapterFailClosedTests(unittest.TestCase):
    def run_adapter(self, adapter, prompt="go"):
        with tempfile.TemporaryDirectory() as root:
            return adapter.run(prompt, cwd=Path(root))

    def config(self, **kwargs):
        kwargs.setdefault("enabled", True)
        return AdapterConfig("fixture", sys.executable, **kwargs)

    def test_adapters_built_from_empty_config_are_disabled_and_refuse_to_run(self):
        for name in ("agent-a", "agent-b", "agent-d"):
            adapter = make_adapter(name, {})
            self.assertFalse(adapter.config.enabled)
            with self.assertRaisesRegex(AdapterError, "disabled|no verified CLI"):
                self.run_adapter(adapter)

    def test_unknown_adapter_name_is_refused(self):
        with self.assertRaisesRegex(AdapterError, "unknown adapter"):
            make_adapter("agent-z", {"enabled": True})

    def test_enabled_adapter_with_missing_executable_refuses(self):
        for executable in ("", str(Path(tempfile.gettempdir()) / secrets.token_hex(8) / "absent")):
            with self.subTest(executable=bool(executable)), self.assertRaisesRegex(AdapterError, "unavailable"):
                self.run_adapter(_Trivial(AdapterConfig("fixture", executable, enabled=True)))

    def test_enabled_flag_must_be_truthy_in_the_config_file(self):
        self.assertFalse(make_adapter("agent-a", {"enabled": 0}).config.enabled)
        self.assertFalse(make_adapter("agent-a", {"enabled": ""}).config.enabled)

    def test_native_profile_requires_the_boolean_true(self):
        for value in ("true", 1, "yes", None):
            self.assertFalse(make_adapter("agent-b", {"use_native_profile": value}).config.use_native_profile)
        self.assertTrue(make_adapter("agent-b", {"use_native_profile": True}).config.use_native_profile)

    def test_output_cap_in_config_is_clamped_to_safe_bounds(self):
        self.assertEqual(make_adapter("agent-a", {"max_output_bytes": 10 ** 9}).config.max_output_bytes, 262144)
        self.assertEqual(make_adapter("agent-a", {"max_output_bytes": 1}).config.max_output_bytes, 1024)

    def test_prompt_validation_rejects_empty_non_text_and_oversize(self):
        adapter = _Trivial(self.config())
        for prompt, message in (("  \n", "non-empty"), (None, "non-empty"), (123, "non-empty"),
                                ("x" * 1_000_001, "1 MB")):
            with self.subTest(message=message), self.assertRaisesRegex(AdapterError, message):
                self.run_adapter(adapter, prompt)

    def test_agent_b_message_over_the_command_line_limit_is_refused_before_launch(self):
        adapter = AgentBAdapter(AdapterConfig("agent-b", sys.executable, enabled=True, model="example-model"))
        with self.assertRaisesRegex(AdapterError, "command-line limit"):
            self.run_adapter(adapter, "x" * 10_001)

    def test_agent_a_requires_its_pinned_model(self):
        adapter = AgentAAdapter(AdapterConfig("agent-a", sys.executable, enabled=True, model="other-model"))
        with self.assertRaisesRegex(AdapterError, "example-model"):
            self.run_adapter(adapter)

    def test_provider_credential_name_must_be_allowlisted_and_present(self):
        with self.assertRaisesRegex(AdapterError, "not allowlisted"):
            self.run_adapter(_Trivial(self.config(provider_key_env="PATH")))
        with patch.dict(os.environ):
            os.environ.pop("PROVIDER_A_API_KEY", None)
            with self.assertRaisesRegex(AdapterError, "unavailable"):
                self.run_adapter(_Trivial(self.config(provider_key_env="PROVIDER_A_API_KEY")))

    def test_non_zero_exit_is_an_error_with_a_bounded_tail(self):
        class Failing(_Trivial):
            def argv(self):
                return ["-c", "import sys; print('y' * 5000); sys.exit(3)"]

        with self.assertRaises(AdapterError) as caught:
            self.run_adapter(Failing(self.config()))
        self.assertIn("exited 3", str(caught.exception))
        self.assertLess(len(str(caught.exception)), 2200)


class WorkerRefusalTests(unittest.TestCase):
    def run_refused(self, config, token="set"):
        env = {"HUB_WORKER_TOKEN": secrets.token_hex(8)} if token else {}
        with patch.dict(os.environ, env):
            if not token:
                os.environ.pop("HUB_WORKER_TOKEN", None)
            with patch.object(worker, "_request") as request:
                with self.assertRaises(RuntimeError):
                    worker.run_once(config)
                request.assert_not_called()

    def test_worker_refuses_before_any_broker_call_when_unconfigured(self):
        enabled = {"enabled": True, "allow_unverified_provider_cost": True}
        self.run_refused(enabled, token=None)
        self.run_refused({"enabled": False, "allow_unverified_provider_cost": True})
        self.run_refused({"enabled": True})
        self.run_refused({})


class WorkerTaskRootTests(unittest.TestCase):
    """A claimed task must never run outside the package's task root."""

    class Opener:
        def __init__(self, case):
            self.case = case

        def open(self, request, timeout=10):
            from urllib.error import HTTPError
            from urllib.parse import urlsplit
            parsed = urlsplit(request.full_url)
            response = self.case.client.request(request.method, parsed.path, content=request.data,
                                                headers=dict(request.header_items()))
            if response.status_code >= 400:
                raise HTTPError(request.full_url, response.status_code, response.text, response.headers, None)

            class Reply:
                content = response.content

                def read(self, size=-1):
                    return self.content

                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    return False
            return Reply()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.coordinator_token, self.worker_token = secrets.token_hex(16), secrets.token_hex(16)
        self.env = patch.dict(os.environ, {"HUB_COORDINATOR_TOKEN": self.coordinator_token,
                                           "HUB_WORKER_TOKENS": self.worker_token, "HUB_ENABLE_WORKERS": "1",
                                           "HUB_WORKER_TOKEN": self.worker_token,
                                           "HUB_BROKER_URL": "http://127.0.0.1:8765"})
        self.env.start()
        self.package = Path(self.tmp.name) / "package"
        self.package.mkdir()
        (Path(self.tmp.name) / "ws").mkdir()
        self.store = Store(Path(self.tmp.name) / "w.sqlite3", rate_limit=1000, allowed_workspaces=[self.tmp.name])
        self.client = TestClient(create_app(self.store))
        self.http = patch("urllib.request.build_opener", lambda *handlers: self.Opener(self))
        self.http.start()

    def tearDown(self):
        self.http.stop()
        self.store.close()
        self.env.stop()
        self.tmp.cleanup()

    def run_with_root(self, task_root, key):
        headers = {"Authorization": "Bearer " + self.coordinator_token}
        created = self.client.post("/v1/dispatch", headers=headers, json={
            "workspace": str(Path(self.tmp.name) / "ws"), "payload": {"adapter": "agent-b", "prompt": "hi"},
            "idempotency_key": key, "target_worker": "worker-1", "cost_reserved": 0.1, "timeout_seconds": 20}).json()
        self.client.post("/v1/approve/" + created["id"], headers=headers, json={"task_digest": created["task_digest"]})
        config = {"enabled": True, "allow_unverified_provider_cost": True, "cost_limit": 0.2, "lease_seconds": 9,
                  "task_root": task_root, "_package_root": str(self.package),
                  "adapters": {"agent-b": {"enabled": True, "use_native_profile": True}}}
        self.assertTrue(worker.run_once(config))
        return self.store.get_task(created["id"])

    def test_task_root_outside_the_package_fails_the_task_without_creating_it(self):
        elsewhere = Path(self.tmp.name) / "elsewhere"
        for index, root in enumerate((str(elsewhere), "../elsewhere")):
            with self.subTest(root=root):
                task = self.run_with_root(root, "escape-%d" % index)
                self.assertEqual(task["state"], "failed")
                self.assertIn("task_root", task["error"])
                self.assertFalse(elsewhere.exists())

    def test_zero_cost_reservation_fails_the_task_without_running_it(self):
        headers = {"Authorization": "Bearer " + self.coordinator_token}
        created = self.client.post("/v1/dispatch", headers=headers, json={
            "workspace": str(Path(self.tmp.name) / "ws"), "payload": {"adapter": "agent-b", "prompt": "hi"},
            "idempotency_key": "no-cost", "target_worker": "worker-1", "cost_reserved": 0.0,
            "timeout_seconds": 20}).json()
        self.client.post("/v1/approve/" + created["id"], headers=headers, json={"task_digest": created["task_digest"]})
        config = {"enabled": True, "allow_unverified_provider_cost": True, "cost_limit": 1.0,
                  "_package_root": str(self.package)}
        self.assertTrue(worker.run_once(config))
        task = self.store.get_task(created["id"])
        self.assertEqual(task["state"], "failed")
        self.assertIn("cost reservation", task["error"])


class RelayEnvelopeSizeTests(unittest.TestCase):
    def test_oversize_non_json_and_wrong_schema_bodies_are_refused(self):
        for body in ("{" + " " * 17000 + "}", "not json", "[]", json.dumps({"schema": "other/v9"}), "", None):
            with self.subTest(body=str(body)[:12]), self.assertRaises(RelayError):
                parse_envelope(body, allowed_targets={"worker-1"})


if __name__ == "__main__":
    unittest.main()
