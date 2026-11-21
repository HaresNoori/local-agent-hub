import json
import os
import tempfile
import unittest
from urllib.parse import urlsplit
from pathlib import Path

from hub.relay import CursorFile, GitHubRelay, RelayBrokerClient, RelayError, TransientRelayError, parse_envelope


TASK_ID = "12345678-1234-4234-8234-123456789abc"


class FakeGitHub:
    def __init__(self, comments=None): self.comments = comments or []; self.created = []; self.publisher_id = 444
    def get_authenticated_user(self): return {"id": self.publisher_id}
    def get_repo(self, owner, repo):
        return {"id": 987654, "private": True, "owner": {"login": owner}, "name": repo}
    def list_comments_since(self, owner, repo, since=None, page=1, per_page=100):
        return self.comments if page == 1 else []
    def comment_provenance(self, node_id):
        cid = int(node_id.removeprefix("node-"))
        event = next(c for c in self.comments + self.created if c["id"] == cid)
        edited = event["updated_at"] != event["created_at"]
        return {"database_id": cid, "body": event["body"], "author_id": event["user"]["id"],
                "author_type": "User",
                "last_edited_at": event["updated_at"] if edited else None,
                "editor_id": 222 if edited else None, "editor_type": "User" if edited else None, "issue_number": 7,
                "repository_id": 987654, "issue_type": "Issue", "author_type":"User"}
    def list_comments(self, owner, repo, issue_number, page=1, per_page=100): return []
    def create_comment(self, owner, repo, issue_number, body):
        cid = 100 + len(self.created)
        value = {"id":cid,"node_id":f"node-{cid}","body":body,"user":{"id":self.publisher_id},
            "html_url":f"https://github.com/{owner}/{repo}/issues/{issue_number}#issuecomment-{cid}",
            "issue_url":f"https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}",
            "created_at":"2026-10-20T12:00:00Z","updated_at":"2026-10-20T12:00:00Z"}
        self.created.append(value)
        return value


class FakeBroker:
    def __init__(self): self.calls = []
    def call(self, method, path, payload=None): self.calls.append((method, path, payload)); return {"task_id": TASK_ID}


class InProcessResponse:
    def __init__(self, response): self.body = response.content
    def __enter__(self): return self
    def __exit__(self, *args): return None
    def read(self, size=-1): return self.body if size < 0 else self.body[:size]


class InProcessOpener:
    def __init__(self, client): self.client = client
    def open(self, request, timeout):
        parsed = urlsplit(request.full_url)
        response = self.client.request(request.method, parsed.path + ("?" + parsed.query if parsed.query else ""),
            content=request.data, headers={"Authorization": request.get_header("Authorization"),
                                           "Content-Type": "application/json"})
        if response.status_code >= 400:
            from urllib.error import HTTPError
            raise HTTPError(request.full_url, response.status_code, "API error", response.headers, None)
        return InProcessResponse(response)


def envelope(**overrides):
    value = {"schema": "local-agent-hub/task-v1", "action": "dispatch", "workspace": "primary",
             "prompt": "Summarize this bounded material", "adapter": "agent-a", "target_worker": "worker-1",
             "priority": 0, "depends_on": [], "timeout_seconds": 120, "cost_reserved": 1.0}
    value.update(overrides)
    return json.dumps(value)


def comment(body, *, user_id=111, updated="2026-10-20T10:00:00Z", created="2026-10-20T10:00:00Z", cid=55):
    return {"id": cid, "node_id": f"node-{cid}", "body": body, "created_at": created, "updated_at": updated,
            "user": {"id": user_id}, "issue_url": "https://api.github.com/repos/account/agent-hub-execution-relay/issues/7"}


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["HUB_GITHUB_TOKEN"] = "gh-secret-test-value"
        self.config = {"enabled": True, "owner": "account", "repo": "agent-hub-execution-relay",
            "repository_id": 987654, "allowed_user_ids": [111], "allowed_targets": ["worker-1"],
            "workspace_aliases": {"primary": str(Path(self.tmp.name) / "workspace")},
            "github_token_env": "HUB_GITHUB_TOKEN", "initial_since_utc": "2026-10-19T00:00:00Z",
            "max_pages_per_poll": 3}
        self.github, self.broker = FakeGitHub([comment(envelope())]), FakeBroker()
        self.cursor = CursorFile(Path(self.tmp.name) / "cursor.json")
        self.relay = GitHubRelay(self.config, self.github, self.broker, self.cursor)

    def tearDown(self):
        os.environ.pop("HUB_GITHUB_TOKEN", None)
        self.tmp.cleanup()

    def test_valid_comment_queues_only_validated_fields_and_advances_cursor(self):
        result = self.relay.poll_once()
        self.assertEqual(result["accepted"], 1)
        method, path, body = self.broker.calls[0]
        self.assertEqual((method, path), ("POST", "/v1/relay/dispatch"))
        self.assertEqual(body["workspace"], self.config["workspace_aliases"]["primary"])
        self.assertEqual(body["payload"]["adapter"], "agent-a")
        self.assertEqual(body["relay_sender_id"], "111")
        self.assertNotIn("github-secret-test-value", json.dumps(body))
        self.assertEqual(self.cursor.read(), "2026-10-20T09:59:59Z")

    def test_private_repository_identity_and_author_edit_gates(self):
        self.github.get_repo = lambda owner, repo: {"id": 987654, "private": False, "owner": {"login": owner}, "name": repo}
        with self.assertRaises(RelayError): self.relay.poll_once()
        self.github.get_repo = lambda owner, repo: {"id": 987654, "private": True, "owner": {"login": owner}, "name": repo}
        self.github.comments = [comment(envelope(), updated="2026-10-20T10:01:00Z"), comment(envelope(), user_id=222, cid=56)]
        result = self.relay.poll_once()
        self.assertEqual(result["accepted"], 0)
        self.assertEqual(len(self.broker.calls), 0)

    def test_authorized_author_with_unauthorized_last_editor_is_rejected(self):
        self.github.comments = [comment(envelope())]
        self.github.comment_provenance = lambda node_id: {"database_id": 55, "body": envelope(),
            "author_id": 111, "repository_id": 987654, "issue_number": 7, "issue_type": "Issue",
            "last_edited_at": "2026-10-20T10:00:00Z", "editor_id": 222}
        result = self.relay.poll_once()
        self.assertEqual(result["accepted"], 0)
        self.assertEqual(len(self.broker.calls), 0)

    def test_strict_schema_rejects_shell_and_malformed_types(self):
        for overrides in ({"adapter": ["agent-a"]}, {"target_worker": {}}, {"priority": True},
                          {"timeout_seconds": float("inf")}, {"cost_reserved": float("nan")},
                          {"workspace": "C:\\temp"}, {"model": "untrusted-model"},
                          {"prompt": "run `powershell Remove-Item`"}):
            # Shell-like prose remains plain prompt text; forbidden routing/config fields fail closed.
            body = envelope(**overrides)
            if "model" in overrides:
                with self.assertRaises(RelayError): parse_envelope(body, allowed_targets={"worker-1"})
            elif "powershell" in overrides.get("prompt", ""):
                parsed = parse_envelope(body, allowed_targets={"worker-1"})
                self.assertEqual(parsed["prompt"], overrides["prompt"])
            else:
                with self.assertRaises(RelayError): parse_envelope(body, allowed_targets={"worker-1"})
        invalid = json.dumps({"schema": "local-agent-hub/task-v1", "action": "dispatch", "command": "whoami"})
        with self.assertRaises(RelayError): parse_envelope(invalid, allowed_targets={"worker-1"})

    def test_remote_cancel_is_scoped_and_cannot_approve(self):
        body = json.dumps({"schema": "local-agent-hub/task-v1", "action": "cancel", "task_id": TASK_ID})
        self.github.comments = [comment(body)]
        self.relay.poll_once()
        method, path, payload = self.broker.calls[0]
        self.assertEqual(path, f"/v1/relay/cancel/{TASK_ID}")
        self.assertEqual(payload["sender_id"], 111)
        self.assertNotIn("approve", path)

    def test_result_publish_uses_approved_outbox_marker_and_relay_identity(self):
        digest = "a" * 64
        item = {"id": "outbox-1", "source": "github:987654", "kind":"result", "task_id": TASK_ID, "approval_digest": digest,
                "lease_epoch": 3, "payload": {"task_id": TASK_ID, "task_digest": "b" * 64,
                "kind": "result", "source":"github:987654", "state": "completed", "result": {"text": "safe"}, "error": None,
                    "relay_destination": {"issue_number": 7}}}
        def call(method, path, payload=None):
            self.broker.calls.append((method,path,payload))
            if path.endswith("/claim"): return item
            if path.startswith("/v1/relay/tasks/"): return {"state":"completed"}
            if path.endswith("/heartbeat"): return {"allowed":True}
            return {}
        self.broker.call = call
        self.config["publisher_user_id"] = 444
        self.assertTrue(self.relay.publish_one())
        self.assertEqual(self.github.created[0]["id"], 100)
        self.assertIn("local-agent-hub-delivery:" + digest, self.github.created[0]["body"])
        method, path, complete = self.broker.calls[-1]
        self.assertEqual(path, "/v1/relay/outbox/complete")
        self.assertEqual(complete["outbox_id"], "outbox-1")
        self.assertEqual(complete["worker_id"], "relay")
        self.assertTrue(complete["delivered"])
        self.assertEqual(complete["receipt"]["comment_id"],100)
        self.assertEqual(complete["receipt"]["verification"],"github_graphql_readback")

    def test_retryable_broker_failure_preserves_cursor(self):
        from hub.relay import TransientRelayError
        self.broker.call = lambda *args, **kwargs: (_ for _ in ()).throw(TransientRelayError("temporary"))
        with self.assertRaises(TransientRelayError): self.relay.poll_once()
        self.assertIsNone(self.cursor.read_state())

    def test_page_cap_persists_continuation_without_advancing_timestamp(self):
        rows = [comment("invalid", user_id=999, cid=i + 1) for i in range(100)]
        def listing(owner, repo, since=None, page=1, per_page=100):
            return rows if page in (1, 2) else []
        self.github.list_comments_since = listing
        self.config["max_pages_per_poll"] = 1
        result = self.relay.poll_once()
        self.assertTrue(result["page_cap_reached"])
        self.assertEqual(self.cursor.read_state(), {"since":"2026-10-19T00:00:00Z", "page":2})

    def test_untrusted_marker_substring_cannot_suppress_exact_publish(self):
        digest = "c" * 64
        item = {"id":"outbox-2", "source":"github:987654", "kind":"status", "task_id":TASK_ID,
            "approval_digest":digest, "lease_epoch":4,
            "payload":{"kind":"status", "source":"github:987654", "task_id":TASK_ID, "task_digest":"d"*64,
                "state":"queued", "transition":"approved", "relay_destination":{"issue_number":7}}}
        self.config["publisher_user_id"] = 444
        self.github.list_comments = lambda *a, **k: ([{"id":88,"node_id":"node-88",
            "user":{"id":999},"body":"attacker copied <!-- local-agent-hub-delivery:"+digest+" -->"}] if k.get("page")==1 else [])
        self.broker.call = lambda method,path,payload=None: item if path.endswith("/claim") else (
            {"task":{"state":"queued"}} if path.startswith("/v1/relay/tasks/") else
            {"allowed":True} if path.endswith("/heartbeat") else {})
        self.assertTrue(self.relay.publish_one())
        self.assertEqual(len(self.github.created),1)
        self.assertIn("status update",self.github.created[0]["body"])

    def test_unverified_create_response_never_acks_delivery(self):
        item = {"id":"outbox-3", "source":"github:987654", "kind":"result", "task_id":TASK_ID,
            "approval_digest":"e"*64, "lease_epoch":5,
            "payload":{"kind":"result", "source":"github:987654", "task_id":TASK_ID,
                "state":"completed", "relay_destination":{"issue_number":7}}}
        self.config["publisher_user_id"] = 444
        def bad_create(owner, repo, issue_number, body):
            value = FakeGitHub.create_comment(self.github, owner, repo, issue_number, body)
            value["user"]["id"] = 999
            return value
        self.github.create_comment = bad_create
        self.broker.call = lambda method,path,payload=None: item if path.endswith("/claim") else (
            {"task":{"state":"completed"}} if path.startswith("/v1/relay/tasks/") else
            {"allowed":True} if path.endswith("/heartbeat") else self.broker.calls.append((method,path,payload)) or {})
        with self.assertRaises(TransientRelayError): self.relay.publish_one()
        self.assertFalse(any(call[1].endswith("/complete") and call[2].get("delivered") is True
                             for call in self.broker.calls))

    def test_wrong_authenticated_publisher_is_rejected_before_outbox_claim(self):
        self.config["publisher_user_id"] = 444
        self.github.publisher_id = 999
        with self.assertRaises(RelayError): self.relay.publish_one()
        self.assertEqual(self.broker.calls, [])

    def test_full_broker_contract_dispatch_approval_completion_and_publication(self):
        from fastapi.testclient import TestClient
        from hub.api import create_app
        from hub.store import Store
        os.environ.update({"HUB_COORDINATOR_TOKEN":"coord-test", "HUB_WORKER_TOKENS":"worker-test",
            "HUB_RELAY_TOKEN":"relay-test", "HUB_ENABLE_RELAY":"1", "HUB_ENABLE_WORKERS":"1",
            "HUB_RELAY_ALLOWED_SOURCES":"github:987654"})
        db = Path(self.tmp.name) / "integration.sqlite3"
        store = Store(db, allowed_workspaces=[self.tmp.name])
        client = TestClient(create_app(store))
        try:
            relay_broker = RelayBrokerClient("http://127.0.0.1:8765", "relay-test",
                                             opener=InProcessOpener(client))
            self.config["workspace_aliases"]["primary"] = self.tmp.name
            self.config["publisher_user_id"] = 444
            relay = GitHubRelay(self.config, self.github, relay_broker, self.cursor)
            self.assertEqual(relay.poll_once()["accepted"], 1)
            task = client.get("/v1/inbox?states=awaiting_approval", headers={"Authorization":"Bearer coord-test"}).json()[0]
            headers = {"Authorization":"Bearer coord-test"}
            self.assertEqual(client.post(f"/v1/approve/{task['id']}", headers=headers,
                json={"task_digest":task["task_digest"]}).status_code, 200)
            worker = {"Authorization":"Bearer worker-test"}
            claim = client.post("/v1/worker/claim", headers=worker, json={}).json()
            done = client.post("/v1/worker/complete", headers=worker, json={"task_id":task["id"],
                "worker_id":"worker-1", "lease_epoch":claim["lease_epoch"], "result":{"summary":"fixture result"}})
            self.assertEqual(done.status_code, 200)
            proposals = client.get("/v1/relay/outbox?state=awaiting_approval", headers=headers).json()
            result = next(row for row in proposals if row["kind"] == "result")
            self.assertEqual(client.post(f"/v1/relay/outbox/{result['id']}/approve", headers=headers,
                json={"approval_digest":result["approval_digest"]}).status_code, 200)
            self.assertTrue(relay.publish_one())
            delivered = store.get_outbox(result["id"])
            self.assertEqual(delivered["state"], "delivered")
            self.assertEqual(delivered["receipt"]["verification"], "github_graphql_readback")
            self.assertEqual(delivered["receipt"]["comment_id"], 100)
            self.assertEqual(self.github.created[0]["id"], 100)
        finally:
            client.close()
            store.close()


if __name__ == "__main__": unittest.main()
