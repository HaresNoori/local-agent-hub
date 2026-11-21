"""API tests run when FastAPI and its test client are available."""
import os
import uuid
import json
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

try:
    from fastapi.testclient import TestClient
    from hub.api import create_app
    from hub.drive_bridge import canonical, request_digest
    from hub.store import Store
except ImportError as exc:  # keep dependency absence explicit without installing packages
    TestClient = None
    IMPORT_ERROR = str(exc)
else:
    IMPORT_ERROR = None


import secrets as _secrets

COORD_TOKEN = _secrets.token_hex(16)  # generated per run; never a real credential
WORKER_TOKEN = _secrets.token_hex(16)  # generated per run; never a real credential


@unittest.skipIf(TestClient is None, "FastAPI test dependencies unavailable: " + str(IMPORT_ERROR))
class ApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["HUB_COORDINATOR_TOKEN"] = COORD_TOKEN
        os.environ["HUB_WORKER_TOKENS"] = WORKER_TOKEN
        os.environ["HUB_ENABLE_WORKERS"] = "0"
        os.environ.pop("HUB_ENABLE_RELAY", None)
        os.environ.pop("HUB_RELAY_TOKEN", None)
        os.environ.pop("HUB_RELAY_ALLOWED_SOURCES", None)
        os.environ.pop("HUB_ENABLE_DRIVE", None)
        os.environ.pop("HUB_DRIVE_ROOT", None)
        os.environ.pop("HUB_DRIVE_WORKSPACE", None)
        self.client = TestClient(create_app(Store(Path(self.tmp.name) / "api.sqlite3", allowed_workspaces=[self.tmp.name])))
        self.coordinator = {"Authorization":"Bearer " + COORD_TOKEN}
        self.worker = {"Authorization":"Bearer " + WORKER_TOKEN}

    def tearDown(self):
        self.client.app.state.store.close()
        self.tmp.cleanup()
        for key in ("HUB_COORDINATOR_TOKEN","HUB_WORKER_TOKENS","HUB_ENABLE_WORKERS","HUB_ENABLE_RELAY","HUB_RELAY_TOKEN","HUB_RELAY_ALLOWED_SOURCES","HUB_ENABLE_DRIVE","HUB_DRIVE_ROOT","HUB_DRIVE_WORKSPACE"):
            os.environ.pop(key, None)

    def test_auth_roles_and_approval_digest(self):
        self.assertEqual(self.client.get("/v1/status").status_code, 401)
        self.assertEqual(self.client.get("/v1/status", headers=self.worker).status_code, 403)
        response = self.client.post("/v1/dispatch", headers=self.coordinator, json={
            "workspace":self.tmp.name,"payload":{"task":"review"},"idempotency_key":"api-one"})
        self.assertEqual(response.status_code, 200)
        task = response.json()
        self.assertEqual(task["state"], "awaiting_approval")
        self.assertEqual(self.client.post(f"/v1/approve/{task['id']}",headers=self.worker,json={"task_digest":task["task_digest"]}).status_code, 403)
        approved = self.client.post(f"/v1/approve/{task['id']}",headers=self.coordinator,json={"task_digest":task["task_digest"]})
        self.assertEqual(approved.json()["state"], "queued")
        self.assertEqual(self.client.post("/v1/worker/claim",headers=self.worker,json={"worker_id":"worker-1"}).status_code, 423)

    def test_worker_identity_is_token_bound_and_targeted(self):
        response = self.client.post("/v1/dispatch", headers=self.coordinator, json={
            "workspace":self.tmp.name,"payload":{"task":"targeted"},"idempotency_key":"targeted",
            "target_worker":"worker-1"})
        task = response.json()
        self.client.post(f"/v1/approve/{task['id']}",headers=self.coordinator,json={"task_digest":task["task_digest"]})
        os.environ["HUB_ENABLE_WORKERS"] = "1"
        claimed = self.client.post("/v1/worker/claim",headers=self.worker,json={"worker_id":"impostor"})
        self.assertEqual(claimed.status_code, 200)
        self.assertEqual(claimed.json()["worker_id"], "worker-1")
        fenced = self.client.post("/v1/worker/heartbeat",headers=self.worker,json={
            "task_id":task["id"],"worker_id":"impostor","lease_epoch":claimed.json()["lease_epoch"]})
        self.assertEqual(fenced.status_code, 403)

    def test_status_and_logs_return_redacted_result(self):
        response = self.client.post("/v1/dispatch", headers=self.coordinator, json={
            "workspace":self.tmp.name,"payload":{"task":"log me"},"idempotency_key":"log-task"})
        task = response.json()
        self.client.post(f"/v1/approve/{task['id']}",headers=self.coordinator,json={"task_digest":task["task_digest"]})
        os.environ["HUB_ENABLE_WORKERS"] = "1"
        claim = self.client.post("/v1/worker/claim",headers=self.worker,json={})
        finished = self.client.post("/v1/worker/complete",headers=self.worker,json={
            "task_id":task["id"],"worker_id":"worker-1","lease_epoch":claim.json()["lease_epoch"],
            "result":{"echo":COORD_TOKEN}})
        self.assertEqual(finished.json()["state"], "completed")
        status = self.client.get(f"/v1/status/{task['id']}",headers=self.coordinator)
        logs = self.client.get(f"/v1/logs/{task['id']}",headers=self.coordinator)
        self.assertEqual(status.json()["result"]["echo"], "[REDACTED]")
        self.assertNotIn(COORD_TOKEN, logs.text)

    def test_inbox_active_state_filter_and_offset(self):
        for key in ("inbox-a","inbox-b","inbox-c"):
            self.client.post("/v1/dispatch",headers=self.coordinator,json={"workspace":self.tmp.name,"payload":{"x":key},"idempotency_key":key})
        page=self.client.get("/v1/inbox?states=awaiting_approval&limit=1&offset=1",headers=self.coordinator)
        self.assertEqual(page.status_code,200)
        self.assertEqual(len(page.json()),1)
        invalid=self.client.get("/v1/inbox?states=unknown",headers=self.coordinator)
        self.assertEqual(invalid.status_code,400)

    def test_relay_role_is_disabled_by_default_and_cannot_approve(self):
        os.environ["HUB_RELAY_TOKEN"]="relay-test-token"
        denied=self.client.post("/v1/relay/dispatch",headers={"Authorization":"Bearer relay-test-token"},json={})
        self.assertEqual(denied.status_code,401)
        os.environ["HUB_ENABLE_RELAY"]="1"
        os.environ["HUB_RELAY_ALLOWED_SOURCES"]="repo:3"
        relay={"Authorization":"Bearer relay-test-token"}
        task=self.client.post("/v1/relay/dispatch",headers=relay,json={
            "workspace":self.tmp.name,"payload":{"instruction":"untrusted","relay_destination":{"issue_number":3}},
            "idempotency_key":"relay-api","relay_source":"repo:3","relay_delivery_id":"event:3",
            "relay_payload_digest":"d"*64,"relay_sender_id":"sender:3"})
        self.assertEqual(task.status_code,200)
        self.assertEqual(task.json()["state"],"awaiting_approval")
        self.assertEqual(self.client.post(f"/v1/approve/{task.json()['id']}",headers=relay,
            json={"task_digest":task.json()["task_digest"]}).status_code,403)

    def test_relay_outbox_heartbeat_is_fenced_and_checks_emergency_stop(self):
        os.environ.update({"HUB_ENABLE_RELAY":"1","HUB_RELAY_TOKEN":"relay-test-token",
                           "HUB_RELAY_ALLOWED_SOURCES":"repo:heartbeat","HUB_ENABLE_WORKERS":"1"})
        relay={"Authorization":"Bearer relay-test-token"}
        task=self.client.post("/v1/relay/dispatch",headers=relay,json={
            "workspace":self.tmp.name,"payload":{"prompt":"review","relay_destination":{"issue_number":7}},
            "idempotency_key":"relay-heartbeat-api","relay_source":"repo:heartbeat",
            "relay_delivery_id":"event:heartbeat","relay_payload_digest":"f"*64,"relay_sender_id":"sender:7"})
        self.assertEqual(task.status_code,200)
        self.client.post(f"/v1/approve/{task.json()['id']}",headers=self.coordinator,
                         json={"task_digest":task.json()["task_digest"]})
        worker=self.client.post("/v1/worker/claim",headers=self.worker,json={})
        self.client.post("/v1/worker/complete",headers=self.worker,json={"task_id":task.json()["id"],
            "worker_id":"worker-1","lease_epoch":worker.json()["lease_epoch"],"result":{"done":True}})
        proposals=self.client.get("/v1/relay/outbox?state=awaiting_approval",headers=self.coordinator).json()
        result=next(item for item in proposals if item["kind"]=="result")
        self.client.post(f"/v1/relay/outbox/{result['id']}/approve",headers=self.coordinator,
                         json={"approval_digest":result["approval_digest"]})
        claim=self.client.post("/v1/relay/outbox/claim",headers=relay,json={"lease_seconds":60})
        body={"outbox_id":claim.json()["id"],"worker_id":"relay","lease_epoch":claim.json()["lease_epoch"]}
        self.assertEqual(self.client.post("/v1/relay/outbox/heartbeat",headers=relay,json=body).status_code,200)
        spoof=dict(body,worker_id="forged")
        self.assertEqual(self.client.post("/v1/relay/outbox/heartbeat",headers=relay,json=spoof).status_code,403)
        self.client.post("/v1/emergency-stop",headers=self.coordinator)
        self.assertEqual(self.client.post("/v1/relay/outbox/heartbeat",headers=relay,json=body).status_code,423)
        with closing(self.client.app.state.store._connect()) as c:
            c.execute("UPDATE relay_outbox SET lease_until=0 WHERE id=?",(body["outbox_id"],))
        self.client.app.state.store.recover_expired_leases()
        abandon={"approval_digest":result["approval_digest"],"publication_checked":True,
                 "evidence_note":"I checked the issue; publication outcome remains unknown."}
        route=f"/v1/relay/outbox/{body['outbox_id']}/abandon"
        self.assertEqual(self.client.post(route,headers=self.worker,json=abandon).status_code,403)
        self.assertEqual(self.client.post(route,headers=relay,json=abandon).status_code,403)
        self.assertEqual(self.client.post(route,headers=self.coordinator,json=dict(abandon,publication_checked=False)).status_code,400)
        abandoned=self.client.post(route,headers=self.coordinator,json=abandon)
        self.assertEqual(abandoned.status_code,200)
        self.assertEqual(abandoned.json()["state"],"abandoned")
        self.assertEqual(abandoned.json()["error"]["outcome"],"unknown")

    def test_interrupted_reconciliation_is_coordinator_only_and_cancel_only(self):
        os.environ.update({"HUB_ENABLE_RELAY":"1","HUB_RELAY_TOKEN":"relay-test-token"})
        task=self.client.post("/v1/dispatch",headers=self.coordinator,json={"workspace":self.tmp.name,
            "payload":{"work":"interrupted"},"idempotency_key":"reconcile-api","cost_reserved":2}).json()
        with closing(self.client.app.state.store._connect()) as c:
            c.execute("UPDATE tasks SET state='interrupted',worker_id='worker-1',lease_epoch=7 WHERE id=?",(task["id"],))
        body={"task_digest":task["task_digest"],"process_termination_confirmed":True,
              "evidence_note":"Operator observed worker exit."}
        self.assertEqual(self.client.post(f"/v1/reconcile/{task['id']}",headers=self.worker,json=body).status_code,403)
        relay={"Authorization":"Bearer relay-test-token"}
        self.assertEqual(self.client.post(f"/v1/reconcile/{task['id']}",headers=relay,json=body).status_code,403)
        false_body=dict(body,process_termination_confirmed=False)
        self.assertEqual(self.client.post(f"/v1/reconcile/{task['id']}",headers=self.coordinator,json=false_body).status_code,400)
        coerced_body=dict(body,process_termination_confirmed=1)
        self.assertEqual(self.client.post(f"/v1/reconcile/{task['id']}",headers=self.coordinator,json=coerced_body).status_code,422)
        wrong_digest=dict(body,task_digest="wrong")
        self.assertEqual(self.client.post(f"/v1/reconcile/{task['id']}",headers=self.coordinator,json=wrong_digest).status_code,409)
        response=self.client.post(f"/v1/reconcile/{task['id']}",headers=self.coordinator,json=body)
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json()["state"],"cancelled")

    def test_drive_is_disabled_by_default_then_imports_without_promoting(self):
        self.assertEqual(self.client.get("/v1/drive/status",headers=self.coordinator).status_code,423)
        root=Path(self.tmp.name)/"drive"
        outbox=root/"agents"/"agent-c"/"outbox"
        inbox=root/"agents"/"agent-c"/"inbox"
        outbox.mkdir(parents=True); inbox.mkdir(parents=True)
        (root/"agents"/"agent-b"/"outbox").mkdir(parents=True)
        (root/"agents"/"agent-b"/"inbox").mkdir(parents=True)
        message={"schema_version":1,"id":str(uuid.uuid4()),"thread":"drive-api-thread","from":"agent-c",
            "to":"agent-a","task":"Review request","content":"Untrusted peer content",
            "created_at":datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),
            "limits":{"max_seconds":60,"max_output_chars":1000}}
        message["request_digest"]=request_digest(message)
        (outbox/(message["id"]+".json")).write_bytes(canonical(message))
        os.environ.update({"HUB_ENABLE_DRIVE":"1","HUB_DRIVE_ROOT":str(root),"HUB_DRIVE_WORKSPACE":self.tmp.name})
        synced=self.client.post("/v1/drive/sync",headers=self.coordinator,json={"limit":20})
        self.assertEqual(synced.status_code,200)
        self.assertEqual(synced.json()["execution_started"],False)
        status=self.client.get("/v1/drive/status",headers=self.coordinator)
        self.assertEqual(status.json()["polling"],False)
        messages=self.client.get("/v1/drive/messages?thread_id=drive-api-thread",headers=self.coordinator)
        self.assertEqual(messages.status_code,200)
        self.assertEqual(messages.json()[0]["state"],"received")
        self.assertEqual(self.client.post(f"/v1/drive/promote/{message['id']}",headers=self.coordinator,json={
            "request_digest":"0"*64,"target_worker":"drive:agent-c","cost_reserved":0.1}).status_code,409)
        promoted=self.client.post(f"/v1/drive/promote/{message['id']}",headers=self.coordinator,json={
            "request_digest":messages.json()[0]["message_digest"],"target_worker":"drive:agent-c","cost_reserved":0.1})
        self.assertEqual(promoted.status_code,200)
        self.assertEqual(promoted.json()["state"],"awaiting_approval")
        self.assertEqual(self.client.post(f"/v1/approve/{promoted.json()['id']}",headers=self.worker,
            json={"task_digest":promoted.json()["task_digest"]}).status_code,403)
        outbound=self.client.post("/v1/dispatch",headers=self.coordinator,json={"workspace":self.tmp.name,
            "payload":{"prompt":"Approved bounded review","title":"Review"},"idempotency_key":"drive-api-out",
            "target_worker":"drive:agent-c"}).json()
        self.client.post(f"/v1/approve/{outbound['id']}",headers=self.coordinator,
            json={"task_digest":outbound["task_digest"]})
        exported=self.client.post(f"/v1/drive/export/{outbound['id']}",headers=self.coordinator)
        self.assertEqual(exported.status_code,200)
        self.assertEqual(exported.json()["pickup"],"unknown")
        state=self.client.get(f"/v1/drive/status/{outbound['id']}",headers=self.coordinator)
        self.assertEqual(state.json()["state"],"running")
        self.assertEqual(state.json()["external_peer"]["pickup"],"unknown")


if __name__ == "__main__": unittest.main()
