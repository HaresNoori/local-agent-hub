"""Refusal and edge paths for the approval gate, leases and the emergency stop.

These complement test_store.py and test_api.py. They assert exact error codes and statuses so a
regression that changes a refusal into a different failure is caught.
"""
from __future__ import annotations

import os
import secrets
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from hub.api import create_app
from hub.drive_bridge import export_approved_task
from hub.store import HubError, Store


class StoreCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = Store(self.root / "broker.sqlite3", rate_limit=1000, allowed_workspaces=[self.root])
        self.workspace = str(self.root / "workspace")
        Path(self.workspace).mkdir()

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def dispatch(self, key="task-1", **kwargs):
        kwargs.setdefault("payload", {"prompt": "calculate"})
        return self.store.dispatch(workspace=self.workspace, idempotency_key=key, **kwargs)

    def approved(self, key="task-1", **kwargs):
        task = self.dispatch(key, **kwargs)
        return self.store.approve(task["id"], task_digest=task["task_digest"])

    def expire_lease(self, task_id):
        with closing(self.store._connect()) as c:
            c.execute("UPDATE tasks SET lease_until=0 WHERE id=?", (task_id,))

    def refusal(self, fn, *args, **kwargs):
        with self.assertRaises(HubError) as caught:
            fn(*args, **kwargs)
        return caught.exception


class ApprovalReplayAndMismatchTests(StoreCase):
    def test_second_approval_of_the_same_task_is_refused(self):
        task = self.dispatch()
        self.store.approve(task["id"], task_digest=task["task_digest"])
        error = self.refusal(self.store.approve, task["id"], task_digest=task["task_digest"])
        self.assertEqual((error.code, error.status), ("invalid_state", 409))

    def test_digest_from_another_task_does_not_approve(self):
        first = self.dispatch("first")
        second = self.dispatch("second", payload={"prompt": "different"})
        self.assertNotEqual(first["task_digest"], second["task_digest"])
        error = self.refusal(self.store.approve, first["id"], task_digest=second["task_digest"])
        self.assertEqual((error.code, error.status), ("digest_mismatch", 409))
        self.assertEqual(self.store.get_task(first["id"])["state"], "awaiting_approval")

    def test_digest_binds_limits_and_routing_not_only_the_prompt(self):
        base = self.dispatch("base")
        longer = self.dispatch("longer", timeout_seconds=301)
        routed = self.dispatch("routed", target_worker="worker-9")
        self.assertEqual(len({base["task_digest"], longer["task_digest"], routed["task_digest"]}), 3)
        error = self.refusal(self.store.approve, longer["id"], task_digest=base["task_digest"])
        self.assertEqual(error.code, "digest_mismatch")

    def test_cancelled_task_cannot_be_approved_afterwards(self):
        task = self.dispatch()
        self.store.cancel(task["id"])
        error = self.refusal(self.store.approve, task["id"], task_digest=task["task_digest"])
        self.assertEqual((error.code, error.status), ("invalid_state", 409))
        self.assertIsNone(self.store.claim("worker-1"))

    def test_unknown_task_is_not_found(self):
        error = self.refusal(self.store.approve, "no-such-task", task_digest="0" * 64)
        self.assertEqual((error.code, error.status), ("not_found", 404))


class UnapprovedWorkNeverReachesASinkTests(StoreCase):
    """Claim (c): each outward path refuses work that has no matching approval."""

    def test_unapproved_task_is_not_claimable_even_when_targeted_at_the_worker(self):
        self.dispatch(target_worker="worker-1")
        self.assertIsNone(self.store.claim("worker-1"))

    def test_drive_export_refuses_an_unapproved_task_and_writes_nothing(self):
        drive = self.root / "drive"
        for peer in ("agent-b", "agent-c"):
            (drive / "agents" / peer / "inbox").mkdir(parents=True)
        task = self.dispatch(payload={"prompt": "review", "title": "t"}, target_worker="drive:agent-c")
        error = self.refusal(export_approved_task, self.store, drive, task["id"])
        self.assertEqual(error.code, "invalid_state")
        self.assertEqual(list((drive / "agents" / "agent-c" / "inbox").iterdir()), [])
        self.assertEqual(self.store.get_task(task["id"])["state"], "awaiting_approval")

    def test_relay_outbox_item_is_not_claimable_until_its_digest_is_approved(self):
        with patch.dict(os.environ, {"HUB_RELAY_ALLOWED_SOURCES": "repo:1"}):
            task = self.dispatch(payload={"prompt": "review", "relay_destination": {"issue_number": 3}},
                                 relay_source="repo:1", relay_delivery_id="event:1",
                                 relay_payload_digest="a" * 64, relay_sender_id="sender:1")
            self.store.approve(task["id"], task_digest=task["task_digest"])
            claim = self.store.claim("worker-1")
            self.store.complete(task["id"], "worker-1", claim["lease_epoch"], result={"text": "done"})
            result = [o for o in self.store.list_outbox() if o["kind"] == "result"][0]
            self.assertEqual(result["state"], "awaiting_approval")
            self.assertIsNone(self.store.claim_outbox("relay"))
            wrong = self.refusal(self.store.approve_outbox, result["id"], "0" * 64)
            self.assertEqual((wrong.code, wrong.status), ("digest_mismatch", 409))
            self.assertIsNone(self.store.claim_outbox("relay"))
            self.store.approve_outbox(result["id"], result["approval_digest"])
            replay = self.refusal(self.store.approve_outbox, result["id"], result["approval_digest"])
            self.assertEqual(replay.code, "invalid_state")
            claimed = self.store.claim_outbox("relay")
            self.assertEqual(claimed["id"], result["id"])

    def test_relay_outbox_claim_refuses_when_no_source_is_allowlisted(self):
        with patch.dict(os.environ):
            os.environ.pop("HUB_RELAY_ALLOWED_SOURCES", None)
            error = self.refusal(self.store.claim_outbox, "relay")
        self.assertEqual((error.code, error.status), ("relay_source_forbidden", 403))


class LeaseExpiryTests(StoreCase):
    def test_heartbeat_on_an_expired_lease_is_refused_and_does_not_extend_it(self):
        self.approved()
        claim = self.store.claim("worker-1", 30)
        self.expire_lease(claim["id"])
        error = self.refusal(self.store.heartbeat, claim["id"], "worker-1", claim["lease_epoch"], 60)
        self.assertEqual((error.code, error.status), ("stale_lease", 409))
        self.assertLess(self.store.get_task(claim["id"])["lease_until"], time.time())

    def test_complete_on_an_expired_lease_is_refused_before_any_sweep(self):
        self.approved()
        claim = self.store.claim("worker-1", 30)
        self.expire_lease(claim["id"])
        error = self.refusal(self.store.complete, claim["id"], "worker-1", claim["lease_epoch"], result={})
        self.assertEqual(error.code, "stale_lease")
        self.assertEqual(self.store.get_task(claim["id"])["state"], "running")

    def test_next_claim_fences_the_expired_task_and_does_not_hand_it_on(self):
        first = self.approved("first")
        claim = self.store.claim("worker-1", 30)
        self.approved("second")
        self.expire_lease(first["id"])
        self.assertIsNone(self.store.claim("worker-2"))
        self.assertEqual(self.store.get_task(first["id"])["state"], "interrupted")
        self.assertEqual(self.store.get_task(first["id"])["lease_epoch"], claim["lease_epoch"] + 1)
        error = self.refusal(self.store.complete, first["id"], "worker-1", claim["lease_epoch"], result={})
        self.assertEqual(error.code, "stale_lease")

    def test_lease_length_is_clamped_to_five_through_three_hundred_seconds(self):
        self.approved("short")
        short = self.store.claim("worker-1", 0)
        self.assertTrue(4 <= short["lease_until"] - time.time() <= 6)
        self.store.complete(short["id"], "worker-1", short["lease_epoch"], result={})
        self.approved("long")
        long = self.store.claim("worker-1", 10 ** 9)
        self.assertTrue(295 <= long["lease_until"] - time.time() <= 301)

    def test_task_timeout_forces_cancellation_acknowledgement(self):
        task = self.approved(timeout_seconds=5)
        claim = self.store.claim("worker-1", 60)
        with closing(self.store._connect()) as c:
            c.execute("UPDATE tasks SET started_at=? WHERE id=?", (time.time() - 100, task["id"]))
        beat = self.store.heartbeat(task["id"], "worker-1", claim["lease_epoch"])
        self.assertTrue(beat["cancellation_requested"])
        error = self.refusal(self.store.complete, task["id"], "worker-1", claim["lease_epoch"], result={})
        self.assertEqual(error.code, "cancel_ack_required")
        done = self.store.complete(task["id"], "worker-1", claim["lease_epoch"], cancelled=True)
        self.assertEqual(done["state"], "cancelled")

    def test_cancellation_acknowledgement_without_a_pending_cancel_is_refused(self):
        self.approved()
        claim = self.store.claim("worker-1", 60)
        error = self.refusal(self.store.complete, claim["id"], "worker-1", claim["lease_epoch"], cancelled=True)
        self.assertEqual(error.code, "unexpected_cancel_ack")

    def test_another_worker_cannot_complete_a_running_task(self):
        self.approved()
        claim = self.store.claim("worker-1", 60)
        error = self.refusal(self.store.complete, claim["id"], "worker-2", claim["lease_epoch"], result={})
        self.assertEqual(error.code, "stale_lease")


class EmergencyStopTests(StoreCase):
    def test_stop_with_a_running_task_blocks_claims_and_demands_cancel_ack(self):
        queued = self.approved("queued")
        running_task = self.approved("running")
        claim = self.store.claim("worker-1", 60)
        self.assertIn(claim["id"], (queued["id"], running_task["id"]))
        self.store.emergency_stop(True)
        error = self.refusal(self.store.claim, "worker-2")
        self.assertEqual((error.code, error.status), ("emergency_stop", 423))
        beat = self.store.heartbeat(claim["id"], "worker-1", claim["lease_epoch"])
        self.assertTrue(beat["cancellation_requested"])
        error = self.refusal(self.store.complete, claim["id"], "worker-1", claim["lease_epoch"], result={})
        self.assertEqual(error.code, "cancel_ack_required")
        self.assertEqual(self.store.complete(claim["id"], "worker-1", claim["lease_epoch"],
                                             cancelled=True)["state"], "cancelled")

    def test_clearing_the_stop_does_not_resurrect_cancelled_work(self):
        task = self.approved()
        self.store.emergency_stop(True)
        self.assertEqual(self.store.get_task(task["id"])["state"], "cancelled")
        status = self.store.emergency_stop(False)
        self.assertFalse(status["emergency_stop"])
        self.assertEqual(self.store.get_task(task["id"])["state"], "cancelled")
        self.assertIsNone(self.store.claim("worker-1"))
        self.assertEqual(self.dispatch("after-stop")["state"], "awaiting_approval")

    def test_stop_releases_reserved_cost_of_cancelled_work(self):
        self.dispatch(cost_reserved=4.0)
        self.assertEqual(self.store.status()["reserved_cost"], 4.0)
        self.store.emergency_stop(True)
        self.assertEqual(self.store.status()["reserved_cost"], 0.0)

    def test_stop_survives_a_broker_restart(self):
        self.store.emergency_stop(True)
        self.store.close()
        self.store = Store(self.root / "broker.sqlite3", allowed_workspaces=[self.root])
        self.assertTrue(self.store.status()["emergency_stop"])
        error = self.refusal(self.dispatch, "blocked")
        self.assertEqual(error.code, "emergency_stop")


class EmergencyStopApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.coordinator_token = secrets.token_hex(16)
        self.worker_token = secrets.token_hex(16)
        self.env = patch.dict(os.environ, {"HUB_COORDINATOR_TOKEN": self.coordinator_token,
                                           "HUB_WORKER_TOKENS": self.worker_token, "HUB_ENABLE_WORKERS": "1"})
        self.env.start()
        self.store = Store(Path(self.tmp.name) / "api.sqlite3", rate_limit=1000, allowed_workspaces=[self.tmp.name])
        self.client = TestClient(create_app(self.store), raise_server_exceptions=False)
        self.coordinator = {"Authorization": "Bearer " + self.coordinator_token}
        self.worker = {"Authorization": "Bearer " + self.worker_token}
        (Path(self.tmp.name) / "ws").mkdir()
        self.body = {"workspace": str(Path(self.tmp.name) / "ws"), "payload": {"prompt": "x"},
                     "idempotency_key": "api-stop"}

    def tearDown(self):
        self.store.close()
        self.env.stop()
        self.tmp.cleanup()

    def test_dispatch_is_refused_with_423_while_stopped(self):
        stopped = self.client.post("/v1/emergency-stop", headers=self.coordinator)
        self.assertEqual(stopped.status_code, 200)
        self.assertTrue(stopped.json()["emergency_stop"])
        refused = self.client.post("/v1/dispatch", headers=self.coordinator, json=self.body)
        self.assertEqual(refused.status_code, 423)
        self.assertEqual(refused.json()["detail"]["error"], "emergency_stop")

    def test_worker_claim_never_succeeds_while_stopped(self):
        created = self.client.post("/v1/dispatch", headers=self.coordinator, json=self.body).json()
        self.client.post("/v1/approve/" + created["id"], headers=self.coordinator,
                         json={"task_digest": created["task_digest"]})
        self.client.post("/v1/emergency-stop", headers=self.coordinator)
        response = self.client.post("/v1/worker/claim", headers=self.worker, json={"lease_seconds": 30})
        self.assertEqual(response.status_code, 423)
        self.assertEqual(response.json()["detail"]["error"], "emergency_stop")
        self.assertNotEqual(self.store.get_task(created["id"])["state"], "running")

    def test_stop_can_be_cleared_and_dispatch_resumes(self):
        self.client.post("/v1/emergency-stop", headers=self.coordinator)
        cleared = self.client.post("/v1/emergency-stop?stopped=false", headers=self.coordinator)
        self.assertFalse(cleared.json()["emergency_stop"])
        self.assertEqual(self.client.post("/v1/dispatch", headers=self.coordinator, json=self.body).status_code, 200)


if __name__ == "__main__":
    unittest.main()
