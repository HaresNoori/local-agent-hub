import tempfile
import unittest
import os
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from pathlib import Path

from hub.store import HubError, Store


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = Store(self.root / "broker.sqlite3", max_depth=5, cost_limit=10, allowed_workspaces=[self.root])
        self.workspace = str(self.root / "workspace")
        Path(self.workspace).mkdir()

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def dispatch(self, **kwargs):
        return self.store.dispatch(workspace=self.workspace, payload={"instruction":"calculate"},
                                   idempotency_key="one", **kwargs)

    def test_approval_fencing_and_completion(self):
        task = self.dispatch()
        self.assertEqual(task["state"], "awaiting_approval")
        self.assertIsNone(self.store.claim("w1"))
        queued = self.store.approve(task["id"], task_digest=task["task_digest"])
        self.assertEqual(queued["state"], "queued")
        claimed = self.store.claim("w1", 30)
        self.assertEqual(claimed["state"], "running")
        with self.assertRaises(HubError):
            self.store.heartbeat(task["id"], "w1", claimed["lease_epoch"] - 1)
        done = self.store.complete(task["id"], "w1", claimed["lease_epoch"], result={"answer":42})
        self.assertEqual(done["state"], "completed")
        self.assertEqual(done["result"], {"answer":42})

    def test_idempotency_conflict_and_redaction(self):
        task = self.store.dispatch(workspace=self.workspace, payload={"api_key":"secret-value", "text":"Bearer abcdefghijklmnop"}, idempotency_key="x")
        self.assertEqual(task["payload"]["api_key"], "[REDACTED]")
        same = self.store.dispatch(workspace=self.workspace, payload={"api_key":"secret-value", "text":"Bearer abcdefghijklmnop"}, idempotency_key="x")
        self.assertEqual(same["id"], task["id"])
        with self.assertRaises(HubError) as ctx:
            self.store.dispatch(workspace=self.workspace, payload={"different":True}, idempotency_key="x")
        self.assertEqual(ctx.exception.code, "idempotency_conflict")

    def test_root_idempotency_replay_preserves_explicit_thread_and_correlation(self):
        original = self.store.dispatch(workspace=self.workspace, payload={"same":True},
            idempotency_key="explicit-root", thread_id="chosen-thread", correlation_id="chosen-correlation")
        replay = self.store.dispatch(workspace=self.workspace, payload={"same":True},
            idempotency_key="explicit-root", thread_id="chosen-thread", correlation_id="chosen-correlation")
        self.assertEqual(replay["id"], original["id"])
        for override in ({"thread_id":"other-thread"}, {"correlation_id":"other-correlation"}):
            with self.assertRaises(HubError) as ctx:
                self.store.dispatch(workspace=self.workspace, payload={"same":True},
                    idempotency_key="explicit-root", **override)
            self.assertEqual(ctx.exception.code, "idempotency_conflict")

    def test_known_bearer_tokens_are_redacted_from_outputs(self):
        original = os.environ.get("HUB_COORDINATOR_TOKEN")
        os.environ["HUB_COORDINATOR_TOKEN"] = "coordinator-secret-test-value"
        try:
            task = self.store.dispatch(workspace=self.workspace,
                payload={"echo":"coordinator-secret-test-value"}, idempotency_key="known-token")
            self.assertNotIn("coordinator-secret-test-value", str(task))
        finally:
            if original is None: os.environ.pop("HUB_COORDINATOR_TOKEN", None)
            else: os.environ["HUB_COORDINATOR_TOKEN"] = original

    def test_restart_marks_running_interrupted_without_retry(self):
        task = self.dispatch()
        waiting = self.store.dispatch(workspace=self.workspace, payload={"instruction":"wait"}, idempotency_key="waiting")
        self.store.approve(task["id"], task_digest=task["task_digest"])
        self.store.approve(waiting["id"], task_digest=waiting["task_digest"])
        claimed = self.store.claim("w1")
        self.store.close()
        reopened = Store(self.root / "broker.sqlite3", allowed_workspaces=[self.root])
        recovered = reopened.get_task(task["id"])
        self.assertEqual(recovered["state"], "interrupted")
        self.assertIsNone(reopened.claim("w2"), "interrupted work holds workspace until review")
        with self.assertRaises(HubError):
            reopened.complete(task["id"], "w1", claimed["lease_epoch"], result={})
        reopened.close()

    def test_interrupted_task_reconciliation_requires_confirmation_and_frees_workspace(self):
        first=self.store.dispatch(workspace=self.workspace,payload={"n":1},idempotency_key="reconcile-first",cost_reserved=3)
        second=self.store.dispatch(workspace=self.workspace,payload={"n":2},idempotency_key="reconcile-second")
        for task in (first,second): self.store.approve(task["id"],task_digest=task["task_digest"])
        claimed=self.store.claim("worker")
        with closing(self.store._connect()) as c: c.execute("UPDATE tasks SET lease_until=0 WHERE id=?",(first["id"],))
        self.store.recover_expired_leases()
        self.assertIsNone(self.store.claim("worker-2"))
        for kwargs in (
            {"task_digest":"wrong","process_termination_confirmed":True,"evidence_note":"process stopped"},
            {"task_digest":first["task_digest"],"process_termination_confirmed":False,"evidence_note":"process stopped"},
            {"task_digest":first["task_digest"],"process_termination_confirmed":True,"evidence_note":"  "},
        ):
            with self.assertRaises(HubError): self.store.reconcile_interrupted(first["id"],**kwargs)
        reconciled=self.store.reconcile_interrupted(first["id"],task_digest=first["task_digest"],
            process_termination_confirmed=True,evidence_note="Operator observed the worker process stopped.")
        self.assertEqual(reconciled["state"],"cancelled")
        self.assertEqual(self.store.claim("worker-2")["id"],second["id"])
        self.assertEqual(self.store.logs(first["id"])[-1]["event"],"reconciled_cancelled_after_user_confirmation")
        with self.assertRaises(HubError): self.store.complete(first["id"],"worker",claimed["lease_epoch"],result={"should":"not complete"})

    def test_interrupted_outbox_can_only_be_abandoned_as_unknown(self):
        old_sources=os.environ.get("HUB_RELAY_ALLOWED_SOURCES")
        os.environ["HUB_RELAY_ALLOWED_SOURCES"]="repo:abandon"
        try:
            task=self.store.dispatch(workspace=self.workspace,payload={"relay_destination":{"issue_number":8}},idempotency_key="abandon-outbox",
                relay_source="repo:abandon",relay_delivery_id="event:abandon",relay_payload_digest="9"*64,relay_sender_id="sender:8")
            self.store.approve(task["id"],task_digest=task["task_digest"])
            worker=self.store.claim("worker")
            self.store.complete(task["id"],"worker",worker["lease_epoch"],result={"answer":"done"})
            out=next(item for item in self.store.list_outbox() if item["kind"]=="result")
            self.store.approve_outbox(out["id"],out["approval_digest"])
            delivery=self.store.claim_outbox("relay")
            with closing(self.store._connect()) as c: c.execute("UPDATE relay_outbox SET lease_until=0 WHERE id=?",(delivery["id"],))
            self.store.recover_expired_leases()
            with self.assertRaises(HubError):
                self.store.abandon_interrupted_outbox(out["id"],approval_digest=out["approval_digest"],publication_checked=False,evidence_note="checked")
            abandoned=self.store.abandon_interrupted_outbox(out["id"],approval_digest=out["approval_digest"],
                publication_checked=True,evidence_note="I checked the destination; delivery remains unknown.")
            self.assertEqual(abandoned["state"],"abandoned")
            self.assertEqual(abandoned["error"]["outcome"],"unknown")
            self.assertIsNone(self.store.claim_outbox("relay"))
        finally:
            if old_sources is None: os.environ.pop("HUB_RELAY_ALLOWED_SOURCES",None)
            else: os.environ["HUB_RELAY_ALLOWED_SOURCES"]=old_sources

    def test_expired_lease_is_interrupted_not_requeued(self):
        task = self.dispatch()
        self.store.approve(task["id"], task_digest=task["task_digest"])
        claimed = self.store.claim("w1", 5)
        with closing(self.store._connect()) as c:
            c.execute("UPDATE tasks SET lease_until=0 WHERE id=?", (task["id"],))
        self.assertEqual(self.store.recover_expired_leases(), 1)
        self.assertEqual(self.store.get_task(task["id"])["state"], "interrupted")
        self.assertIsNone(self.store.claim("w2"))
        with self.assertRaises(HubError):
            self.store.complete(task["id"], "w1", claimed["lease_epoch"], result={})

    def test_approval_digest_and_cost_limit(self):
        task = self.dispatch(cost_reserved=4)
        with self.assertRaises(HubError): self.store.approve(task["id"], task_digest="bad")
        with self.assertRaises(HubError):
            self.store.dispatch(workspace=self.workspace, payload={}, idempotency_key="two", cost_reserved=7)

    def test_emergency_stop_cancels_unstarted_and_blocks_dispatch(self):
        task = self.dispatch()
        self.store.emergency_stop(True)
        self.assertEqual(self.store.get_task(task["id"])["state"], "cancelled")
        with self.assertRaises(HubError):
            self.store.dispatch(workspace=self.workspace, payload={}, idempotency_key="two")

    def test_workspace_registration_is_unique(self):
        self.store.register_workspace(self.workspace)
        other = Store(self.root / "other.sqlite3", allowed_workspaces=[self.root])
        with self.assertRaises(HubError): other.register_workspace(self.workspace)
        other.close()

    def test_target_routing_and_running_cancel_ack(self):
        task = self.store.dispatch(workspace=self.workspace, payload={"instruction":"work"},
                                   idempotency_key="routed", target_worker="worker-1")
        self.store.approve(task["id"], task_digest=task["task_digest"])
        self.assertIsNone(self.store.claim("worker-2"))
        claim = self.store.claim("worker-1")
        self.store.cancel(task["id"])
        self.assertTrue(self.store.heartbeat(task["id"], "worker-1", claim["lease_epoch"])["cancellation_requested"])
        with self.assertRaises(HubError):
            self.store.complete(task["id"], "worker-1", claim["lease_epoch"], result={})
        cancelled = self.store.complete(task["id"], "worker-1", claim["lease_epoch"], cancelled=True)
        self.assertEqual(cancelled["state"], "cancelled")

    def test_concurrent_claim_has_one_owner(self):
        task = self.dispatch()
        self.store.approve(task["id"], task_digest=task["task_digest"])
        barrier = Barrier(2)
        def attempt(worker):
            barrier.wait()
            return self.store.claim(worker)
        with ThreadPoolExecutor(max_workers=2) as pool:
            claims = list(pool.map(attempt, ("worker-a", "worker-b")))
        owned = [claim for claim in claims if claim is not None]
        self.assertEqual(len(owned), 1)

    def test_one_running_or_interrupted_task_holds_workspace_claims(self):
        first = self.store.dispatch(workspace=self.workspace,payload={"n":1},idempotency_key="serial-1")
        second = self.store.dispatch(workspace=self.workspace,payload={"n":2},idempotency_key="serial-2")
        for task in (first, second):
            self.store.approve(task["id"], task_digest=task["task_digest"])
        claim = self.store.claim("w1")
        self.assertEqual(claim["id"], first["id"])
        self.assertIsNone(self.store.claim("w2"))
        self.store.complete(first["id"], "w1", claim["lease_epoch"], result={"done":True})
        next_claim = self.store.claim("w2")
        self.assertEqual(next_claim["id"], second["id"])

    def test_queue_bound_and_nonfinite_cost_rejected(self):
        self.store.max_depth = 1
        self.dispatch()
        with self.assertRaises(HubError):
            self.store.dispatch(workspace=self.workspace, payload={}, idempotency_key="overflow")
        for value in (float("nan"), float("inf")):
            with self.assertRaises(HubError):
                self.store.dispatch(workspace=self.workspace, payload={}, idempotency_key=str(value), cost_reserved=value)

    def test_lineage_is_bound_to_parent_thread_and_hop_limit(self):
        self.store.max_hops = 1
        root = self.dispatch()
        self.assertEqual(root["depth"], 0)
        child = self.store.dispatch(workspace=self.workspace, payload={"instruction":"child"},
                                    idempotency_key="child", parent_task_id=root["id"])
        self.assertEqual(child["depth"], 1)
        self.assertEqual(child["thread_id"], root["thread_id"])
        with self.assertRaises(HubError) as ctx:
            self.store.dispatch(workspace=self.workspace, payload={}, idempotency_key="grandchild",
                                parent_task_id=child["id"])
        self.assertEqual(ctx.exception.code, "hop_limit")
        with self.assertRaises(HubError):
            self.store.dispatch(workspace=self.workspace, payload={}, idempotency_key="unlinked",
                                thread_id=root["thread_id"])

    def test_different_workspaces_can_have_independent_claims(self):
        other_workspace = self.root / "workspace-two"
        other_workspace.mkdir()
        first = self.store.dispatch(workspace=self.workspace, payload={"w":1}, idempotency_key="other-ws-1")
        second = self.store.dispatch(workspace=other_workspace, payload={"w":2}, idempotency_key="other-ws-2")
        for task in (first,second): self.store.approve(task["id"],task_digest=task["task_digest"])
        a = self.store.claim("w1")
        b = self.store.claim("w2")
        self.assertNotEqual(a["workspace"], b["workspace"])

    def test_priority_dependencies_and_blocking(self):
        base=self.store.dispatch(workspace=self.workspace,payload={"base":1},idempotency_key="dep-base")
        dependent=self.store.dispatch(workspace=self.workspace,payload={"dependent":1},idempotency_key="dep-child",
            priority=100,depends_on=[base["id"]])
        ready=self.store.dispatch(workspace=self.workspace,payload={"ready":1},idempotency_key="priority-ready",priority=5)
        for task in (base,dependent,ready): self.store.approve(task["id"],task_digest=task["task_digest"])
        self.assertEqual(self.store.claim("w1")["id"],ready["id"],"blocked high-priority task must not starve ready work")

    def test_failed_dependency_is_blocked_and_never_claimed(self):
        base=self.store.dispatch(workspace=self.workspace,payload={"base":1},idempotency_key="failed-base")
        dependent=self.store.dispatch(workspace=self.workspace,payload={"dependent":1},idempotency_key="failed-child",depends_on=[base["id"]])
        self.store.approve(base["id"],task_digest=base["task_digest"])
        self.store.approve(dependent["id"],task_digest=dependent["task_digest"])
        claim=self.store.claim("w1")
        self.store.complete(base["id"],"w1",claim["lease_epoch"],error={"failed":True})
        view=next(x for x in self.store.inbox() if x["id"]==dependent["id"])
        self.assertEqual(view["dependency_state"],"blocked")
        self.assertEqual(view["blocked_by"],[base["id"]])
        self.assertIsNone(self.store.claim("w2"))

    def test_priority_order_and_inbox_filters_pagination(self):
        tasks=[]
        for key,priority in (("low",-1),("high",10),("middle",2)):
            task=self.store.dispatch(workspace=self.workspace,payload={"key":key},idempotency_key=key,priority=priority)
            self.store.approve(task["id"],task_digest=task["task_digest"]); tasks.append(task)
        first=self.store.claim("w1")
        self.assertEqual(first["id"],tasks[1]["id"])
        self.assertEqual(len(self.store.inbox(states=["queued"],limit=1,offset=1)),1)
        with self.assertRaises(HubError): self.store.inbox(states=["bogus"])

    def test_relay_delivery_mapping_and_approved_result_outbox(self):
        old_token=os.environ.get("HUB_COORDINATOR_TOKEN")
        old_sources=os.environ.get("HUB_RELAY_ALLOWED_SOURCES")
        os.environ["HUB_COORDINATOR_TOKEN"]="coordinator-secret-for-redaction"
        os.environ["HUB_RELAY_ALLOWED_SOURCES"]="repo:1"
        try:
            task=self.store.dispatch(workspace=self.workspace,
                payload={"instruction":"review","relay_destination":{"issue_number":9}},idempotency_key="relay-1",
                relay_source="repo:1",relay_delivery_id="event:7",relay_payload_digest="a"*64,relay_sender_id="sender:2")
            replay=self.store.dispatch(workspace=self.workspace,
                payload={"instruction":"review","relay_destination":{"issue_number":9}},idempotency_key="relay-1",
                relay_source="repo:1",relay_delivery_id="event:7",relay_payload_digest="a"*64,relay_sender_id="sender:2")
            self.assertEqual(replay["id"],task["id"])
            status_proposal=self.store.list_outbox()[0]
            self.assertEqual(status_proposal["kind"],"status")
            self.assertEqual(status_proposal["payload"]["state"],"awaiting_approval")
            with self.assertRaises(HubError):
                self.store.dispatch(workspace=self.workspace,payload={"changed":True},idempotency_key="relay-1",
                    relay_source="repo:1",relay_delivery_id="event:7",relay_payload_digest="b"*64,relay_sender_id="sender:2")
            self.store.approve(task["id"],task_digest=task["task_digest"])
            superseded=self.store.get_outbox(status_proposal["id"])
            self.assertEqual(superseded["state"],"superseded")
            queued_proposal=self.store.list_outbox(state="awaiting_approval")[0]
            self.assertEqual(queued_proposal["payload"]["state"],"queued")
            claim=self.store.claim("w1")
            self.store.complete(task["id"],"w1",claim["lease_epoch"],result={"answer":"coordinator-secret-for-redaction"})
            out=self.store.list_outbox()[0]
            self.assertEqual(out["state"],"awaiting_approval")
            self.assertEqual(out["kind"],"result")
            relay_view=self.store.get_relay_task("repo:1",task["id"])
            self.assertEqual(relay_view["relay_outbox"][0]["kind"],"result",
                             "multi-row outbox readback must put the newest terminal result first")
            self.assertEqual(out["payload"]["relay_destination"],{"issue_number":9})
            self.assertNotIn("coordinator-secret-for-redaction",str(out))
            self.assertIsNone(self.store.claim_outbox("relay"))
            with self.assertRaises(HubError): self.store.approve_outbox(out["id"],"bad")
            ready=self.store.approve_outbox(out["id"],out["approval_digest"])
            delivered=self.store.claim_outbox("relay")
            self.assertEqual(ready["state"],"ready")
            self.assertEqual(delivered["state"],"running")
            with self.assertRaises(HubError):
                self.store.complete_outbox(out["id"],"relay",delivered["lease_epoch"],delivered=True)
            receipt={"comment_id":123,"comment_node_id":"IC_kwDOexample",
                "comment_url":"https://github.com/acme/project/issues/9#issuecomment-123",
                "body_sha256":"1"*64,"verification":"github_graphql_readback"}
            bad_receipt=dict(receipt,comment_url="https://evil.example/issues/9#issuecomment-123")
            with self.assertRaises(HubError):
                self.store.complete_outbox(out["id"],"relay",delivered["lease_epoch"],delivered=True,receipt=bad_receipt)
            done=self.store.complete_outbox(out["id"],"relay",delivered["lease_epoch"],delivered=True,receipt=receipt)
            self.assertEqual(done["state"],"delivered")
            self.assertEqual(done["receipt"],receipt)
        finally:
            if old_token is None: os.environ.pop("HUB_COORDINATOR_TOKEN",None)
            else: os.environ["HUB_COORDINATOR_TOKEN"]=old_token
            if old_sources is None: os.environ.pop("HUB_RELAY_ALLOWED_SOURCES",None)
            else: os.environ["HUB_RELAY_ALLOWED_SOURCES"]=old_sources

    def test_relay_outbox_heartbeat_renews_and_obeys_emergency_stop(self):
        old_sources=os.environ.get("HUB_RELAY_ALLOWED_SOURCES")
        os.environ["HUB_RELAY_ALLOWED_SOURCES"]="repo:hb"
        try:
            task=self.store.dispatch(workspace=self.workspace,payload={"relay_destination":{"issue_number":2}},idempotency_key="relay-heartbeat",
                relay_source="repo:hb",relay_delivery_id="event:hb",relay_payload_digest="e"*64,relay_sender_id="sender:hb")
            self.store.approve(task["id"],task_digest=task["task_digest"])
            claim=self.store.claim("w1")
            self.store.complete(task["id"],"w1",claim["lease_epoch"],result={"ok":True})
            item=self.store.list_outbox(state="awaiting_approval")[0]
            self.store.approve_outbox(item["id"],item["approval_digest"])
            delivery=self.store.claim_outbox("relay")
            heartbeat=self.store.heartbeat_outbox(delivery["id"],"relay",delivery["lease_epoch"],60)
            self.assertTrue(heartbeat["allowed"])
            self.store.emergency_stop(True)
            with self.assertRaises(HubError) as ctx:
                self.store.heartbeat_outbox(delivery["id"],"relay",delivery["lease_epoch"],60)
            self.assertEqual(ctx.exception.code,"emergency_stop")
        finally:
            if old_sources is None: os.environ.pop("HUB_RELAY_ALLOWED_SOURCES",None)
            else: os.environ["HUB_RELAY_ALLOWED_SOURCES"]=old_sources

    def test_relay_cancel_requires_allowlisted_immutable_sender(self):
        old=os.environ.get("HUB_RELAY_ALLOWED_CANCEL_SENDERS")
        task=self.store.dispatch(workspace=self.workspace,payload={},idempotency_key="relay-cancel",
            relay_source="repo:2",relay_delivery_id="event:2",relay_payload_digest="c"*64,relay_sender_id="sender:allowed")
        os.environ["HUB_RELAY_ALLOWED_CANCEL_SENDERS"]="sender:allowed"
        try:
            with self.assertRaises(HubError):
                self.store.request_relay_cancel(task["id"],source="repo:2",sender_id="sender:forged")
            self.assertEqual(self.store.request_relay_cancel(task["id"],source="repo:2",sender_id="sender:allowed",reason="removed")["state"],"cancelled")
        finally:
            if old is None: os.environ.pop("HUB_RELAY_ALLOWED_CANCEL_SENDERS",None)
            else: os.environ["HUB_RELAY_ALLOWED_CANCEL_SENDERS"]=old


if __name__ == "__main__": unittest.main()
