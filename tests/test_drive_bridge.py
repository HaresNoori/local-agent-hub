import json
import tempfile
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path

from hub.drive_bridge import BridgeError, canonical, request_digest, sync_drive_once, export_approved_task
from hub.store import HubError, Store


class DriveBrokerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "drive"
        for peer in ("agent-b", "agent-c"):
            (self.root / "agents" / peer / "outbox").mkdir(parents=True)
            (self.root / "agents" / peer / "inbox").mkdir(parents=True)
        self.workspace = Path(self.tmp.name) / "workspace"
        self.workspace.mkdir()
        self.store = Store(Path(self.tmp.name) / "hub.sqlite3", allowed_workspaces=[self.workspace])

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def envelope(self, *, peer="agent-c", kind="task", msg_id=None, thread="drive-thread", content="Review this safely"):
        msg_id = msg_id or str(uuid.uuid4())
        value = {"schema_version": 1, "id": msg_id, "thread": thread, "from": peer,
                 "to": "agent-a", "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                 "limits": {"max_seconds": 90, "max_output_chars": 2500}}
        if kind == "task":
            value.update({"task": "Review request", "content": content})
        else:
            value.update({"reply_to": msg_id, "request_digest": "a" * 64,
                          "status": "completed", "content": content})
        value["request_digest"] = request_digest(value)
        return value

    def write_outbox(self, msg):
        path = self.root / "agents" / msg["from"] / "outbox" / (msg["id"] + ".json")
        path.write_bytes(canonical(msg))
        return path

    def test_import_is_untrusted_idempotent_and_not_a_task(self):
        message = self.envelope()
        self.write_outbox(message)
        first = sync_drive_once(self.store, self.root)
        replay = sync_drive_once(self.store, self.root)
        self.assertEqual(len(first["imported"]), 1)
        self.assertEqual(replay["imported"][0]["state"], "received")
        self.assertEqual(self.store.inbox(), [])
        rows = self.store.list_drive_messages(state="received", thread_id="drive-thread")
        self.assertEqual(rows[0]["message_digest"], __import__("hashlib").sha256(canonical(message)).hexdigest())
        self.assertEqual(self.store.status()["drive"]["polling"], False)
        self.assertEqual(first["execution_started"], False)

    def test_sync_pages_progress_then_rescan_to_detect_changed_old_ids(self):
        messages=[]
        for suffix in ("0001","0002","0003"):
            msg=self.envelope(msg_id=f"00000000-0000-4000-8000-00000000{suffix}",content=f"task {suffix}")
            messages.append(msg); self.write_outbox(msg)
        pages=[]
        for _ in range(3): pages.append(sync_drive_once(self.store,self.root,limit=1))
        imported=[page["imported"][0]["message_id"] for page in pages]
        self.assertEqual(imported,[msg["id"] for msg in messages])
        self.assertEqual([page["has_more"] for page in pages],[True,True,False])
        self.assertFalse(self.store.drive_status()["continuation_required"])
        changed=dict(messages[0],content="changed after original import")
        changed["request_digest"]=request_digest(changed)
        (self.root/"agents/agent-c/outbox"/(changed["id"]+".json")).write_bytes(canonical(changed))
        rescanned=sync_drive_once(self.store,self.root,limit=1)
        self.assertEqual(rescanned["rejected"][0]["error"],"drive_message_conflict")

    def test_promotion_requires_exact_message_digest_and_normal_approval(self):
        message = self.envelope()
        self.write_outbox(message)
        sync_drive_once(self.store, self.root)
        record = self.store.get_drive_message(message["id"])
        with self.assertRaises(HubError):
            self.store.promote_drive_message(message["id"], request_digest="0" * 64,
                workspace=self.workspace, target_worker="drive:agent-c", cost_reserved=0.25)
        promoted = self.store.promote_drive_message(message["id"], request_digest=record["message_digest"],
            workspace=self.workspace, target_worker="drive:agent-c", cost_reserved=0.25)
        self.assertEqual(promoted["state"], "awaiting_approval")
        self.assertEqual(self.store.promote_drive_message(message["id"], request_digest=record["message_digest"],
            workspace=self.workspace, target_worker="drive:agent-c", cost_reserved=0.25)["id"], promoted["id"])
        with self.assertRaises(HubError):
            export_approved_task(self.store, self.root, promoted["id"])
        approved = self.store.approve(promoted["id"], task_digest=promoted["task_digest"])
        self.assertEqual(approved["state"], "queued")

    def test_export_and_reply_are_digest_correlated_and_complete_once(self):
        payload = {"adapter": "drive-peer", "prompt": "Review a function", "title": "Technical review",
                   "limits": {"max_seconds": 90, "max_output_chars": 2500}}
        task = self.store.dispatch(workspace=self.workspace, payload=payload, idempotency_key="drive-export-1",
            thread_id="reply-thread", target_worker="drive:agent-c", cost_reserved=0.5)
        self.store.approve(task["id"], task_digest=task["task_digest"])
        exported = export_approved_task(self.store, self.root, task["id"])
        self.assertEqual(exported["pickup"], "unknown")
        self.assertFalse(exported["remote_execution_confirmed"])
        envelope = json.loads((self.root / "agents/agent-c/inbox" / (task["id"] + ".json")).read_text(encoding="utf-8"))
        self.assertEqual(envelope["request_digest"], exported["request_digest"])
        replay = export_approved_task(self.store, self.root, task["id"])
        self.assertEqual(replay["request_digest"], exported["request_digest"])
        reply = {"schema_version": 1, "id": task["id"], "thread": "reply-thread", "from": "agent-c",
                 "to": "agent-a", "reply_to": task["id"], "request_digest": envelope["request_digest"],
                 "status": "completed", "content": "Review received", "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                 "limits": envelope["limits"]}
        reply["request_digest"] = request_digest(reply)
        # The protocol uses request_digest for the signed request on replies, so restore it after digest construction.
        reply["request_digest"] = envelope["request_digest"]
        self.write_outbox(reply)
        synced = sync_drive_once(self.store, self.root)
        self.assertFalse(synced["rejected"], synced)
        self.assertEqual(synced["correlated"][0]["state"], "completed")
        self.assertEqual(self.store.get_task(task["id"])["result"]["text"], "Review received")

    def test_malformed_and_wrong_peer_reply_never_complete_task(self):
        msg = self.envelope(kind="reply", content="unmatched result")
        # A reply without an export can be imported as a message only.
        self.write_outbox(msg)
        synced = sync_drive_once(self.store, self.root)
        self.assertEqual(synced["correlated"], [])
        self.assertEqual(self.store.inbox(), [])
        self.assertEqual(self.store.list_drive_messages()[0]["state"], "received")
        msg["command"] = "dangerous"
        (self.root / "agents/agent-c/outbox" / (msg["id"] + ".json")).write_bytes(canonical(msg))
        rejected = sync_drive_once(self.store, self.root)
        self.assertTrue(rejected["rejected"])
        self.assertFalse(rejected["execution_started"])

    def test_cancelled_external_task_late_reply_is_not_completed(self):
        task = self.store.dispatch(workspace=self.workspace, payload={"prompt":"Review","title":"Review"},
            idempotency_key="drive-cancel", target_worker="drive:agent-c", cost_reserved=0.5)
        self.store.approve(task["id"], task_digest=task["task_digest"])
        export = export_approved_task(self.store, self.root, task["id"])
        cancelled = self.store.cancel(task["id"], principal="coordinator", reason="Stop waiting")
        self.assertTrue(cancelled["cancellation_requested"])
        reply = {"schema_version":1,"id":task["id"],"thread":task["thread_id"],"from":"agent-c","to":"agent-a",
                 "reply_to":task["id"],"request_digest":export["request_digest"],"status":"completed","content":"late",
                 "created_at":datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),
                 "limits":{"max_seconds":90,"max_output_chars":2500}}
        self.write_outbox(reply)
        sync_drive_once(self.store, self.root)
        self.assertEqual(self.store.get_task(task["id"])["state"], "running")
        self.assertTrue(self.store.get_task(task["id"])["cancellation_requested"])

    def test_export_respects_emergency_stop_and_workspace_slot(self):
        first = self.store.dispatch(workspace=self.workspace, payload={"prompt":"first","title":"one"},
            idempotency_key="drive-first", target_worker="drive:agent-c", cost_reserved=0.5)
        self.store.approve(first["id"], task_digest=first["task_digest"])
        self.store.emergency_stop(True)
        with self.assertRaises(HubError):
            export_approved_task(self.store, self.root, first["id"])
        self.assertEqual(self.store.get_task(first["id"])["state"], "cancelled")
        self.store.emergency_stop(False)
        active = self.store.dispatch(workspace=self.workspace, payload={"prompt":"active","title":"active"},
            idempotency_key="drive-active", target_worker="drive:agent-c", cost_reserved=0.5)
        self.store.approve(active["id"], task_digest=active["task_digest"])
        export_approved_task(self.store, self.root, active["id"])
        second = self.store.dispatch(workspace=self.workspace, payload={"prompt":"second","title":"two"},
            idempotency_key="drive-second", target_worker="drive:agent-c", cost_reserved=0.5)
        self.store.approve(second["id"], task_digest=second["task_digest"])
        with self.assertRaises(HubError):
            export_approved_task(self.store, self.root, second["id"])

    def test_expired_external_lease_is_interrupted_and_never_reexported(self):
        task = self.store.dispatch(workspace=self.workspace, payload={"prompt":"expires","title":"expire"},
            idempotency_key="drive-expire", target_worker="drive:agent-c", cost_reserved=0.5)
        self.store.approve(task["id"], task_digest=task["task_digest"])
        export_approved_task(self.store, self.root, task["id"])
        from contextlib import closing
        with closing(self.store._connect()) as c:
            c.execute("UPDATE tasks SET lease_until=0 WHERE id=?", (task["id"],))
        self.store.recover_expired_leases()
        self.assertEqual(self.store.get_task(task["id"])["state"], "interrupted")
        with self.assertRaises(BridgeError):
            export_approved_task(self.store, self.root, task["id"])

    def test_peer_execution_cap_does_not_shorten_bounded_pickup_lease(self):
        task=self.store.dispatch(workspace=self.workspace,
            payload={"prompt":"Echo the supplied connection nonce only.","title":"Connection check",
                     "limits":{"max_seconds":300,"max_output_chars":1000}},
            idempotency_key="drive-scheduled-pickup",target_worker="drive:agent-c",
            cost_reserved=0.0,timeout_seconds=3600)
        self.store.approve(task["id"],task_digest=task["task_digest"])
        exported=export_approved_task(self.store,self.root,task["id"])
        current=self.store.get_task(task["id"])
        self.assertEqual(current["timeout_seconds"],3600)
        self.assertEqual(current["lease_until"]-current["started_at"],3600)
        envelope=json.loads((self.root/"agents/agent-c/inbox"/(task["id"]+".json")).read_text(encoding="utf-8"))
        self.assertEqual(envelope["limits"]["max_seconds"],300)
        reply={"schema_version":1,"id":task["id"],"thread":task["thread_id"],"from":"agent-c","to":"agent-a",
               "reply_to":task["id"],"request_digest":exported["request_digest"],"status":"completed",
               "content":"nonce echoed","created_at":datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),
               "limits":envelope["limits"]}
        self.write_outbox(reply)
        from contextlib import closing
        with closing(self.store._connect()) as c:
            c.execute("UPDATE tasks SET lease_until=0 WHERE id=?",(task["id"],))
        self.store.recover_expired_leases()
        late=sync_drive_once(self.store,self.root)
        self.assertEqual(self.store.get_task(task["id"])["state"],"interrupted")
        self.assertEqual(late["correlated"],[])
        self.assertIn("drive_reply_late",[entry["error"] for entry in late["rejected"]])

    def _stage_peer_export(self, key, workspace=None):
        task=self.store.dispatch(workspace=workspace or self.workspace,
            payload={"prompt":"Echo the supplied connection nonce only.","title":"Connection check",
                     "limits":{"max_seconds":300,"max_output_chars":1000}},
            idempotency_key=key,target_worker="drive:agent-c",cost_reserved=0.0,timeout_seconds=3600)
        self.store.approve(task["id"],task_digest=task["task_digest"])
        exported=export_approved_task(self.store,self.root,task["id"])
        return task,exported

    def test_valid_external_lease_survives_restart_and_correlated_reply_once(self):
        task,exported=self._stage_peer_export("restart-peer-valid")
        before=self.store.get_task(task["id"])
        db=Path(self.store.db_path)
        self.store.close()
        self.store=Store(db,allowed_workspaces=[self.workspace])
        after=self.store.get_task(task["id"])
        self.assertEqual(after["state"],"running")
        self.assertEqual(after["lease_epoch"],before["lease_epoch"])
        self.assertEqual(after["lease_until"],before["lease_until"])
        reply_digest="b"*64
        result={"text":"nonce echoed","external_status":"completed"}
        completed=self.store.complete_external_drive_task(task["id"],"agent-c",exported["request_digest"],
            reply_digest,result=result)
        self.assertEqual(completed["state"],"completed")
        replay=self.store.complete_external_drive_task(task["id"],"agent-c",exported["request_digest"],
            reply_digest,result=result)
        self.assertEqual(replay["state"],"completed")
        with self.assertRaises(HubError) as caught:
            self.store.complete_external_drive_task(task["id"],"agent-c",exported["request_digest"],
                "c"*64,result={"text":"different"})
        self.assertEqual(caught.exception.code,"drive_reply_conflict")

    def test_restart_fences_expired_cancelled_stopped_and_malformed_peer_exports(self):
        cases=("expired","cancelled","stopped","malformed")
        for case in cases:
            with self.subTest(case=case):
                workspace=self.workspace/case
                workspace.mkdir()
                task,exported=self._stage_peer_export("restart-peer-"+case,workspace)
                db=Path(self.store.db_path)
                from contextlib import closing
                with closing(self.store._connect()) as c:
                    if case=="expired": c.execute("UPDATE tasks SET lease_until=0 WHERE id=?",(task["id"],))
                    elif case=="cancelled": c.execute("UPDATE tasks SET cancellation_requested=1 WHERE id=?",(task["id"],))
                    elif case=="malformed": c.execute("UPDATE drive_exports SET request_json='{}' WHERE task_id=?",(task["id"],))
                if case=="stopped": self.store.emergency_stop(True)
                self.store.close()
                self.store=Store(db,allowed_workspaces=[self.workspace])
                recovered=self.store.get_task(task["id"])
                self.assertEqual(recovered["state"],"interrupted")
                self.assertGreater(recovered["lease_epoch"],task["lease_epoch"])
                with self.assertRaises(HubError) as caught:
                    self.store.complete_external_drive_task(task["id"],"agent-c",exported["request_digest"],
                        "d"*64,result={"text":"must remain held"})
                self.assertEqual(caught.exception.code,"drive_reply_late")
                if case=="stopped": self.store.emergency_stop(False)


if __name__ == "__main__":
    unittest.main()
