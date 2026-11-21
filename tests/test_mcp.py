import json
import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlsplit
from unittest.mock import patch

try:
    from fastapi.testclient import TestClient
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from hub import mcp_server
    from hub.api import create_app
    from hub.drive_bridge import canonical, request_digest
    from hub.store import Store
    HAS_MCP_DEPS = True
except ImportError:
    HAS_MCP_DEPS = False


class InProcessResponse:
    def __init__(self, response):
        self.status = response.status_code
        self._data = response.content
    def read(self, size=-1):
        return self._data if size < 0 else self._data[:size]
    def __enter__(self): return self
    def __exit__(self, *args): return False


@unittest.skipUnless(HAS_MCP_DEPS, "install package-local requirements to run MCP/API integration tests")
class MCPAPITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "test.sqlite3"), allowed_workspaces=[self.tmp.name])
        self.client = TestClient(create_app(self.store))
        self.env = patch.dict(os.environ, {"HUB_COORDINATOR_TOKEN": "test-coordinator-token",
                                          "HUB_BROKER_URL": "http://127.0.0.1:8765",
                                          "HUB_ENABLE_DRIVE": "0"})
        self.env.start()
        self.http = patch("urllib.request.build_opener", self.build_opener)
        self.http.start()

    def tearDown(self):
        self.http.stop()
        self.env.stop()
        self.store.close()
        self.tmp.cleanup()

    def build_opener(self, *handlers):
        return self.InProcessOpener(self)

    class InProcessOpener:
        def __init__(self, case): self.case = case
        def open(self, request, timeout=10): return self.case.request(request)

    def request(self, request):
        parsed = urlsplit(request.full_url)
        headers = dict(request.header_items())
        response = self.client.request(request.method, parsed.path + ("?" + parsed.query if parsed.query else ""),
            content=request.data, headers=headers)
        if response.status_code >= 400:
            from urllib.error import HTTPError
            raise HTTPError(request.full_url, response.status_code, response.text, response.headers, None)
        return InProcessResponse(response)

    def test_http_client_blocks_redirects_and_proxy_handlers(self):
        built = {}
        def capture(*handlers):
            built["handlers"] = handlers
            return object()
        with patch("urllib.request.build_opener", capture):
            mcp_server._local_opener()
        from urllib.request import ProxyHandler
        proxy = next(h for h in built["handlers"] if isinstance(h, ProxyHandler))
        redirect = next(h for h in built["handlers"] if isinstance(h, mcp_server._NoRedirect))
        self.assertEqual(proxy.proxies, {})
        self.assertIsNone(redirect.redirect_request(None, None, 302, "Found", {}, "https://example.com"))

    def test_dispatch_send_status_logs_inbox_thread_approval_cancel_handover_stop(self):
        workspace = self.tmp.name
        sent = mcp_server.agent_send(workspace, "review this paragraph", "send-key", "thread-a")
        self.assertEqual(sent["state"], "awaiting_approval")
        task = mcp_server.agent_dispatch(workspace, {"prompt": "analyze", "adapter": "agent-a"},
            "dispatch-key", "thread-a", target_worker="worker-1", parent_task_id=sent["id"],
            priority=8, depends_on=[sent["id"]])
        self.assertEqual(task["target_worker"], "worker-1")
        self.assertEqual(task["parent_task_id"], sent["id"])
        self.assertEqual(task["priority"], 8)
        self.assertEqual(task["depends_on"], [sent["id"]])
        self.assertEqual(task["dependency_state"], "waiting")
        status = mcp_server.agent_status()
        self.assertIn("counts", status["broker"])
        self.assertFalse(status["drive"]["enabled"])
        self.assertEqual(mcp_server.agent_status(task["id"])["id"], task["id"])
        self.assertEqual(mcp_server.agent_result(task["id"])["state"], "awaiting_approval")
        self.assertTrue(mcp_server.agent_logs(task["id"]))
        active = mcp_server.agent_inbox(workspace, states=["awaiting_approval", "queued", "running"], offset=0)
        self.assertTrue(active["tasks"])
        self.assertIn(task["id"], {row["id"] for row in active["tasks"]})
        self.assertFalse(active["drive"]["enabled"])
        self.assertTrue(mcp_server.agent_thread("thread-a")["tasks"])
        self.assertEqual(mcp_server.agent_outbox(), [])
        approved = mcp_server.agent_approve(task["id"], task["task_digest"], "test approval")
        self.assertEqual(approved["state"], "queued")
        mcp_server.agent_handover(task["id"], {"next": "inspect"})
        cancelled = mcp_server.agent_cancel(task["id"], "Rejected: waiting on source evidence")
        self.assertIn(cancelled["state"], {"cancelled", "cancellation_requested"})
        self.assertIn("Rejected", str(cancelled.get("error")))
        self.assertTrue(mcp_server.agent_emergency_stop(True)["emergency_stop"])

    def test_drive_mcp_sync_promote_approve_export_and_correlate(self):
        drive_root = Path(self.tmp.name) / "drive"
        for peer in ("agent-b", "agent-c"):
            for leaf in ("inbox", "outbox"):
                (drive_root / "agents" / peer / leaf).mkdir(parents=True, exist_ok=True)
        inbound = {
            "schema_version": 1, "id": "22222222-2222-4222-8222-222222222222",
            "thread": "mcp-drive-roundtrip", "from": "agent-c", "to": "agent-a",
            "task": "Review a harmless calculation", "content": "Review this harmless calculation.",
            "created_at": "2026-10-20T10:00:00Z",
            "limits": {"max_seconds": 45, "max_output_chars": 1000},
        }
        inbound["request_digest"] = request_digest(inbound)
        inbound_path = drive_root / "agents" / "agent-c" / "outbox" / (inbound["id"] + ".json")
        inbound_path.write_bytes(canonical(inbound))

        with patch.dict(os.environ, {"HUB_ENABLE_DRIVE": "1", "HUB_DRIVE_ROOT": str(drive_root),
                                     "HUB_DRIVE_WORKSPACE": self.tmp.name}):
            drive_status = mcp_server.agent_drive_status()
            self.assertTrue(drive_status["enabled"])
            self.assertFalse(drive_status["polling"])
            self.assertEqual(drive_status["peer_pickup"], "unknown")

            synced = mcp_server.agent_drive_sync()
            self.assertFalse(synced["auto_approved"])
            self.assertFalse(synced["execution_started"])
            self.assertFalse(synced["polling"])

            messages = mcp_server.agent_drive_messages(state="received")
            self.assertEqual(len(messages), 1)
            self.assertEqual(messages[0]["origin"], "Drive folder")
            self.assertEqual(messages[0]["input_trust"], "untrusted")
            self.assertEqual(messages[0]["approval_state"], "not_approved_by_import")

            promoted = mcp_server.agent_drive_promote(messages[0]["message_id"],
                messages[0]["message_digest"], "drive:agent-c", timeout_seconds=45)
            self.assertEqual(promoted["state"], "awaiting_approval")
            self.assertEqual(promoted["origin"], "Drive folder")
            self.assertEqual(promoted["input_trust"], "untrusted")

            approved = mcp_server.agent_approve(promoted["id"], promoted["task_digest"], "explicit test approval")
            self.assertEqual(approved["state"], "queued")
            self.assertTrue(approved["drive_export_required"])
            exported = mcp_server.agent_drive_export(promoted["id"])
            self.assertEqual(exported["state"], "exported_waiting_for_peer")
            self.assertEqual(exported["peer_pickup"], "unknown")
            self.assertFalse(exported["remote_execution_confirmed"])

            external_task = json.loads((drive_root / "agents" / "agent-c" / "inbox" /
                                        (promoted["id"] + ".json")).read_text(encoding="utf-8"))
            reply = {
                "schema_version": 1, "id": external_task["id"], "thread": external_task["thread"],
                "from": "agent-c", "to": "agent-a", "reply_to": external_task["id"],
                "request_digest": external_task["request_digest"], "status": "completed",
                "content": "Independent review received.", "created_at": "2026-10-20T10:01:00Z",
                "limits": external_task["limits"],
            }
            (drive_root / "agents" / "agent-c" / "outbox" /
             (external_task["id"] + ".json")).write_bytes(canonical(reply))
            synced_again = mcp_server.agent_drive_sync()
            self.assertIn({"message_id": external_task["id"], "task_id": promoted["id"], "state": "completed"},
                          synced_again["correlated"])
            final = mcp_server.agent_status(promoted["id"])
            self.assertEqual(final["state"], "completed")
            self.assertFalse(final["external_peer"]["remote_stop_confirmed"])
            self.assertEqual(final["external_peer"]["pickup"], "unknown")
            thread = mcp_server.agent_thread("mcp-drive-roundtrip")
            self.assertIn(promoted["id"], {task["id"] for task in thread["tasks"]})
            self.assertGreaterEqual(len(thread["drive_messages"]), 2)

    def test_mcp_tool_catalog_exposes_control_surface(self):
        tools = asyncio.run(mcp_server.mcp.list_tools())
        names = {tool.name for tool in tools}
        self.assertTrue({"agent_send", "agent_dispatch", "agent_status", "agent_result", "agent_logs",
                         "agent_inbox", "agent_thread", "agent_approve", "agent_cancel",
                         "agent_handover", "agent_emergency_stop", "agent_outbox",
                         "agent_drive_status", "agent_drive_sync", "agent_drive_messages",
                         "agent_drive_promote", "agent_drive_export",
                         "agent_approve_relay_delivery", "agent_reconcile_interrupted",
                         "agent_abandon_relay_delivery"}.issubset(names))

    def test_recovery_tools_use_coordinator_routes_and_terminal_only_states(self):
        task = mcp_server.agent_dispatch(self.tmp.name, {"work": "interrupted"}, "reconcile-key")
        connection = self.store._connect()
        try:
            connection.execute("UPDATE tasks SET state='interrupted',worker_id='worker-1',lease_epoch=4 WHERE id=?",
                               (task["id"],))
        finally:
            connection.close()
        reconciled = mcp_server.agent_reconcile_interrupted(task["id"], task["task_digest"], True,
            "I confirmed the owned worker process tree exited; no success was observed.")
        self.assertEqual(reconciled["state"], "cancelled")
        self.assertIsNone(reconciled["result"])

        relay_task = self.store.dispatch(workspace=self.tmp.name, payload={"work": "publish"},
            idempotency_key="relay-abandon-key", relay_source="github:123", relay_delivery_id="issue:comment:9",
            relay_payload_digest="a" * 64, relay_sender_id="42")
        outbox = self.store.list_outbox(state="awaiting_approval")[0]
        connection = self.store._connect()
        try:
            connection.execute("UPDATE relay_outbox SET state='interrupted' WHERE id=?", (outbox["id"],))
        finally:
            connection.close()
        abandoned = mcp_server.agent_abandon_relay_delivery(outbox["id"], outbox["approval_digest"], True,
            "I checked the dedicated issue and cannot prove whether the write completed; do not retry.")
        self.assertEqual(abandoned["state"], "abandoned")
        self.assertEqual(abandoned["error"]["outcome"], "unknown")

    def test_mcp_call_tool_validates_list_return_schemas(self):
        fixtures = {
            "/v1/logs/task-a?limit=20": [{"event": "claimed"}],
            "/v1/inbox?limit=10&states=queued,running&offset=5": [{"id": "task-a"}],
            "/v1/thread/thread-a": [{"id": "task-a"}],
            "/v1/drive/status": {"enabled": False, "polling": False, "peer_pickup": "unknown"},
            "/v1/relay/outbox?limit=50&state=awaiting_approval": [{"id": "out-1"}],
            "/v1/relay/outbox/out-1/approve": {"id": "out-1", "state": "ready"},
            "/v1/relay/outbox/out-2/abandon": {"id": "out-2", "state": "abandoned"},
            "/v1/reconcile/task-a": {"id": "task-a", "state": "cancelled"},
        }
        with patch.object(mcp_server, "_call", side_effect=lambda method, path, payload=None: fixtures[path]):
            results = asyncio.run(self._mcp_list_call_tools())
        self.assertEqual(results, [[{"event": "claimed"}], {"tasks": [{"id": "task-a", "transport": "local broker worker queue"}], "drive_messages": [],
                                    "drive": {"enabled": False, "polling": False, "peer_pickup": "unknown",
                                              "sync_required": True}},
                                   {"thread_id": "thread-a", "tasks": [{"id": "task-a", "transport": "local broker worker queue"}], "drive_messages": [],
                                    "drive": {"enabled": False, "polling": False, "peer_pickup": "unknown",
                                              "sync_required": True}},
                                   {"enabled": False, "polling": False, "peer_pickup": "unknown",
                                    "sync_required": True},
                                   [{"id": "out-1"}], {"id": "out-1", "state": "ready"},
                                   {"id": "task-a", "state": "cancelled"},
                                   {"id": "out-2", "state": "abandoned"}])

    async def _mcp_list_call_tools(self):
        values = []
        for name, args in (("agent_logs", {"task_id": "task-a", "limit": 20}),
                           ("agent_inbox", {"limit": 10, "states": ["queued", "running"], "offset": 5}),
                           ("agent_thread", {"thread_id": "thread-a"}),
                           ("agent_drive_status", {}),
                           ("agent_outbox", {}),
                           ("agent_approve_relay_delivery", {"outbox_id": "out-1",
                               "approval_digest": "abc", "note": "human approved exact result"}),
                           ("agent_reconcile_interrupted", {"task_id": "task-a", "task_digest": "digest-a",
                               "process_termination_confirmed": True,
                               "evidence_note": "I verified the worker tree stopped."}),
                           ("agent_abandon_relay_delivery", {"outbox_id": "out-2", "approval_digest": "digest-b",
                               "publication_checked": True,
                               "evidence_note": "I checked the issue publication state."})):
            response = await mcp_server.mcp.call_tool(name, args)
            if isinstance(response, tuple):
                content, structured = response
                self.assertEqual(len(content), 1)
                values.append(structured["result"])
            else:
                self.assertEqual(len(response), 1)
                values.append(json.loads(response[0].text))
        return values

    def test_actual_mcp_stdio_initialize_and_tool_list(self):
        async def exchange():
            entry = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scripts", "mcp-entry.py")
            params = StdioServerParameters(command=os.path.join(os.path.dirname(os.sys.executable), "python.exe"),
                                           args=[entry])
            async with stdio_client(params) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    return await session.list_tools()
        response = asyncio.run(exchange())
        names = {tool.name for tool in response.tools}
        self.assertTrue({"agent_send", "agent_dispatch", "agent_status", "agent_result", "agent_logs",
                         "agent_inbox", "agent_thread", "agent_drive_status", "agent_drive_sync",
                         "agent_drive_messages", "agent_drive_promote", "agent_drive_export",
                         "agent_approve", "agent_cancel",
                         "agent_handover", "agent_emergency_stop", "agent_outbox",
                         "agent_approve_relay_delivery", "agent_reconcile_interrupted",
                         "agent_abandon_relay_delivery"}.issubset(names))


if __name__ == "__main__":
    unittest.main()

