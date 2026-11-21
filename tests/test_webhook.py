from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from hub.webhook_bridge import (
    BridgeError,
    ID_RE,
    _public_addresses,
    _read_stable_reply,
    _reply_path,
    run_transaction,
)


class WebhookBridgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "inbox"
        self.root.mkdir()
        self.receipts = Path(self.temp.name) / "receipts"
        self.settings = {
            "format_version": 1,
            "endpoint_url": "https://hook.example.com/route?fixed=1",
            "allowed_host": "hook.example.com",
            "header_name": "Authorization",
            "header_value_prefix": "Bearer ",
            "sender_key": "test-key-only",
            "inbox_root": str(self.root),
        }
        self.envelope = {"settings": self.settings, "source": "agent-b", "content": "Review this small task.", "wait_seconds": 2}

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_prepare_requires_exact_digest_and_does_not_store_payload_or_secret(self) -> None:
        sent = []
        prepared = run_transaction(self.envelope, receipt_dir=self.receipts, expected_inbox=str(self.root), sender=lambda *args: sent.append(args) or 202)
        self.assertEqual(prepared["state"], "prepared")
        self.assertRegex(prepared["task_id"], ID_RE)
        self.assertEqual(sent, [])
        receipt = json.loads((self.receipts / "peer-webhook-pending.json").read_text(encoding="utf-8"))
        serialized = json.dumps(receipt)
        self.assertNotIn("Review this small task", serialized)
        self.assertNotIn("test-key-only", serialized)
        self.assertNotIn("hook.example.com", serialized)
        self.assertEqual(receipt["reply_filename"], f"FOR-AGENT-B-{prepared['task_id']}.md")

    def test_exact_approval_posts_once_and_reads_correlated_untrusted_reply(self) -> None:
        prepared = run_transaction(self.envelope, receipt_dir=self.receipts, expected_inbox=str(self.root))
        posts = []

        def sender(parsed, header, auth, payload):
            posts.append((parsed, header, auth, payload))
            return 202

        reply_bytes = b"Review result\n"
        reply_hash = hashlib.sha256(reply_bytes).hexdigest()
        result = run_transaction(
            {**self.envelope, "approval_digest": prepared["payload_sha256"]},
            receipt_dir=self.receipts,
            expected_inbox=str(self.root),
            sender=sender,
            reply_reader=lambda path: ("Review result\n", reply_hash),
        )
        self.assertEqual(result["state"], "reply_received")
        self.assertEqual(result["http_status"], 202)
        self.assertEqual(result["reply_sha256"], reply_hash)
        self.assertEqual(result["reply_text_untrusted"], "Review result\n")
        self.assertEqual(len(posts), 1)
        self.assertEqual(posts[0][1], "Authorization")
        self.assertEqual(posts[0][2], "Bearer test-key-only")
        self.assertEqual(posts[0][3]["id"], prepared["task_id"])
        self.assertIn(prepared["task_id"], posts[0][3]["content"])
        next_task = run_transaction({**self.envelope, "content": "A later task"}, receipt_dir=self.receipts, expected_inbox=str(self.root))
        archive = self.receipts / f"peer-webhook-{prepared['task_id']}.json"
        self.assertTrue(archive.is_file())
        self.assertEqual(json.loads(archive.read_text(encoding="utf-8"))["state"], "reply_received")
        self.assertNotEqual(next_task["task_id"], prepared["task_id"])

    def test_ambiguous_post_is_never_retried_on_resume(self) -> None:
        prepared = run_transaction(self.envelope, receipt_dir=self.receipts, expected_inbox=str(self.root))
        calls = []

        def ambiguous(*_args):
            calls.append(1)
            raise BridgeError("webhook POST outcome is ambiguous; automatic retry is disabled")

        with self.assertRaises(BridgeError):
            run_transaction(
                {**self.envelope, "approval_digest": prepared["payload_sha256"]},
                receipt_dir=self.receipts,
                expected_inbox=str(self.root),
                sender=ambiguous,
            )
        receipt = json.loads((self.receipts / "peer-webhook-pending.json").read_text(encoding="utf-8"))
        self.assertEqual(receipt["state"], "send_ambiguous")
        result = run_transaction(
            {**self.envelope, "approval_digest": prepared["payload_sha256"]},
            receipt_dir=self.receipts,
            expected_inbox=str(self.root),
            sender=ambiguous,
            reply_reader=lambda _path: ("Arrived later", hashlib.sha256(b"Arrived later").hexdigest()),
        )
        self.assertEqual(result["state"], "reply_received")
        self.assertEqual(len(calls), 1)

    def test_accepted_post_and_wait_timeout_remain_distinct(self) -> None:
        prepared = run_transaction(self.envelope, receipt_dir=self.receipts, expected_inbox=str(self.root))
        posts = []
        first = run_transaction(
            {**self.envelope, "approval_digest": prepared["payload_sha256"]},
            receipt_dir=self.receipts,
            expected_inbox=str(self.root),
            sender=lambda *args: posts.append(args) or 200,
            reply_reader=lambda _path: None,
            wait=lambda _seconds: (_ for _ in ()).throw(KeyboardInterrupt()),
        )
        self.assertEqual(first["state"], "reply_wait_cancelled")
        self.assertEqual(len(posts), 1)
        receipt = json.loads((self.receipts / "peer-webhook-pending.json").read_text(encoding="utf-8"))
        self.assertEqual(receipt["http_status"], 200)
        self.assertEqual(receipt["state"], "reply_wait_cancelled")
        later = run_transaction(
            self.envelope,
            receipt_dir=self.receipts,
            expected_inbox=str(self.root),
            sender=lambda *args: posts.append(args) or 200,
            reply_reader=lambda _path: ("The correlated answer", hashlib.sha256(b"The correlated answer").hexdigest()),
        )
        self.assertEqual(later["state"], "reply_received")
        self.assertEqual(len(posts), 1)

    def test_changed_request_and_wrong_approval_digest_are_rejected_before_post(self) -> None:
        prepared = run_transaction(self.envelope, receipt_dir=self.receipts, expected_inbox=str(self.root))
        posts = []
        changed = {**self.envelope, "content": "Changed task", "approval_digest": prepared["payload_sha256"]}
        with self.assertRaisesRegex(BridgeError, "changed after preparation"):
            run_transaction(changed, receipt_dir=self.receipts, expected_inbox=str(self.root), sender=lambda *a: posts.append(a) or 200)
        wrong = {**self.envelope, "approval_digest": "0" * 64}
        result = run_transaction(wrong, receipt_dir=self.receipts, expected_inbox=str(self.root), sender=lambda *a: posts.append(a) or 200)
        self.assertEqual(result["state"], "approval_required")
        self.assertEqual(posts, [])

    def test_rejects_wrong_inbox_and_reply_filename_traversal(self) -> None:
        with self.assertRaisesRegex(BridgeError, "does not match"):
            run_transaction(self.envelope, receipt_dir=self.receipts, expected_inbox=str(self.root / "other"))
        with self.assertRaises(BridgeError):
            _reply_path(self.root, "agent-a", "T" + "0" * 20 + "../escape")

    def test_rejects_header_injection_and_private_dns(self) -> None:
        bad = {**self.settings, "header_value_prefix": "Bearer\r\nX-Evil: 1"}
        with self.assertRaisesRegex(BridgeError, "invalid characters"):
            run_transaction({**self.envelope, "settings": bad}, receipt_dir=self.receipts, expected_inbox=str(self.root))

        def resolver(*_args, **_kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]

        import socket

        with self.assertRaisesRegex(BridgeError, "non-public"):
            _public_addresses("hook.example.com", 443, resolver=resolver)

    def test_public_address_is_accepted_for_pinned_connection(self) -> None:
        import socket

        def resolver(*_args, **_kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]

        self.assertEqual(_public_addresses("hook.example.com", 443, resolver=resolver), ["8.8.8.8"])

    def test_empty_reply_is_rejected(self) -> None:
        empty = self.root / "empty.md"
        empty.write_text("  \n", encoding="utf-8")
        with self.assertRaisesRegex(BridgeError, "empty"):
            _read_stable_reply(empty, delay=0)


if __name__ == "__main__":
    unittest.main()
