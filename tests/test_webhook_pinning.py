"""Address pinning and refusal paths for the one-shot webhook bridge.

No test here opens a socket. DNS resolution is replaced by a recording fake and
socket.create_connection by a recorder that raises, so a regression that dials a hostname or an
unvalidated address shows up as a failed assertion rather than as network traffic. As a backstop,
name lookup and connection are blocked for the whole class.
"""
from __future__ import annotations

import base64
import io
import json
import socket
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.parse import urlsplit

from hub import webhook_bridge
from hub.webhook_bridge import (
    BridgeError,
    MAX_CONTENT_CHARS,
    MAX_REPLY_BYTES,
    _PinnedHTTPSConnection,
    _post_once,
    _public_addresses,
    _read_stable_reply,
    _reply_path,
    _validate_settings,
    run_transaction,
)

PUBLIC = "8.8.8.8"
URL = "https://hook.example.com/route?fixed=1"


import secrets as _secrets

SENDER_KEY = _secrets.token_hex(16)  # generated per run; never a real credential


def records(*addresses):
    return [(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 443)) for a in addresses]


class NoNetworkCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        for target in ("socket.getaddrinfo", "socket.create_connection"):
            patcher = patch(target, side_effect=AssertionError("network access attempted in a test"))
            patcher.start()
            self.addCleanup(patcher.stop)
        self.root = Path(self.temp.name) / "inbox"
        self.root.mkdir()
        self.receipts = Path(self.temp.name) / "receipts"
        self.settings = {"format_version": 1, "endpoint_url": URL, "allowed_host": "hook.example.com",
                         "header_name": "Authorization", "header_value_prefix": "Bearer ",
                         "sender_key": SENDER_KEY, "inbox_root": str(self.root)}
        self.envelope = {"settings": self.settings, "source": "agent-b", "content": "Review this.", "wait_seconds": 2}

    def run_tx(self, envelope=None, **kwargs):
        return run_transaction(envelope or self.envelope, receipt_dir=self.receipts,
                               expected_inbox=str(self.root), **kwargs)

    def prepare(self):
        return self.run_tx()


class AddressPinningTests(NoNetworkCase):
    def test_post_dials_the_validated_address_once_and_never_the_hostname(self):
        lookups, dialled = [], []
        original = webhook_bridge._public_addresses

        def resolver(host, port, **_kwargs):
            lookups.append((host, port))
            # A rebinding resolver: the first answer is public, any later answer is loopback.
            return records(PUBLIC) if len(lookups) == 1 else records("127.0.0.1")

        def dial(address, timeout=None, *_args, **_kwargs):
            dialled.append((address, timeout))
            raise OSError("blocked by test")

        parsed = urlsplit(URL)
        with patch.object(webhook_bridge, "_public_addresses",
                          lambda host, port: original(host, port, resolver=resolver)):
            with patch("socket.create_connection", side_effect=dial):
                with self.assertRaisesRegex(BridgeError, "ambiguous"):
                    _post_once(parsed, "Authorization", "Bearer x", {"id": "T0", "content": "c"})
        self.assertEqual(lookups, [("hook.example.com", 443)])
        self.assertEqual(dialled, [((PUBLIC, 443), 20.0)])

    def test_post_refuses_a_non_public_resolution_before_any_dial(self):
        original = webhook_bridge._public_addresses
        for bad in ("127.0.0.1", "10.1.2.3", "169.254.169.254", "192.168.0.9", "::1", "fe80::1"):
            with self.subTest(address=bad):
                with patch.object(webhook_bridge, "_public_addresses",
                                  lambda host, port, bad=bad: original(host, port, resolver=lambda *a, **k: records(bad))):
                    with patch("socket.create_connection") as dial:
                        with self.assertRaisesRegex(BridgeError, "non-public"):
                            _post_once(urlsplit(URL), "Authorization", "Bearer x", {"id": "T0"})
                        dial.assert_not_called()

    def test_connection_dials_the_pinned_ip_but_verifies_tls_against_the_hostname(self):
        conn = _PinnedHTTPSConnection("hook.example.com", 443, PUBLIC, 5.0)
        conn._context = MagicMock()
        raw_socket = object()
        with patch("socket.create_connection", return_value=raw_socket) as dial:
            conn.connect()
        dial.assert_called_once_with((PUBLIC, 443), 5.0)
        conn._context.wrap_socket.assert_called_once_with(raw_socket, server_hostname="hook.example.com")

    def test_a_mixed_answer_with_any_private_address_is_refused_whole(self):
        resolver = lambda *a, **k: records(PUBLIC, "10.0.0.5")  # noqa: E731
        with self.assertRaisesRegex(BridgeError, "non-public"):
            _public_addresses("hook.example.com", 443, resolver=resolver)

    def test_resolver_failures_and_empty_answers_are_refused(self):
        def failing(*_a, **_k):
            raise OSError("lookup failed")

        with self.assertRaisesRegex(BridgeError, "DNS lookup failed"):
            _public_addresses("hook.example.com", 443, resolver=failing)
        with self.assertRaisesRegex(BridgeError, "no usable public address"):
            _public_addresses("hook.example.com", 443, resolver=lambda *a, **k: [])
        with self.assertRaisesRegex(BridgeError, "invalid address"):
            _public_addresses("hook.example.com", 443, resolver=lambda *a, **k: records("not-an-ip"))

    def test_duplicate_addresses_are_collapsed_and_order_is_kept(self):
        resolver = lambda *a, **k: records(PUBLIC, "1.1.1.1", PUBLIC)  # noqa: E731
        self.assertEqual(_public_addresses("hook.example.com", 443, resolver=resolver), [PUBLIC, "1.1.1.1"])


class EndpointSettingsTests(NoNetworkCase):
    def refused(self, message, **overrides):
        with self.assertRaisesRegex(BridgeError, message):
            _validate_settings({**self.settings, **overrides}, str(self.root))

    def test_valid_settings_are_accepted(self):
        parsed, name, auth, _inbox = _validate_settings(self.settings, str(self.root))
        self.assertEqual((parsed.hostname, name, auth), ("hook.example.com", "Authorization",
                                                         "Bearer " + SENDER_KEY))

    def test_endpoint_host_must_equal_the_pinned_host_ignoring_case(self):
        self.refused("pinned host", allowed_host="other.example.com")
        _validate_settings({**self.settings, "endpoint_url": "https://HOOK.example.com/route"}, str(self.root))

    def test_only_https_without_user_info_or_fragment(self):
        self.refused("HTTPS", endpoint_url="http://hook.example.com/route")
        self.refused("HTTPS", endpoint_url="https://user" + "@hook.example.com/route")
        self.refused("pinned host", endpoint_url=URL + "#fragment")

    def test_ip_literals_and_local_or_reserved_names_are_refused(self):
        self.refused("DNS hostname", endpoint_url="https://203.0.113.9/x", allowed_host="203.0.113.9")
        for host in ("localhost", "app.localhost", "printer.local", "db.internal", "metadata.google.internal",
                     "hook.test"):
            with self.subTest(host=host):
                self.refused("local or reserved", endpoint_url="https://%s/x" % host, allowed_host=host)

    def test_reserved_or_malformed_header_names_are_refused(self):
        for name in ("Host", "Content-Length", "Cookie", "Transfer-Encoding", "Upgrade"):
            with self.subTest(name=name):
                self.refused("invalid or reserved", header_name=name)
        self.refused("invalid or reserved", header_name="Bad Header")
        self.refused("invalid characters", header_name="X-Key\n")

    def test_incomplete_unsupported_or_oversize_settings_are_refused(self):
        self.refused("unsupported", format_version=2)
        self.refused("incomplete", sender_key="")
        self.refused("incomplete", header_value_prefix=None)
        self.refused("size limit", header_value_prefix="p" * 9000)

    def test_inbox_must_equal_the_verified_root(self):
        with self.assertRaisesRegex(BridgeError, "does not match"):
            _validate_settings(self.settings, str(self.root / "other"))

    def test_without_a_configured_verified_root_the_default_refuses(self):
        with patch.dict("os.environ", {webhook_bridge.INBOX_ROOT_ENV: ""}):
            with self.assertRaisesRegex(BridgeError, "no verified inbox configured"):
                run_transaction(self.envelope, receipt_dir=self.receipts)


class TransactionRefusalTests(NoNetworkCase):
    def refused(self, message, **overrides):
        with self.assertRaisesRegex(BridgeError, message):
            self.run_tx({**self.envelope, **overrides})

    def test_content_bounds_and_wait_bounds(self):
        self.refused("empty or exceeds", content="")
        self.refused("empty or exceeds", content="   ")
        self.refused("empty or exceeds", content="x" * (MAX_CONTENT_CHARS + 1))
        for wait in (0, 181, True, 2.5, "5"):
            with self.subTest(wait=wait):
                self.refused("wait timeout", wait_seconds=wait)

    def test_unknown_source_or_missing_settings_are_refused(self):
        self.refused("request is invalid", source="agent-z")
        self.refused("request is invalid", settings=None)

    def test_a_concurrent_transaction_is_refused_by_the_lock(self):
        self.receipts.mkdir()
        (self.receipts / "peer-webhook.lock").write_text("1")
        self.refused("another webhook transaction")

    def test_corrupt_receipt_is_refused_not_overwritten(self):
        self.receipts.mkdir()
        receipt = self.receipts / "peer-webhook-pending.json"
        receipt.write_text("{bad", encoding="utf-8")
        self.refused("receipt is invalid")
        self.assertEqual(receipt.read_text(encoding="utf-8"), "{bad")

    def test_pending_task_from_another_source_blocks_a_new_request(self):
        self.prepare()
        self.refused("does not match this request", source="agent-a")

    def test_unknown_pending_state_is_not_resumable(self):
        prepared = self.prepare()
        receipt = self.receipts / "peer-webhook-pending.json"
        data = json.loads(receipt.read_text(encoding="utf-8"))
        data["state"] = "bogus"
        receipt.write_text(json.dumps(data), encoding="utf-8")
        self.refused("not resumable", approval_digest=prepared["payload_sha256"])

    def test_http_rejection_is_recorded_and_never_retried(self):
        prepared = self.prepare()
        calls = []
        approved = {**self.envelope, "approval_digest": prepared["payload_sha256"]}
        with self.assertRaisesRegex(BridgeError, "HTTP 500"):
            self.run_tx(approved, sender=lambda *a: calls.append(a) or 500)
        state = json.loads((self.receipts / "peer-webhook-pending.json").read_text(encoding="utf-8"))["state"]
        self.assertEqual(state, "http_rejected")
        again = self.run_tx(sender=lambda *a: calls.append(a) or 200)
        self.assertEqual(again["state"], "prepared")
        self.assertNotEqual(again["task_id"], prepared["task_id"])
        self.assertEqual(len(calls), 1)

    def test_malformed_approval_digests_never_reach_the_sender(self):
        self.prepare()
        calls = []
        for value in ("short", "G" * 64, 12345, None, ""):
            with self.subTest(value=value):
                result = self.run_tx({**self.envelope, "approval_digest": value}, sender=lambda *a: calls.append(a) or 200)
                self.assertEqual(result["state"], "approval_required")
        self.assertEqual(calls, [])

    def test_receipt_never_records_the_endpoint_credential_or_content(self):
        self.prepare()
        text = (self.receipts / "peer-webhook-pending.json").read_text(encoding="utf-8")
        for secret in (SENDER_KEY, "Review this.", "hook.example.com"):
            self.assertNotIn(secret, text)


class ReplyRefusalTests(NoNetworkCase):
    def test_oversize_non_utf8_and_missing_replies(self):
        big = self.root / "big.md"
        big.write_bytes(b"x" * (MAX_REPLY_BYTES + 1))
        with self.assertRaisesRegex(BridgeError, "size limit"):
            _read_stable_reply(big, delay=0)
        bad = self.root / "bad.md"
        bad.write_bytes(b"\xff\xfe\xfa")
        with self.assertRaisesRegex(BridgeError, "UTF-8"):
            _read_stable_reply(bad, delay=0)
        self.assertIsNone(_read_stable_reply(self.root / "missing.md", delay=0))
        self.assertIsNone(_read_stable_reply(self.root, delay=0))

    def test_a_reply_that_changes_between_reads_is_not_accepted(self):
        reply = self.root / "changing.md"
        reply.write_bytes(b"first")
        with patch("hub.webhook_bridge.time.sleep", side_effect=lambda _s: reply.write_bytes(b"second")):
            self.assertIsNone(_read_stable_reply(reply, delay=0.01))

    def test_reply_path_accepts_only_known_sources_and_well_formed_ids(self):
        task_id = "T" + "a" * 32
        self.assertEqual(_reply_path(self.root, "agent-a", task_id).name, "FOR-AGENT-A-%s.md" % task_id)
        for source, ident in (("agent-z", task_id), ("agent-a", "T" + "a" * 31), ("agent-a", "t" + "a" * 32),
                              ("agent-a", task_id + "/..")):
            with self.subTest(source=source, ident=ident), self.assertRaises(BridgeError):
                _reply_path(self.root, source, ident)


class EntryPointInputTests(NoNetworkCase):
    class Stdin:
        def __init__(self, data):
            self.buffer = io.BytesIO(data)

    def run_main(self, data):
        err, out = io.StringIO(), io.StringIO()
        with patch("sys.stdin", self.Stdin(data)), redirect_stderr(err), redirect_stdout(out):
            code = webhook_bridge.main()
        self.assertEqual(out.getvalue(), "")
        return code, json.loads(base64.b64decode(err.getvalue().strip()))

    def test_malformed_input_exits_with_a_generic_error_and_no_traceback(self):
        for data in (b"!!!not-base64!!!", base64.b64encode(b"garbage, not json"), b""):
            with self.subTest(data=data[:10]):
                code, reply = self.run_main(data)
                self.assertEqual(code, 2)
                self.assertEqual(reply, {"state": "error", "error": "invalid bridge input"})

    def test_oversize_request_is_refused_before_decoding(self):
        code, reply = self.run_main(b"A" * (2 * webhook_bridge.MAX_REQUEST_BYTES))
        self.assertEqual(code, 2)
        self.assertEqual(reply["error"], "request exceeds the size limit")


class InboxRootConfigTests(NoNetworkCase):
    def test_unset_inbox_root_refuses(self):
        with patch.dict("os.environ", {webhook_bridge.INBOX_ROOT_ENV: ""}):
            with self.assertRaisesRegex(BridgeError, "no verified inbox configured"):
                run_transaction(self.envelope, receipt_dir=self.receipts)

    def test_inbox_root_from_environment_is_used(self):
        with patch.dict("os.environ", {webhook_bridge.INBOX_ROOT_ENV: str(self.root)}):
            prepared = run_transaction(self.envelope, receipt_dir=self.receipts)
        self.assertEqual(prepared["state"], "prepared")

    def test_environment_root_must_match_configured_inbox(self):
        other = Path(self.temp.name) / "elsewhere"
        other.mkdir()
        with patch.dict("os.environ", {webhook_bridge.INBOX_ROOT_ENV: str(other)}):
            with self.assertRaisesRegex(BridgeError, "does not match"):
                run_transaction(self.envelope, receipt_dir=self.receipts)


if __name__ == "__main__":
    unittest.main()
