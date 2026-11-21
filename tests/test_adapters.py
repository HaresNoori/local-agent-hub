import json
import os
import sys
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from hub.adapters import AdapterCancelled, AdapterConfig, AdapterError, CLIAdapter, AgentAAdapter, AgentDAdapter, AgentBAdapter, _stop_process_tree
from hub.worker import _is_confirmed_cancellation


class PythonFixture(CLIAdapter):
    name = "fixture"
    def __init__(self, config, code):
        super().__init__(config)
        self.code = code
    def argv(self):
        return ["-c", self.code]


class AgentBEnvironmentFixture(PythonFixture):
    name = "agent-b"
    def extra_environment(self, cwd):
        return AgentBAdapter(AdapterConfig("agent-b", "unused", model="fixture")).extra_environment(cwd)


class AdapterTests(unittest.TestCase):
    def config(self, **kwargs):
        return AdapterConfig("fixture", sys.executable, enabled=True,
                             timeout_seconds=kwargs.get("timeout", 3),
                             max_output_bytes=kwargs.get("output", 1024))

    def test_fixed_argv_stdin_and_isolated_working_directory(self):
        script = "import os,sys; print(os.getcwd()); print(sys.stdin.read())"
        with tempfile.TemporaryDirectory() as root:
            result = PythonFixture(self.config(), script).run("hello; harmless text", cwd=Path(root))
        self.assertIn(root, result)
        self.assertIn("hello; harmless text", result)

    def test_output_is_capped(self):
        with tempfile.TemporaryDirectory() as root:
            result = PythonFixture(self.config(output=1024), "print('x'*50000)").run("go", cwd=Path(root))
        self.assertLessEqual(len(result.encode()), 1024)

    def test_timeout_stops_child(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(AdapterError, "timed out"):
                PythonFixture(self.config(timeout=1), "import time; time.sleep(10)").run("go", cwd=Path(root))

    @unittest.skipUnless(os.name == "nt", "Windows process-tree behavior")
    def test_nonzero_taskkill_cannot_acknowledge_tree_cancellation(self):
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, shell=False)
        try:
            with patch("hub.adapters.subprocess.run", return_value=subprocess.CompletedProcess([], 1)):
                with self.assertRaisesRegex(AdapterError, "tree termination unconfirmed"):
                    _stop_process_tree(proc)
            self.assertFalse(_is_confirmed_cancellation(
                AdapterError("Windows process tree termination unconfirmed"), []))
            self.assertFalse(_is_confirmed_cancellation(
                AdapterError("fixture exited 1: cancelled by broker"), []))
            self.assertTrue(_is_confirmed_cancellation(AdapterCancelled("fixture cancelled by broker"), []))
            self.assertIsNone(proc.poll(), "fixture process remains alive when tree termination is unconfirmed")
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=5)

    def test_cancellation_stops_child(self):
        event = threading.Event()
        timer = threading.Timer(0.3, event.set)
        timer.start()
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(AdapterError, "cancelled by broker"):
                PythonFixture(self.config(timeout=4), "import time; time.sleep(10)").run("go", cwd=Path(root), cancel_event=event)
        timer.cancel()

    def test_agent_d_and_unconfigured_agent_b_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(AdapterError, "no verified CLI"):
                AgentDAdapter(AdapterConfig("agent-d", "", enabled=True)).run("x", cwd=Path(root))
            with self.assertRaisesRegex(AdapterError, "disabled"):
                AgentBAdapter(AdapterConfig("agent-b", "unused", enabled=False)).run("x", cwd=Path(root))

    def test_verified_cli_invocations_are_fixed_and_tools_are_denied(self):
        with tempfile.TemporaryDirectory() as root:
            cwd = Path(root)
            agent_a = AgentAAdapter(AdapterConfig("agent-a", "agent-a.exe", enabled=True, model="example-model"))
            self.assertIn("--sandbox", agent_a.argv())
            self.assertIn("read-only", agent_a.argv())
            self.assertIn("--skip-git-repo-check", agent_a.argv())
            self.assertIn("example-model", agent_a.argv())
            self.assertEqual(agent_a.stdin_payload("prompt"), b"prompt")
            agent_b = AgentBAdapter(AdapterConfig("agent-b", "agent-b-cli.exe", enabled=True,
                                                       model="provider/example-model"))
            self.assertEqual(agent_b.prompt_argv("literal; text"),
                             ["run", "--format", "json", "--model", "provider/example-model", "literal; text"])
            self.assertEqual(agent_b.stdin_payload("prompt"), b"")
            self.assertEqual(json.loads(agent_b.extra_environment(cwd)["AGENT_B_CONFIG_CONTENT"]),
                             {"permission": {"*": "deny"}})

    def test_native_agent_b_profile_is_explicit_and_keeps_task_temp_and_deny_overlay(self):
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, {
                "USERPROFILE": r"C:\\Users\\profile-test",
                "APPDATA": r"C:\\Users\\profile-test\\AppData\\Roaming",
                "LOCALAPPDATA": r"C:\\Users\\profile-test\\AppData\\Local",
                "HOME": r"C:\\Users\\profile-test",
                "UNRELATED_SECRET": "must-not-pass"}, clear=False):
            cwd = Path(root)
            isolated = AgentBEnvironmentFixture(AdapterConfig("agent-b", sys.executable,
                enabled=True), "import os,json; print(json.dumps({k:os.getenv(k) for k in ('USERPROFILE','APPDATA','LOCALAPPDATA','HOME','TEMP','UNRELATED_SECRET','AGENT_B_CONFIG_CONTENT')}))")
            default = json.loads(isolated.run("go", cwd=cwd))
            self.assertEqual(default["USERPROFILE"], str(cwd / ".client-home"))
            self.assertIsNone(default["UNRELATED_SECRET"])
            self.assertIn(str(cwd / ".temp"), default["TEMP"])

            native = AgentBEnvironmentFixture(AdapterConfig("agent-b", sys.executable,
                enabled=True, use_native_profile=True), isolated.code)
            reused = json.loads(native.run("go", cwd=cwd))
            self.assertEqual(reused["USERPROFILE"], r"C:\\Users\\profile-test")
            self.assertEqual(reused["APPDATA"], r"C:\\Users\\profile-test\\AppData\\Roaming")
            self.assertEqual(reused["LOCALAPPDATA"], r"C:\\Users\\profile-test\\AppData\\Local")
            self.assertEqual(reused["HOME"], r"C:\\Users\\profile-test")
            self.assertIn(str(cwd / ".temp"), reused["TEMP"])
            self.assertIsNone(reused["UNRELATED_SECRET"])
            self.assertEqual(json.loads(reused["AGENT_B_CONFIG_CONTENT"]),
                             {"permission": {"*": "deny"}})

    def test_native_profile_keeps_regular_run_command_and_is_rejected_for_agent_a(self):
        adapter = AgentBAdapter(AdapterConfig("agent-b", "agent-b-cli.exe", enabled=True,
                                                model="provider/model", use_native_profile=True))
        self.assertEqual(adapter.prompt_argv("literal"),
                         ["run", "--format", "json", "--model", "provider/model", "literal"])
        agent_a = AgentAAdapter(AdapterConfig("agent-a", sys.executable, enabled=True,
                                           model="example-model", use_native_profile=True))
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(AdapterError, "only for Agent B"):
                agent_a.run("go", cwd=Path(root))

    def test_only_explicit_provider_key_is_forwarded_and_output_redacted(self):
        provider_secret = "test-key-never-return-this"
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, {
                "PROVIDER_A_API_KEY": provider_secret, "HUB_COORDINATOR_TOKEN": "coordinator-secret",
                "HUB_WORKER_TOKEN": "worker-secret"}):
            adapter = PythonFixture(AdapterConfig("fixture", sys.executable, enabled=True,
                provider_key_env="PROVIDER_A_API_KEY"),
                "import os; print(os.getenv('PROVIDER_A_API_KEY')); print(os.getenv('HUB_COORDINATOR_TOKEN')); print(os.getenv('HUB_WORKER_TOKEN'))")
            result = adapter.run("go", cwd=Path(root))
        self.assertNotIn(provider_secret, result)
        self.assertIn("[REDACTED]", result)
        self.assertIn("None", result)


if __name__ == "__main__":
    unittest.main()
