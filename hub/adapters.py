"""Fail-closed adapters for verified local text-only agent CLIs."""
from __future__ import annotations

import os
import subprocess
import threading
import time
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


class AdapterError(RuntimeError):
    pass


class AdapterCancelled(AdapterError):
    """Raised only after process-tree termination was confirmed."""
    pass


@dataclass(frozen=True)
class AdapterConfig:
    name: str
    executable: str
    enabled: bool = False
    timeout_seconds: int = 300
    max_output_bytes: int = 65536
    model: str = ""
    provider_key_env: str = ""
    use_native_profile: bool = False


PROVIDER_KEY_ENV_ALLOWLIST = {"PROVIDER_A_API_KEY", "PROVIDER_B_API_KEY", "PROVIDER_C_API_KEY", "PROVIDER_D_API_KEY"}


class CLIAdapter:
    """A deliberately narrow adapter: fixed argv, text over stdin, bounded output."""
    name = "base"

    def __init__(self, config: AdapterConfig):
        self.config = config

    def argv(self) -> Sequence[str]:
        raise NotImplementedError

    def prompt_argv(self, prompt: str) -> Sequence[str]:
        return self.argv()

    def extra_environment(self, cwd: Path) -> dict[str, str]:
        return {}

    def stdin_payload(self, prompt: str) -> bytes:
        return prompt.encode("utf-8")

    def run(self, prompt: str, *, cwd: Path, timeout_seconds: int | None = None, cancel_event=None) -> str:
        if not self.config.enabled:
            raise AdapterError(f"{self.name} adapter is disabled")
        if not self.config.executable or not Path(self.config.executable).is_file():
            raise AdapterError(f"{self.name} executable is unavailable")
        if not isinstance(prompt, str) or not prompt.strip():
            raise AdapterError("prompt must be non-empty text")
        if len(prompt.encode("utf-8")) > 1_000_000:
            raise AdapterError("prompt exceeds the 1 MB limit")
        cwd = cwd.resolve(strict=True)
        if self.config.use_native_profile and self.name != "agent-b":
            raise AdapterError("native profile opt-in is supported only for Agent B")
        env = {k: v for k, v in os.environ.items() if k in {"SYSTEMROOT", "WINDIR"}}
        native_profile = {}
        if self.config.use_native_profile:
            # Explicitly reuse only Agent B's profile-location variables. Keep
            # temp files task-local and do not inherit arbitrary user secrets.
            for key in ("USERPROFILE", "APPDATA", "LOCALAPPDATA", "HOME"):
                if os.environ.get(key):
                    native_profile[key] = os.environ[key]
        client_home = cwd / ".client-home"
        client_home.mkdir(exist_ok=True)
        temp_dir = cwd / ".temp"
        temp_dir.mkdir(exist_ok=True)
        env.update({"TEMP": str(temp_dir), "TMP": str(temp_dir), "HOME": str(client_home),
                    "USERPROFILE": str(client_home), "APPDATA": str(client_home / "AppData" / "Roaming"),
                    "LOCALAPPDATA": str(client_home / "AppData" / "Local")})
        env.update(native_profile)
        provider_secret = None
        if self.config.provider_key_env:
            if self.config.provider_key_env not in PROVIDER_KEY_ENV_ALLOWLIST:
                raise AdapterError("provider credential environment name is not allowlisted")
            provider_secret = os.environ.get(self.config.provider_key_env)
            if not provider_secret:
                raise AdapterError("explicit provider credential is unavailable")
            env[self.config.provider_key_env] = provider_secret
        env.update(self.extra_environment(cwd))
        try:
            argv = [self.config.executable, *self.prompt_argv(prompt)]
            proc = subprocess.Popen(argv, cwd=str(cwd), stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env,
                shell=False, creationflags=(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) |
                                            getattr(subprocess, "CREATE_NO_WINDOW", 0)))
            chunks: list[bytes] = []
            retained = 0
            def drain() -> None:
                nonlocal retained
                while True:
                    block = proc.stdout.read(4096)
                    if not block:
                        break
                    room = self.config.max_output_bytes - retained
                    if room > 0:
                        chunks.append(block[:room])
                        retained += min(room, len(block))
            reader = threading.Thread(target=drain, daemon=True)
            reader.start()
            def write_prompt() -> None:
                try:
                    proc.stdin.write(self.stdin_payload(prompt))
                    proc.stdin.close()
                except (BrokenPipeError, OSError):
                    pass
            writer = threading.Thread(target=write_prompt, daemon=True)
            writer.start()
            try:
                deadline = time.monotonic() + (timeout_seconds or self.config.timeout_seconds)
                while proc.poll() is None:
                    if cancel_event is not None and cancel_event.is_set():
                        _stop_process_tree(proc)
                        raise AdapterCancelled(f"{self.name} cancelled by broker")
                    if time.monotonic() >= deadline:
                        _stop_process_tree(proc)
                        raise AdapterError(f"{self.name} timed out")
                    time.sleep(0.1)
                if cancel_event is not None and cancel_event.is_set():
                    # The child exited concurrently with cancellation. We cannot
                    # prove that descendants also stopped after its exit.
                    raise AdapterError("process tree termination unconfirmed: child exited during cancellation")
            finally:
                writer.join(timeout=2)
                reader.join(timeout=5)
                proc.stdout.close()
        except OSError as exc:
            raise AdapterError(f"{self.name} could not start: {exc}") from None
        out = b"".join(chunks)
        text = out.decode("utf-8", errors="replace")
        if provider_secret:
            text = text.replace(provider_secret, "[REDACTED]")
        if proc.returncode:
            raise AdapterError(f"{self.name} exited {proc.returncode}: {text[-2000:]}")
        return text


def _stop_process_tree(proc: subprocess.Popen) -> None:
    if os.name == "nt":
        # taskkill receives a numeric PID, not interpolated command text.
        system_root = os.environ.get("SYSTEMROOT", r"C:\Windows")
        taskkill = str(Path(system_root) / "System32" / "taskkill.exe")
        try:
            outcome = subprocess.run([taskkill, "/PID", str(proc.pid), "/T", "/F"],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, timeout=10, check=False, shell=False)
        except (OSError, subprocess.TimeoutExpired):
            raise AdapterError("Windows process tree termination unconfirmed") from None
        if outcome.returncode != 0:
            raise AdapterError("Windows process tree termination unconfirmed")
    else:
        proc.kill()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        raise AdapterError("process tree termination unconfirmed: root process did not exit") from None


class AgentAAdapter(CLIAdapter):
    name = "agent-a"

    def argv(self) -> Sequence[str]:
        # Verified local help: exec reads prompt from stdin; read-only and ephemeral.
        if self.config.model != "example-model":
            raise AdapterError("Agent A model must be explicitly set to example-model")
        return ["exec", "--ephemeral", "--ignore-user-config", "--skip-git-repo-check",
                "--sandbox", "read-only", "--model", self.config.model, "--json", "-"]

    def extra_environment(self, cwd: Path) -> dict[str, str]:
        isolated = cwd / ".agent-a-home"
        isolated.mkdir(exist_ok=True)
        return {"AGENT_A_HOME": str(isolated)}


class AgentBAdapter(CLIAdapter):
    name = "agent-b"

    def argv(self) -> Sequence[str]:
        if not self.config.model:
            raise AdapterError("Agent B model must be explicitly configured")
        return ["run", "--format", "json"]

    def prompt_argv(self, prompt: str) -> Sequence[str]:
        # The CLI's verified run syntax takes a message argument. It is one argv
        # element and is never passed through a shell.
        if len(prompt.encode("utf-16-le")) > 20000:
            raise AdapterError("Agent B message exceeds the safe Windows command-line limit")
        return [*self.argv(), "--model", self.config.model, prompt]

    def stdin_payload(self, prompt: str) -> bytes:
        return b""

    def extra_environment(self, cwd: Path) -> dict[str, str]:
        # Request a tool-deny overlay for this invocation. This is a CLI config
        # preference, not an OS boundary, and managed config may override it.
        return {"AGENT_B_CONFIG_CONTENT": json.dumps({"permission": {"*": "deny"}})}


class AgentDAdapter(CLIAdapter):
    name = "agent-d"

    def run(self, prompt: str, *, cwd: Path, timeout_seconds: int | None = None, cancel_event=None) -> str:
        raise AdapterError("Agent D has no verified CLI; adapter unavailable")

    def argv(self) -> Sequence[str]:
        raise AdapterError("Agent D has no verified CLI; adapter unavailable")


def make_adapter(name: str, config: dict) -> CLIAdapter:
    classes = {"agent-a": AgentAAdapter, "agent-b": AgentBAdapter, "agent-d": AgentDAdapter}
    if name not in classes:
        raise AdapterError(f"unknown adapter: {name}")
    return classes[name](AdapterConfig(name=name, executable=config.get("executable", ""),
        enabled=bool(config.get("enabled", False)), timeout_seconds=int(config.get("timeout_seconds", 300)),
        max_output_bytes=min(262144, max(1024, int(config.get("max_output_bytes", 65536)))),
        model=str(config.get("model", "")), provider_key_env=str(config.get("provider_key_env", "")),
        use_native_profile=(config.get("use_native_profile", False) is True)))

