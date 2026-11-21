"""Opt-in GitHub issue-comment bridge. Imports never start polling."""
from __future__ import annotations

import hashlib
import json
import os
import argparse
import re
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .github_client import GitHubClient, GitHubError

MAX_TASK_BODY = 16_384
MAX_PAGES = 10
TASK_KEYS = {"schema", "action", "workspace", "prompt", "adapter", "target_worker", "priority",
             "depends_on", "timeout_seconds", "cost_reserved", "task_id"}
ADAPTERS = {"agent-a", "agent-b"}
_ID = re.compile(r"^[1-9][0-9]{0,17}$")
_TASK_ID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
_MARKER = re.compile(r"<!-- local-agent-hub-delivery:([a-f0-9]{64}) -->")


class RelayError(RuntimeError):
    pass


class PermanentReject(RelayError):
    """Untrusted source event failed local validation; safe to advance past."""


class TransientRelayError(RelayError):
    """Remote/local transport issue; preserve cursor and retry later."""


def _int_id(value, name):
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise RelayError(f"{name} must be a positive numeric GitHub ID")
    return value


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(value):
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _safe_cursor_timestamp(value):
    if not isinstance(value, str) or len(value) > 40:
        raise RelayError("invalid cursor timestamp")
    # GitHub accepts ISO-8601 strings. Restrict syntax before putting it in a query.
    if not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value):
        raise RelayError("cursor must be UTC ISO-8601")
    return value


def parse_envelope(body: str, *, allowed_targets: set[str], max_prompt_chars=12_000,
                   max_timeout=1800, max_cost=25.0):
    """Parse only a narrow JSON schema; never interpret shell or markdown commands."""
    if not isinstance(body, str) or not body or len(body.encode("utf-8")) > MAX_TASK_BODY:
        raise RelayError("comment body missing or exceeds the task size limit")
    try:
        value = json.loads(body)
    except (json.JSONDecodeError, UnicodeError):
        raise RelayError("comment must contain one JSON task envelope") from None
    if not isinstance(value, dict) or set(value) - TASK_KEYS:
        raise RelayError("task envelope has unknown fields")
    if value.get("schema") != "local-agent-hub/task-v1":
        raise RelayError("unsupported task schema")
    action = value.get("action")
    if action == "dispatch":
        required = {"schema", "action", "workspace", "prompt", "adapter", "target_worker", "priority",
                    "depends_on", "timeout_seconds", "cost_reserved"}
        if set(value) != required:
            raise RelayError("dispatch envelope fields do not match task-v1")
        workspace, prompt, adapter, target = value["workspace"], value["prompt"], value["adapter"], value["target_worker"]
        if not isinstance(workspace, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", workspace):
            raise RelayError("workspace must be a configured alias")
        if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > max_prompt_chars:
            raise RelayError("prompt is empty or exceeds configured limit")
        if not isinstance(adapter, str) or adapter not in ADAPTERS:
            raise RelayError("adapter is not in the supported target allowlist")
        if not isinstance(target, str) or target not in allowed_targets:
            raise RelayError("target_worker is not in the configured allowlist")
        priority = value["priority"]
        if isinstance(priority, bool) or not isinstance(priority, int) or not -100 <= priority <= 100:
            raise RelayError("priority must be an integer from -100 to 100")
        deps = value["depends_on"]
        if not isinstance(deps, list) or len(deps) > 20 or any(not isinstance(x, str) or not _TASK_ID.fullmatch(x) for x in deps):
            raise RelayError("depends_on must contain at most 20 task IDs")
        timeout = value["timeout_seconds"]
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= max_timeout:
            raise RelayError("timeout_seconds exceeds configured bound")
        cost = value["cost_reserved"]
        if isinstance(cost, bool) or not isinstance(cost, (int, float)) or not 0 <= cost <= max_cost:
            raise RelayError("cost_reserved exceeds configured bound")
        return {"action": action, "workspace": workspace, "prompt": prompt, "adapter": adapter,
                "target_worker": target, "priority": priority, "depends_on": deps,
                "timeout_seconds": timeout, "cost_reserved": float(cost)}
    if action == "cancel":
        if set(value) != {"schema", "action", "task_id"}:
            raise RelayError("cancel envelope fields do not match task-v1")
        task_id = value["task_id"]
        if not isinstance(task_id, str) or not _TASK_ID.fullmatch(task_id):
            raise RelayError("task_id must be a broker task UUID")
        return {"action": action, "task_id": task_id}
    raise RelayError("unsupported task action")


class RelayBrokerClient:
    """Narrow relay-role HTTP client; never uses coordinator credentials."""
    def __init__(self, base_url: str, token: str, *, opener=None, timeout=10):
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1"} or parsed.username or parsed.password or parsed.path not in ("", "/"):
            raise ValueError("broker URL must be plain HTTP on a loopback IP literal")
        if not token:
            raise ValueError("relay token is required")
        self.base_url = base_url.rstrip("/")
        self._token = token
        self._opener = opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect())
        self.timeout = max(1, min(int(timeout), 20))

    def call(self, method, path, payload=None):
        if not path.startswith("/v1/relay/") or path.startswith("//") or ".." in path or "#" in path:
            raise ValueError("relay broker path is outside the relay-only API")
        data = None if payload is None else _canonical(payload).encode()
        request = urllib.request.Request(self.base_url + path, data=data, method=method,
            headers={"Authorization": "Bearer " + self._token, "Content-Type": "application/json"})
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                raw = response.read(1_000_001)
                if len(raw) > 1_000_000:
                    raise TransientRelayError("broker response exceeded bound")
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            if exc.code == 429 or exc.code >= 500:
                raise TransientRelayError(f"broker relay API returned HTTP {exc.code}") from None
            raise RelayError(f"broker relay API returned HTTP {exc.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise TransientRelayError("broker relay API transport failed") from None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class CursorFile:
    """Small atomic local cursor. Mapping uniqueness in Store remains authoritative."""
    def __init__(self, path):
        self.path = Path(path).resolve()

    def read(self):
        state = self.read_state()
        return state["since"] if state else None

    def read_state(self):
        if not self.path.exists():
            return None
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
            page = value.get("page", 1)
            if isinstance(page, bool) or not isinstance(page, int) or not 1 <= page <= 200:
                raise ValueError
            return {"since": _safe_cursor_timestamp(value["since"]), "page": page}
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            raise RelayError("relay cursor file is invalid; manual review required") from None

    def write(self, since, page=1):
        since = _safe_cursor_timestamp(since)
        if isinstance(page, bool) or not isinstance(page, int) or not 1 <= page <= 200:
            raise RelayError("relay cursor page is invalid")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp = tempfile.mkstemp(prefix=".relay-cursor-", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                json.dump({"since": since, "page": page}, stream, separators=(",", ":"))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, self.path)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)


class GitHubRelay:
    def __init__(self, config: dict, github: GitHubClient, broker: RelayBrokerClient,
                 cursor: CursorFile):
        self.config = config
        self.github, self.broker, self.cursor = github, broker, cursor
        self.owner, self.repo = config["owner"], config["repo"]
        self.repo_id = _int_id(config["repository_id"], "repository_id")
        self.allowed_authors = {_int_id(x, "allowed_user_id") for x in config["allowed_user_ids"]}
        self.allowed_targets = set(config["allowed_targets"])
        self.source = f"github:{self.repo_id}"
        self._secrets = [os.environ.get(config.get("github_token_env", ""), "")]
        self._publisher_verified = False

    def _scrub(self, value):
        if isinstance(value, dict):
            return {k: self._scrub(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._scrub(v) for v in value]
        if isinstance(value, str):
            for secret in self._secrets:
                if secret:
                    value = value.replace(secret, "[REDACTED]")
            return value
        return value

    def verify_repository(self):
        repo = self.github.get_repo(self.owner, self.repo)
        if not isinstance(repo, dict) or repo.get("id") != self.repo_id or repo.get("private") is not True:
            raise RelayError("repository identity/private check failed; relay remains stopped")
        actual_owner = (repo.get("owner") or {}).get("login")
        if not isinstance(actual_owner, str) or actual_owner.casefold() != self.owner.casefold() or repo.get("name", "").casefold() != self.repo.casefold():
            raise RelayError("repository owner/name check failed")
        return repo

    def verify_publisher(self):
        if self._publisher_verified:
            return
        expected = self.config.get("publisher_user_id")
        if isinstance(expected, bool) or not isinstance(expected, int) or expected <= 0:
            raise RelayError("publisher_user_id must be a positive numeric user ID")
        user = self.github.get_authenticated_user()
        if not isinstance(user, dict) or user.get("id") != expected:
            raise RelayError("GitHub credential does not authenticate as the pinned publisher")
        self._publisher_verified = True

    def _verified_comment(self, comment, expected_body, issue_number):
        """Require a complete REST receipt and matching GraphQL publication provenance."""
        if not isinstance(comment, dict):
            return None
        comment_id = comment.get("id")
        node_id = comment.get("node_id")
        publisher_id = self.config.get("publisher_user_id")
        expected_url = (f"https://github.com/{self.owner}/{self.repo}/issues/"
                        f"{issue_number}#issuecomment-{comment_id}")
        if (isinstance(comment_id, bool) or not isinstance(comment_id, int) or comment_id <= 0
                or not isinstance(node_id, str) or not node_id or len(node_id) > 200
                or comment.get("body") != expected_body
                or not isinstance(comment.get("user"), dict)
                or comment["user"].get("id") != publisher_id
                or comment.get("html_url") != expected_url
                or comment.get("issue_url") != f"https://api.github.com/repos/{self.owner}/{self.repo}/issues/{issue_number}"):
            return None
        proof = self.github.comment_provenance(node_id)
        if (proof.get("database_id") != comment_id or proof.get("body") != expected_body
                or proof.get("repository_id") != self.repo_id or proof.get("issue_number") != issue_number
                or proof.get("issue_type") != "Issue" or proof.get("author_id") != publisher_id
                or proof.get("author_type") != "User"
                or (proof.get("last_edited_at") is not None
                    and (proof.get("editor_id") != publisher_id
                         or proof.get("editor_type") != "User"))):
            return None
        return {"comment_id": comment_id, "comment_node_id": node_id,
                "comment_url": expected_url, "body_sha256": hashlib.sha256(expected_body.encode("utf-8")).hexdigest(),
                "verification": "github_graphql_readback"}

    def _comments(self, since, start_page):
        maximum = int(self.config.get("max_pages_per_poll", 3))
        if not 1 <= maximum <= MAX_PAGES:
            raise RelayError("max_pages_per_poll is outside safe bounds")
        rows = []
        capped = False
        for page in range(start_page, start_page + maximum):
            items = self.github.list_comments_since(self.owner, self.repo, since=since,
                                                    page=page, per_page=100)
            if not isinstance(items, list):
                raise RelayError("GitHub comment listing returned an invalid response")
            rows.extend(items)
            if len(items) < 100:
                return rows, None
        capped = True
        return rows, page + 1

    def poll_once(self):
        self.verify_repository()
        state = self.cursor.read_state() or {"since": _safe_cursor_timestamp(self.config["initial_since_utc"]), "page": 1}
        previous, start_page = state["since"], state["page"]
        # One-second overlap protects equal-second updates; Store source mapping removes duplicates.
        since = previous
        events, next_page = self._comments(since, start_page)
        events.sort(key=lambda x: (str(x.get("updated_at", "")), int(x.get("id", 0))))
        max_seen = previous
        accepted = rejected = 0
        for event in events:
            try:
                self._process_comment(event)
                accepted += 1
            except PermanentReject:
                rejected += 1
            updated = event.get("updated_at")
            if isinstance(updated, str) and (max_seen is None or updated > max_seen):
                max_seen = updated
        if next_page is not None:
            # Resume the bounded page walk on the next poll. Do not advance time
            # until every page in this timestamp window has been processed.
            self.cursor.write(previous, next_page)
        elif max_seen:
            # GitHub timestamps are second precision; overlap on the next request.
            from datetime import datetime, timedelta, timezone
            stamp = datetime.strptime(_safe_cursor_timestamp(max_seen), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            overlap = (stamp - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
            self.cursor.write(overlap, 1)
        return {"accepted": accepted, "rejected": rejected, "seen": len(events), "page_cap_reached": next_page is not None}

    def _process_comment(self, event):
        if not isinstance(event, dict) or not isinstance(event.get("id"), int):
            raise PermanentReject("malformed issue comment")
        user = event.get("user") or {}
        try:
            sender_id = _int_id(user.get("id"), "comment author ID")
        except RelayError as exc:
            raise PermanentReject(str(exc)) from None
        if sender_id not in self.allowed_authors:
            raise PermanentReject("comment author is not allowed")
        try:
            parsed = parse_envelope(event.get("body"), allowed_targets=self.allowed_targets,
                                    max_prompt_chars=int(self.config.get("max_prompt_chars", 12_000)),
                                    max_timeout=int(self.config.get("max_timeout_seconds", 1800)),
                                    max_cost=float(self.config.get("max_cost_reserved", 25)))
        except RelayError as exc:
            raise PermanentReject(str(exc)) from None
        aliases = self.config.get("workspace_aliases", {})
        if parsed["action"] == "dispatch" and parsed["workspace"] not in aliases:
            raise PermanentReject("workspace alias is not configured locally")
        try:
            provenance = self.github.comment_provenance(event.get("node_id"))
        except ValueError:
            raise PermanentReject("GitHub comment provenance request is malformed") from None
        if (provenance.get("database_id") != event["id"] or provenance.get("author_id") != sender_id
                or provenance.get("body") != event.get("body")
                or provenance.get("repository_id") != self.repo_id
                or provenance.get("issue_type") != "Issue"
                or provenance.get("author_type") != "User"):
            raise PermanentReject("GraphQL identity or body snapshot does not match the REST comment")
        editor_id = provenance.get("editor_id")
        last_edited = provenance.get("last_edited_at")
        if last_edited is None:
            if editor_id is not None:
                raise PermanentReject("unexpected editor on an unedited comment")
        else:
            try:
                editor = _int_id(editor_id, "comment editor ID")
            except RelayError as exc:
                raise PermanentReject(str(exc)) from None
            if provenance.get("editor_type") != "User" or editor not in self.allowed_authors:
                raise PermanentReject("comment editor is not allowed")
        issue_url = event.get("issue_url")
        expected = f"https://api.github.com/repos/{self.owner}/{self.repo}/issues/"
        if not isinstance(issue_url, str) or not issue_url.startswith(expected):
            raise PermanentReject("comment issue URL is outside the pinned repository")
        number_text = issue_url[len(expected):]
        if not _ID.fullmatch(number_text):
            raise PermanentReject("comment issue URL is malformed")
        if provenance.get("issue_number") != int(number_text):
            raise PermanentReject("GraphQL issue identity does not match the REST comment")
        try:
            comment_id = _int_id(event["id"], "comment ID")
        except RelayError as exc:
            raise PermanentReject(str(exc)) from None
        parsed = self._scrub(parsed)
        body_digest = _digest(parsed)
        delivery_id = f"issue-comment:{comment_id}"
        if parsed["action"] == "cancel":
            self.broker.call("POST", f"/v1/relay/cancel/{urllib.parse.quote(parsed['task_id'], safe='')}",
                {"source": self.source, "sender_id": sender_id,
                 "reason": f"Authorized issue comment {comment_id} requested cancellation"})
            return
        body = {"workspace": self.config["workspace_aliases"][parsed["workspace"]],
                "payload": {"adapter": parsed["adapter"], "prompt": parsed["prompt"],
                            "relay_destination": {"issue_number": int(number_text)}},
                "idempotency_key": f"gh-{self.repo_id}-{comment_id}-{body_digest[:16]}",
                "action_class": "analysis", "timeout_seconds": parsed["timeout_seconds"],
                "cost_reserved": parsed["cost_reserved"], "target_worker": parsed["target_worker"],
                "priority": parsed["priority"], "depends_on": parsed["depends_on"],
                "relay_source": self.source, "relay_delivery_id": delivery_id,
                "relay_payload_digest": body_digest, "relay_sender_id": str(sender_id)}
        self.broker.call("POST", "/v1/relay/dispatch", body)

    def publish_one(self):
        """Publish an outbox item only after the local coordinator approved its digest."""
        self.verify_publisher()
        item = self.broker.call("POST", "/v1/relay/outbox/claim", {
            "lease_seconds": int(self.config.get("lease_seconds", 60))})
        if not item:
            return False
        if item.get("source") != self.source:
            raise RelayError("outbox source does not match the pinned repository")
        digest_value = item.get("approval_digest")
        if not isinstance(digest_value, str) or not re.fullmatch(r"[a-f0-9]{64}", digest_value):
            raise RelayError("outbox item has no valid approval digest")
        task = item.get("payload") or {}
        if task.get("source") != self.source or task.get("kind") != item.get("kind"):
            raise RelayError("outbox payload source or kind does not match its claim")
        destination = task.get("relay_destination") or {}
        issue_number = destination.get("issue_number")
        if isinstance(issue_number, bool) or not isinstance(issue_number, int) or issue_number <= 0:
            raise RelayError("outbox item lacks validated issue destination")
        marker = f"<!-- local-agent-hub-delivery:{digest_value} -->"
        text = self._format_result(task)
        expected_body = marker + "\n" + text
        # A marker alone is not proof: require exact content and the pinned publisher.
        found = False
        complete_scan = False
        for page in range(1, MAX_PAGES + 1):
            comments = self.github.list_comments(self.owner, self.repo, issue_number,
                                                 page=page, per_page=100)
            if not isinstance(comments, list):
                raise TransientRelayError("GitHub publication readback was invalid")
            for comment in comments:
                candidate_receipt = (self._verified_comment(comment, expected_body, issue_number)
                    if isinstance(comment, dict) and comment.get("user", {}).get("id") == self.config.get("publisher_user_id")
                    and comment.get("body") == expected_body else None)
                if candidate_receipt:
                    found = True
                    receipt = candidate_receipt
                    break
            if found:
                break
            if len(comments) < 100:
                complete_scan = True
                break
        if not found and not complete_scan:
            raise TransientRelayError("GitHub readback scan was capped; refusing a possibly duplicate post")
        if not found:
            current = self.broker.call("GET", f"/v1/relay/tasks/{urllib.parse.quote(item['task_id'], safe='')}?source={urllib.parse.quote(self.source, safe='')}")
            current_task = current.get("task", current) if isinstance(current, dict) else {}
            if (current_task.get("state") != task.get("state")
                    or ("cancellation_requested" in task and
                        bool(current_task.get("cancellation_requested")) != bool(task.get("cancellation_requested")))):
                self.broker.call("POST", "/v1/relay/outbox/complete", {
                    "outbox_id": item["id"], "worker_id": "relay", "lease_epoch": item["lease_epoch"],
                    "delivered": False, "error": "stale status snapshot; review required"})
                return True
            heartbeat = self.broker.call("POST", "/v1/relay/outbox/heartbeat", {
                "outbox_id": item["id"], "worker_id": "relay", "lease_epoch": item["lease_epoch"],
                "lease_seconds": int(self.config.get("lease_seconds", 60))})
            if not isinstance(heartbeat, dict) or heartbeat.get("allowed") is not True:
                raise TransientRelayError("outbox lease or emergency-stop check denied publication")
            try:
                created = self.github.create_comment(self.owner, self.repo, issue_number, expected_body)
            except GitHubError:
                # Ambiguous writes remain leased/interrupted for manual reconciliation.
                raise
            receipt = self._verified_comment(created, expected_body, issue_number)
            if receipt is None:
                raise TransientRelayError("GitHub create response did not prove the expected publisher comment")
        self.broker.call("POST", "/v1/relay/outbox/complete", {
            "outbox_id": item["id"], "worker_id": "relay",
            "lease_epoch": item["lease_epoch"], "delivered": True, "receipt": receipt})
        return True

    def _format_result(self, payload):
        # Render bounded plain text; result content remains untrusted and non-executable.
        keys = ("kind", "task_id", "task_digest", "source_delivery_id", "state", "transition",
                "cancellation_requested", "result", "error")
        safe = self._scrub({k: payload.get(k) for k in keys if k in payload})
        heading = "Local Agent Hub status update" if safe.get("kind") == "status" else "Local Agent Hub result"
        text = heading + "\n\n```json\n" + json.dumps(safe, ensure_ascii=False, indent=2) + "\n```"
        return text[:50_000]


def run(config: dict, *, github=None, broker=None, once=False):
    """Run only when explicitly called by the opt-in relay command."""
    token_env = config.get("github_token_env")
    broker_env = config.get("relay_token_env", "HUB_RELAY_TOKEN")
    if not isinstance(token_env, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{1,63}", token_env):
        raise RelayError("github_token_env must name an environment variable")
    if not os.environ.get(token_env):
        raise RelayError("configured GitHub credential is unavailable")
    if not os.environ.get(broker_env):
        raise RelayError("configured relay credential is unavailable")
    if broker_env != "HUB_RELAY_TOKEN":
        raise RelayError("relay_token_env must be HUB_RELAY_TOKEN")
    if token_env in {"HUB_COORDINATOR_TOKEN", "HUB_WORKER_TOKENS", "HUB_RELAY_TOKEN"}:
        raise RelayError("GitHub credential must use a dedicated environment variable")
    package_root = Path(__file__).resolve().parents[1]
    cursor_path = Path(config["cursor_path"])
    cursor_path = (package_root / cursor_path).resolve() if not cursor_path.is_absolute() else cursor_path.resolve()
    if package_root not in cursor_path.parents:
        raise RelayError("cursor_path must stay inside the package")
    github = github or GitHubClient(os.environ[token_env])
    broker = broker or RelayBrokerClient(config.get("broker_url", "http://127.0.0.1:8765"), os.environ[broker_env])
    relay = GitHubRelay(config, github, broker, CursorFile(cursor_path))
    if not config.get("enabled", False):
        raise RelayError("GitHub relay is disabled in configuration")
    interval = max(5, min(int(config.get("poll_seconds", 60)), 3600))
    max_publishes = config.get("max_publications_per_poll", 2)
    if isinstance(max_publishes, bool) or not isinstance(max_publishes, int) or not 1 <= max_publishes <= 10:
        raise RelayError("max_publications_per_poll must be from 1 to 10")
    failures = 0
    while True:
        try:
            relay.poll_once()
            for _ in range(max_publishes):
                if not relay.publish_one():
                    break
            failures = 0
        except (TransientRelayError, GitHubError):
            failures += 1
            if once or failures >= 5:
                raise
            time.sleep(min(5 * (2 ** (failures - 1)), 120))
            continue
        if once:
            return
        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(description="Opt-in GitHub issue-comment relay")
    parser.add_argument("--config", required=True)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    with open(args.config, "r", encoding="utf-8") as stream:
        config = json.load(stream)
    run(config, once=args.once)


if __name__ == "__main__":
    main()

