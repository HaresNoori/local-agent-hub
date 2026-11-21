"""Narrow GitHub REST client for the private issue relay.

Only fixed api.github.com paths are supported. Redirects and ambient proxies are
disabled so the credential cannot be forwarded to another host.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHubError(RuntimeError):
    pass


class GitHubClient:
    API = "https://api.github.com"
    API_VERSION = "2022-11-28"

    def __init__(self, token: str, *, opener=None, timeout: float = 15,
                 max_response_bytes: int = 1_000_000):
        if not isinstance(token, str) or not token or len(token) > 4096:
            raise ValueError("GitHub token is missing or invalid")
        self._token = token
        self._opener = opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect())
        self.timeout = max(1, min(float(timeout), 30))
        self.max_response_bytes = max(1024, min(int(max_response_bytes), 2_000_000))

    @staticmethod
    def _segment(value: str) -> str:
        if not isinstance(value, str) or not value or len(value) > 100:
            raise ValueError("invalid repository path segment")
        return urllib.parse.quote(value, safe="")

    def request(self, method: str, path: str, body: dict | None = None):
        if not path.startswith("/") or path.startswith("//") or "#" in path or ".." in path:
            raise ValueError("GitHub path must be a fixed API path")
        url = self.API + path
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        request = urllib.request.Request(url, data=data, method=method.upper(), headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + self._token,
            "X-GitHub-Api-Version": self.API_VERSION,
            "User-Agent": "local-agent-hub-relay",
            "Content-Type": "application/json",
        })
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                raw = response.read(self.max_response_bytes + 1)
                if len(raw) > self.max_response_bytes:
                    raise GitHubError("GitHub response exceeded configured bound")
                if not raw:
                    return None
                return json.loads(raw)
        except urllib.error.HTTPError as exc:
            # Never include response bodies or request headers in errors.
            raise GitHubError(f"GitHub API returned HTTP {exc.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise GitHubError(f"GitHub API transport failed ({type(exc).__name__})") from None
        except json.JSONDecodeError:
            raise GitHubError("GitHub API returned invalid JSON") from None

    def get_repo(self, owner: str, repo: str):
        return self.request("GET", f"/repos/{self._segment(owner)}/{self._segment(repo)}")

    def get_authenticated_user(self):
        """Return the authenticated PAT user; the relay is intentionally PAT-only."""
        return self.request("GET", "/user")

    def comment_provenance(self, node_id: str):
        if not isinstance(node_id, str) or not node_id or len(node_id) > 200:
            raise ValueError("invalid GraphQL comment node ID")
        query = "query RelayCommentProvenance($id: ID!) { node(id: $id) { ... on IssueComment { databaseId body author { __typename ... on User { databaseId } ... on Bot { databaseId } } lastEditedAt editor { __typename ... on User { databaseId } ... on Bot { databaseId } } issue { __typename number repository { databaseId } } } } }"
        result = self.request("POST", "/graphql", {"query": query, "variables": {"id": node_id}})
        try:
            if result.get("errors"):
                raise GitHubError("GitHub GraphQL provenance lookup failed")
            node = result["data"]["node"]
            if not isinstance(node, dict):
                raise GitHubError("GitHub comment provenance was unavailable")
            author = node.get("author") or {}
            editor = node.get("editor") or {}
            return {"database_id": node.get("databaseId"),
                    "body": node.get("body"),
                    "author_type": author.get("__typename"),
                    "author_id": author.get("databaseId") if author.get("__typename") in {"User", "Bot"} else None,
                    "last_edited_at": node.get("lastEditedAt"),
                    "editor_type": editor.get("__typename"),
                    "editor_id": editor.get("databaseId") if editor.get("__typename") in {"User", "Bot"} else None,
                    "issue_number": (node.get("issue") or {}).get("number"),
                    "issue_type": (node.get("issue") or {}).get("__typename"),
                    "repository_id": ((node.get("issue") or {}).get("repository") or {}).get("databaseId")}
        except (AttributeError, KeyError, TypeError):
            raise GitHubError("GitHub comment provenance response was incomplete") from None

    def list_issues(self, owner: str, repo: str, *, since: str | None = None,
                    page: int = 1, per_page: int = 100):
        query = {"state": "open", "sort": "updated", "direction": "asc",
                 "page": str(max(1, min(int(page), 20))),
                 "per_page": str(max(1, min(int(per_page), 100)))}
        if since:
            query["since"] = since
        return self.request("GET", f"/repos/{self._segment(owner)}/{self._segment(repo)}/issues?"
                            + urllib.parse.urlencode(query))

    def list_comments_since(self, owner: str, repo: str, *, since: str | None = None,
                            page: int = 1, per_page: int = 100):
        query = {"sort": "updated", "direction": "asc",
                 "page": str(max(1, min(int(page), 20))),
                 "per_page": str(max(1, min(int(per_page), 100)))}
        if since:
            query["since"] = since
        return self.request("GET", f"/repos/{self._segment(owner)}/{self._segment(repo)}"
                            "/issues/comments?" + urllib.parse.urlencode(query))

    def list_comments(self, owner: str, repo: str, issue_number: int, *, page=1, per_page=100):
        number = int(issue_number)
        if number < 1:
            raise ValueError("issue number must be positive")
        query = urllib.parse.urlencode({"page": max(1, min(int(page), 20)),
                                        "per_page": max(1, min(int(per_page), 100))})
        return self.request("GET", f"/repos/{self._segment(owner)}/{self._segment(repo)}"
                            f"/issues/{number}/comments?{query}")

    # Explicit name used by the relay for issue-specific publication readback.
    def list_issue_comments(self, owner: str, repo: str, issue_number: int, *, page=1, per_page=100):
        return self.list_comments(owner, repo, issue_number, page=page, per_page=per_page)

    def create_comment(self, owner: str, repo: str, issue_number: int, body: str):
        number = int(issue_number)
        if number < 1 or not isinstance(body, str) or len(body) > 60_000:
            raise ValueError("invalid issue comment")
        return self.request("POST", f"/repos/{self._segment(owner)}/{self._segment(repo)}"
                            f"/issues/{number}/comments", {"body": body})

    def create_issue_comment(self, owner: str, repo: str, issue_number: int, body: str):
        return self.create_comment(owner, repo, issue_number, body)

