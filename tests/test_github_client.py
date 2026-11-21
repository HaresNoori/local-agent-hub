import json
import unittest
from io import BytesIO
from urllib.error import HTTPError

from hub.github_client import GitHubClient, GitHubError


class Response:
    def __init__(self, payload, status=200):
        self.body = json.dumps(payload).encode()
        self.status = status
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def read(self, n=-1): return self.body[:n]


class Opener:
    def __init__(self, responses): self.responses, self.requests = list(responses), []
    def open(self, request, timeout):
        self.requests.append((request, timeout))
        response = self.responses.pop(0)
        if isinstance(response, Exception): raise response
        return response


class GitHubClientTests(unittest.TestCase):
    def test_fixed_api_host_and_bearer_header(self):
        opener = Opener([Response({"id": 12, "private": True}), Response([])])
        client = GitHubClient("github-secret-test", opener=opener)
        result = client.get_repo("owner", "private repo")
        self.assertEqual(result["id"], 12)
        client.list_comments_since("owner", "repo", since="2026-10-20T00:00:00Z")
        request = opener.requests[0][0]
        self.assertTrue(request.full_url.startswith("https://api.github.com/repos/owner/"))
        self.assertEqual(request.get_header("Authorization"), "Bearer github-secret-test")
        self.assertNotIn("github-secret-test", str(GitHubError("sanitized")))

    def test_http_error_does_not_include_body_or_secret(self):
        err = HTTPError("https://api.github.com", 403, "forbidden", {}, BytesIO(b"github-secret-test"))
        client = GitHubClient("github-secret-test", opener=Opener([err]))
        with self.assertRaises(GitHubError) as ctx:
            client.get_repo("owner", "repo")
        self.assertEqual(str(ctx.exception), "GitHub API returned HTTP 403")
        self.assertNotIn("github-secret-test", str(ctx.exception))

    def test_path_segments_and_response_size_are_bounded(self):
        client = GitHubClient("token", opener=Opener([Response({"large": "x" * 1200})]), max_response_bytes=1024)
        with self.assertRaises(GitHubError):
            client.get_repo("owner", "repo")
        with self.assertRaises(ValueError):
            GitHubClient("token").get_repo("..", "repo")

    def test_graphql_provenance_query_uses_fixed_endpoint_and_variable(self):
        response = {"data": {"node": {"databaseId": 55, "body": "{}", "author": {"__typename": "User", "databaseId": 111},
                    "lastEditedAt": None, "editor": None, "issue": {"__typename": "Issue", "number": 7,
                    "repository": {"databaseId": 987654}}}}}
        opener = Opener([Response(response)])
        client = GitHubClient("token", opener=opener)
        value = client.comment_provenance("IC_kwDOExample")
        self.assertEqual(value["author_id"], 111)
        self.assertEqual(value["repository_id"], 987654)
        self.assertEqual(value["issue_type"], "Issue")
        query = json.loads(request.data.decode()) if False else None
        request = opener.requests[0][0]
        self.assertEqual(request.full_url, "https://api.github.com/graphql")
        self.assertEqual(request.get_method(), "POST")
        self.assertIn("IC_kwDOExample", request.data.decode())
        self.assertIn("... on User { databaseId }", request.data.decode())
        self.assertIn("... on Bot { databaseId }", request.data.decode())


if __name__ == "__main__": unittest.main()
