"""Shared setup for the in-process examples. No server is started and no port is opened."""
from __future__ import annotations

import os
import secrets
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402

from hub.api import create_app  # noqa: E402
from hub.store import Store  # noqa: E402


@contextmanager
def broker():
    """Yield (client, coordinator_headers, worker_headers, workspace) backed by a temporary database.

    Tokens are random per run and exist only in this process's environment.
    """
    coordinator_token, worker_token = secrets.token_hex(16), secrets.token_hex(16)
    with tempfile.TemporaryDirectory() as tmp:
        environment = {"HUB_COORDINATOR_TOKEN": coordinator_token, "HUB_WORKER_TOKENS": worker_token,
                       "HUB_ENABLE_WORKERS": "1"}
        with patch.dict(os.environ, environment):
            workspace = Path(tmp) / "workspace"
            workspace.mkdir()
            store = Store(Path(tmp) / "broker.sqlite3", allowed_workspaces=[tmp])
            try:
                yield (TestClient(create_app(store)),
                       {"Authorization": "Bearer " + coordinator_token},
                       {"Authorization": "Bearer " + worker_token},
                       workspace)
            finally:
                store.close()
