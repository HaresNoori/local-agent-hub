# local-agent-hub

A loopback-only SQLite broker for approval-gated handoffs between local agent tools.

One process (the broker) holds a task queue. Agents, called `agent-a`, `agent-b` and so on here,
submit tasks. A human approves each task by its digest before anything runs. Workers then claim
approved tasks, run them through a restricted command-line adapter, and report results back.
Nothing is executed, relayed or exported without an explicit approval step.

## Architecture

```
 agent-a / agent-b             human approver
 (MCP stdio server) --HTTP--> broker (FastAPI + SQLite, 127.0.0.1) <--HTTP-- worker
                                 |                                         (adapter subprocess)
                                 +-- optional shared-folder bridge ("drive")
                                 +-- optional issue-based relay ("github")
                                 +-- optional one-shot webhook bridge
```

| Module | Role |
|---|---|
| `hub/store.py` | SQLite state machine: tasks, approvals, leases, logs, handovers, emergency stop |
| `hub/api.py` | FastAPI app, bearer-token auth, role separation (coordinator, worker, relay) |
| `hub/mcp_server.py` | MCP stdio server exposing the broker as tools |
| `hub/worker.py`, `hub/adapters.py` | Worker loop and CLI adapters with a scrubbed environment and output caps |
| `hub/drive_bridge.py` | Untrusted file-based message exchange through a shared folder |
| `hub/relay.py`, `hub/github_client.py` | Optional relay via a private repository's issues; outbound delivery needs approval |
| `hub/webhook_bridge.py` | One-shot, approval-gated outbound webhook with address pinning |
| `hub/security.py` | Token comparison, fingerprints, secret redaction |

## Quickstart (Windows PowerShell)

Requires Python 3.11 or later.

```powershell
scripts\install.ps1 -Approved                  # creates .venv, installs requirements.txt
$env:HUB_COORDINATOR_TOKEN = "<random token>"  # never commit real tokens
scripts\start.ps1 -Approved                    # serves on 127.0.0.1:8765
scripts\stop.ps1 -Approved
```

Pinned versions are in `requirements-lock.txt`. The start script keeps the database in
`state/hub.sqlite3` (override with `HUB_DB_PATH`; if that is unset the app falls back to
`./hub.sqlite3` in the working directory). Copy `config.example.json` to `config.json` and review
it before enabling workers.

Point an MCP client at `scripts/mcp-entry.py` (stdio). It talks to the broker at `HUB_BROKER_URL`
(default `http://127.0.0.1:8765`).

## MCP tools

| Tool | Purpose |
|---|---|
| `agent_send`, `agent_dispatch` | Submit a message or a work task (idempotency key required) |
| `agent_status`, `agent_result`, `agent_logs` | Inspect tasks |
| `agent_inbox`, `agent_thread` | Read messages and threads |
| `agent_approve` | Approve a task by its digest |
| `agent_cancel`, `agent_reconcile_interrupted`, `agent_handover` | Task lifecycle controls |
| `agent_emergency_stop` | Halt all claiming |
| `agent_outbox`, `agent_approve_relay_delivery`, `agent_abandon_relay_delivery` | Relay delivery review |
| `agent_drive_sync`, `agent_drive_status`, `agent_drive_messages`, `agent_drive_promote`, `agent_drive_export` | Shared-folder bridge |

## HTTP API (summary)

| Group | Endpoints |
|---|---|
| Health and status | `GET /health`, `GET /v1/status[/{task_id}]`, `GET /v1/logs/{task_id}` |
| Tasks | `POST /v1/dispatch`, `GET /v1/inbox`, `GET /v1/thread/{id}`, `POST /v1/approve/{id}`, `/v1/cancel/{id}`, `/v1/reconcile/{id}`, `/v1/handover/{id}`, `/v1/emergency-stop` |
| Worker | `POST /v1/worker/claim`, `/v1/worker/heartbeat`, `/v1/worker/complete` |
| Shared folder | `/v1/drive/*` (sync, status, messages, promote, export, cancel) |
| Relay | `/v1/relay/*` (dispatch, tasks, outbox claim, approve, abandon, complete, heartbeat) |

Drive and relay endpoints are off unless enabled with `HUB_ENABLE_DRIVE` / `HUB_ENABLE_RELAY`.

## Security model

- **Loopback only.** The relay client refuses non-loopback broker URLs and the start script binds `127.0.0.1`.
- **Approval gate.** Task content is hashed. A task runs only after an approver submits the matching digest. Messages from outside (shared folder, relay) are stored as untrusted data and must be promoted and approved before becoming tasks.
- **Separate tokens.** Coordinator, worker and relay credentials are distinct environment variables, are not stored in the database, and are redacted from returned output.
- **Restricted workers.** Adapters run a fixed command line, in an allow-listed workspace root, with a scrubbed environment, a timeout and an output cap. Provider keys pass only through an explicit allow-list.
- **Fail closed.** Unconfigured adapters refuse to run; an emergency stop blocks new claims.

This is a local coordination tool, not a hardened multi-tenant service. Do not expose it beyond loopback.

## Tests

```
pip install -r requirements-lock.txt pytest
pytest -q
```

Tests use in-process test clients and temporary-directory databases only. They bind no ports and
need no running broker (the `127.0.0.1:8765` strings in tests are inert configuration values).

`python scripts/privacy_check.py <denylist-file>` scans the tree (contents and file names) for
terms listed one per line in a file you supply. No denylist is stored in the repository.

## Limitations

- Windows-oriented: PowerShell scripts, Windows process-tree handling and command-line limits.
- Adapters are thin wrappers around example CLIs; `agent-d` is a placeholder that always refuses.
- Single broker, single SQLite file, no clustering.
- Early (0.1.0) design with no stability guarantees.

## License

MIT, see `LICENSE`.
