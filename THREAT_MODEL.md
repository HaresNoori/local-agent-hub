# Threat model

Scope: version 0.1.0 of the broker, its MCP entry, worker adapters and the three optional bridges.
Written from the code. Where a mitigation depends on something outside the Python package (the
start script's bind address, the host's file permissions) that is stated. Test references are
`file::Class::test` under `tests/`; `all of` means every test in the named class.

## Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Approval record and audit log | SQLite (`store.py`: `tasks`, `events`) | Proves what was approved and by whom |
| Bearer credentials (coordinator, worker, relay) | Process environment only (`security.py:authenticate`) | Whoever holds the coordinator token can approve |
| Upstream credentials (repository token, provider keys, webhook key) | Environment, or a settings blob piped to `webhook_bridge.py:main` | Spend, publication, impersonation |
| Host account | The user running the worker | Adapters start local CLIs with that user's rights |
| Task content and results | SQLite, shared folder, issue comments | May carry private material; must be treated as untrusted on the way in |
| Cost budget and queue capacity | `Store.dispatch` controls | Runaway agents can burn money or starve the queue |

## Trust boundaries

1. **Loopback HTTP** (`api.py:create_app`). The app checks no peer address; loopback depends on the
   bind in `scripts/start.ps1` (`--host 127.0.0.1`). Every route except `/health` needs a bearer token.
2. **MCP stdio entry** (`mcp_server.py`). A client process runs the tools; the server forwards
   them over HTTP using `HUB_COORDINATOR_TOKEN`, so the MCP client holds full coordinator rights.
3. **Worker adapters** (`adapters.py:CLIAdapter.run`, `worker.py:run_once`). Starts local CLIs with
   text from an approved task.
4. **GitHub relay** (`relay.py`, `github_client.py`). Reads issue comments, posts approved results.
5. **Drive bridge** (`drive_bridge.py`). Exchanges JSON files through a synced folder.
6. **Webhook bridge** (`webhook_bridge.py`). One-shot outbound HTTPS POST, plus a reply file read back.

## Attackers

A: malicious or confused agent. B: another local process. C: malicious upstream payload (issue
comment, shared-folder file, webhook reply). D: operator mistake.

## Threats and mitigations

| # | Threat (attacker) | Mitigation (file:function) | Tests |
|---|---|---|---|
| 1 | Work runs without matching approval (A, D) | `store.py:Store.approve` needs digest equal to the immutable task digest and state `awaiting_approval`; `Store.claim` selects only `queued` | `test_approval_gate::ApprovalReplayAndMismatchTests` (all of); `test_store::StoreTests::test_approval_fencing_and_completion` |
| 2 | Unapproved work leaves the machine: peer export, relay post, webhook (A, C) | `Store.prepare_drive_export` needs queued + matching approval digest; `Store.claim_outbox` takes only `ready` items that `Store.approve_outbox` released; `webhook_bridge.py:_run_transaction_locked` sends only on an exact digest | `test_approval_gate::UnapprovedWorkNeverReachesASinkTests` (all of); `test_webhook::WebhookBridgeTests::test_changed_request_and_wrong_approval_digest_are_rejected_before_post`; `test_webhook_pinning::TransactionRefusalTests::test_malformed_approval_digests_never_reach_the_sender` |
| 3 | Content changed after approval (A, C) | `Store.dispatch` hashes workspace, payload, limits, routing and lineage; idempotency key reuse with different content is refused | `test_store::StoreTests::test_idempotency_conflict_and_redaction`; `test_approval_gate::ApprovalReplayAndMismatchTests::test_digest_binds_limits_and_routing_not_only_the_prompt` |
| 4 | Another local process calls the API (B) | `security.py:authenticate` (constant-time compare, tokens from environment); `api.py` role dependencies `coordinator`, `worker`, `relay`; docs and schema routes disabled; worker and relay routes off unless enabled | `test_refusals::AuthenticationRefusalTests` (all of); `test_refusals::SecurityHelperTests` (all of); `test_api::ApiTests::test_relay_role_is_disabled_by_default_and_cannot_approve` |
| 5 | Credentials leak into stored or returned data (A, C) | `security.py:redact` applied in `Store.dispatch`, `Store.complete`, `Store._event`; relay and adapter output scrubbed | `test_store::StoreTests::test_known_bearer_tokens_are_redacted_from_outputs`; `test_api::ApiTests::test_status_and_logs_return_redacted_result`; `test_refusals::SecurityHelperTests::test_redact_masks_sensitive_keys_nested_values_and_credential_shapes` |
| 6 | Client or relay talks to a non-loopback broker, or leaks a bearer token by redirect or proxy (D) | `mcp_server.py:_broker_url`, `worker.py:_url`, `relay.py:RelayBrokerClient.__init__` accept only plain HTTP to a loopback IP literal; openers drop proxies and redirects | `test_refusals::LoopbackRefusalTests` (all of); `test_mcp::MCPAPITests::test_http_client_blocks_redirects_and_proxy_handlers` |
| 7 | Adapter runs something unintended (A, C) | `adapters.py:CLIAdapter.run`: disabled by default, fixed argv, `shell=False`, scrubbed environment, 1 MB prompt cap, output cap, timeout, tree kill; `make_adapter` clamps limits; `worker.py:run_once` pins the task directory under the package and requires a cost reservation | `test_adapters::AdapterTests` (all of); `test_refusals::AdapterFailClosedTests` (all of); `test_refusals::WorkerRefusalTests`; `test_refusals::WorkerTaskRootTests` (all of) |
| 8 | Stale or duplicate worker acts on a task (B, A) | `Store.claim`, `Store.heartbeat`, `Store.complete`: lease epoch fencing; expired leases become `interrupted`, never requeued; one active task per workspace | `test_approval_gate::LeaseExpiryTests` (all of); `test_store::StoreTests::test_expired_lease_is_interrupted_not_requeued`; `test_store::StoreTests::test_concurrent_claim_has_one_owner` |
| 9 | Runaway agent or loop (A) | `Store.emergency_stop`; queue, cost, timeout, hop and rate limits in `Store.dispatch` and `Store.rate_request` | `test_approval_gate::EmergencyStopTests`, `EmergencyStopApiTests`; `test_refusals::AuthenticationRefusalTests::test_request_rate_limit_returns_429_after_the_window_is_spent`; `test_store::StoreTests::test_queue_bound_and_nonfinite_cost_rejected` |
| 10 | Hostile issue comment becomes a task (C) | `relay.py:parse_envelope` (strict schema, size caps), `GitHubRelay._process_comment` (numeric author allowlist, GraphQL provenance, editor check, pinned private repository), relay dispatch lands in `awaiting_approval` | `test_relay::RelayTests::test_strict_schema_rejects_shell_and_malformed_types`, `test_private_repository_identity_and_author_edit_gates`, `test_authorized_author_with_unauthorized_last_editor_is_rejected`; `test_refusals::RelayEnvelopeSizeTests` |
| 11 | Results posted to the wrong place or twice (A, C) | `GitHubRelay.publish_one`: approved outbox only, exact-body readback, pinned publisher identity; `github_client.py:GitHubClient.request` fixed host, no redirects, size bound | `test_relay::RelayTests::test_result_publish_uses_approved_outbox_marker_and_relay_identity`, `test_unverified_create_response_never_acks_delivery`; `test_github_client::GitHubClientTests` (all of) |
| 12 | Malicious shared-folder file (C) | `drive_bridge.py:validate_inbound`, `validate_task` (size, schema, digest, peer identity), `_no_reparse`, `_agent_dir` allowlist, `_atomic_new`; imports are inert records until promoted and approved | `test_drive_bridge::DriveBrokerTests::test_import_is_untrusted_idempotent_and_not_a_task`, `test_malformed_and_wrong_peer_reply_never_complete_task`, `test_promotion_requires_exact_message_digest_and_normal_approval` |
| 13 | Webhook used to reach internal addresses, or DNS changes between check and connect (C, A) | `webhook_bridge.py:_validate_settings` (HTTPS, no user info, DNS name, host equals configured host, reserved names and headers refused); `_public_addresses` (every answer must be globally routable); `_post_once` resolves once and `_PinnedHTTPSConnection.connect` dials that address while TLS is verified against the hostname | `test_webhook_pinning::AddressPinningTests` (all of); `test_webhook_pinning::EndpointSettingsTests` (all of); `test_webhook::WebhookBridgeTests::test_rejects_header_injection_and_private_dns` |
| 14 | Webhook retried or replayed (A, D) | `_run_transaction_locked`: prepare, approve digest, send once; ambiguous or rejected sends are never retried; `_receipt_lock` blocks concurrent runs; receipts hold no payload or key | `test_webhook::WebhookBridgeTests::test_ambiguous_post_is_never_retried_on_resume`; `test_webhook_pinning::TransactionRefusalTests` (all of) |
| 15 | Oversize or malformed input (A, C) | Pydantic bounds in `api.py` request models; limit checks in `Store.dispatch`; reply and request size caps in `webhook_bridge.py` | `test_refusals::MalformedInputTests` (all of); `test_webhook_pinning::ReplyRefusalTests`, `EntryPointInputTests` |
| 16 | Operator enables something unsafe or approves a stuck task as success (D) | `HUB_ENABLE_*` default off; `config.example.json` ships disabled; `Store.reconcile_interrupted` can only mark cancelled and needs explicit booleans | `test_refusals::WorkerEndpointsDisabledTests`; `test_api::ApiTests::test_interrupted_reconciliation_is_coordinator_only_and_cancel_only`; `test_store::StoreTests::test_interrupted_task_reconciliation_requires_confirmation_and_frees_workspace` |

## Residual risks

1. **Approval is a credential, not a person.** The approval digest is returned by dispatch, and
   the MCP entry holds the coordinator token, so an agent connected through MCP can call both
   `agent_dispatch` and `agent_approve`. The gate stops accidents, replays and other credentials;
   it does not prove a human looked. The `agent_approve` description tells the agent not to
   self-approve, which is advice, not enforcement. Separate the approver's credential from the
   agents' if that matters.
2. **Same-user trust.** The database, lock files and environment are protected only by the
   operating system account. Another process running as the same user can read tokens or edit
   state. Loopback has no TLS and no peer check in code.
3. **Adapters are not sandboxed.** A child CLI runs with the user's rights. The scrubbed
   environment and task directory limit accidents, not a CLI that chooses to read elsewhere. The
   Agent B tool-deny overlay is a configuration request the CLI may ignore. Process-tree
   termination uses `taskkill` on Windows only; elsewhere only the root process is killed.
4. **Authorised relay authors are trusted for prompt text.** Prompt injection into the downstream
   model is not addressed. An allow-listed sender can also cancel tasks without approval.
5. **Redaction is pattern-based.** Credential formats it does not recognise pass through.
6. **No cap on result size at the API.** The worker route accepts any size; only the adapter caps
   output (at most 256 KiB).
7. **Emergency stop at claim time.** `POST /v1/worker/claim` during an emergency stop returns
   HTTP 423 with `emergency_stop`, and nothing is claimed
   (`EmergencyStopApiTests::test_worker_claim_never_succeeds_while_stopped`).
8. **Webhook specifics.** The verified inbox root comes from `HUB_WEBHOOK_INBOX_ROOT`, with no
   default. If it is unset, the bridge refuses to run
   (`test_webhook_pinning::InboxRootConfigTests`). The PowerShell entry point named in the module docstring is not in this repository. Pinning
   defeats rebinding between the check and the connection; it does not make a compromised public
   endpoint safe. Only the first resolved address is tried, with no fallback. The server's reply
   text is returned as untrusted.
9. **Shared-folder sync is not a lock.** Atomic rename protects local writes only; peer pickup is
   reported as unknown and remote stop is never confirmed.
10. **Single broker, single file.** No clustering, no backup or tamper evidence for the database.

## Out of scope

Multi-tenant use; exposure beyond loopback; a compromised host or operating system; supply-chain
attacks on dependencies (versions are pinned in `requirements-lock.txt` but not hash-verified);
the security of the third-party CLIs and services the adapters and bridges call; denial of service
by a local process that can already authenticate.
