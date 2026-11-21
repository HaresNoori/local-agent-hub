"""FastAPI loopback API. It brokers records and leases; it never runs a worker."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field, StrictBool

from .security import Principal, authenticate
from .store import HubError, Store
from . import drive_bridge


class DispatchRequest(BaseModel):
    workspace: str
    payload: dict[str, Any]
    idempotency_key: str = Field(min_length=1, max_length=200)
    thread_id: str | None = None
    correlation_id: str | None = None
    action_class: str = "analysis"
    timeout_seconds: int = 300
    cost_reserved: float = 0.0
    target_worker: str | None = None
    parent_task_id: str | None = None
    priority: int = Field(default=0, ge=-100, le=100)
    depends_on: list[str] = Field(default_factory=list, max_length=32)


class RelayDispatchRequest(DispatchRequest):
    relay_source: str = Field(min_length=1, max_length=200)
    relay_delivery_id: str = Field(min_length=1, max_length=200)
    relay_payload_digest: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    relay_sender_id: str = Field(min_length=1, max_length=200)


class ApprovalRequest(BaseModel):
    task_digest: str
    note: str = ""


class WorkerClaimRequest(BaseModel):
    lease_seconds: int = 60


class WorkerLeaseRequest(BaseModel):
    task_id: str
    worker_id: str
    lease_epoch: int
    lease_seconds: int = 60


class WorkerCompleteRequest(BaseModel):
    task_id: str
    worker_id: str
    lease_epoch: int
    result: Any = None
    error: Any = None
    cancelled: bool = False


class HandoverRequest(BaseModel):
    handover: Any


class CancelRequest(BaseModel):
    reason: str = ""


class RelayCancelRequest(BaseModel):
    source: str
    sender_id: str
    reason: str = ""


class OutboxApprovalRequest(BaseModel):
    approval_digest: str
    note: str = ""


class TaskReconcileRequest(BaseModel):
    task_digest: str
    process_termination_confirmed: StrictBool
    evidence_note: str = Field(min_length=1, max_length=2000)


class OutboxAbandonRequest(BaseModel):
    approval_digest: str
    publication_checked: StrictBool
    evidence_note: str = Field(min_length=1, max_length=2000)


class OutboxClaimRequest(BaseModel):
    lease_seconds: int = 60


class OutboxCompleteRequest(BaseModel):
    outbox_id: str | None = None
    delivery_id: str | None = None
    worker_id: str
    lease_epoch: int
    delivered: bool
    error: Any = None
    receipt: dict[str, Any] | None = None


class OutboxHeartbeatRequest(BaseModel):
    outbox_id: str | None = None
    delivery_id: str | None = None
    worker_id: str
    lease_epoch: int
    lease_seconds: int = 60


class DriveSyncRequest(BaseModel):
    limit: int = Field(default=20, ge=1, le=50)


class DrivePromoteRequest(BaseModel):
    request_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    target_worker: str = Field(min_length=1, max_length=64)
    cost_reserved: float = Field(ge=0)
    timeout_seconds: int = Field(default=300, ge=1, le=3600)


class DriveCancelRequest(BaseModel):
    reason: str = Field(default="", max_length=2000)


def create_app(store: Store | None = None) -> FastAPI:
    db_path = os.environ.get("HUB_DB_PATH", str(Path.cwd() / "hub.sqlite3"))
    broker = store or Store(db_path)
    app = FastAPI(title="Local Agent Hub", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store = broker

    def principal(authorization: str | None = Header(default=None)) -> Principal:
        scheme, _, token = (authorization or "").partition(" ")
        identity = authenticate(token if scheme.lower() == "bearer" else None)
        if identity is None:
            raise HTTPException(401, "Bearer authentication required")
        return identity

    def coordinator(p: Principal = Depends(principal)) -> Principal:
        if p.role != "coordinator": raise HTTPException(403, "Coordinator role required")
        call(broker.rate_request, p.subject)
        return p

    def worker(p: Principal = Depends(principal)) -> Principal:
        if p.role != "worker": raise HTTPException(403, "Worker role required")
        if os.environ.get("HUB_ENABLE_WORKERS", "0") != "1":
            raise HTTPException(423, "Worker endpoints are disabled")
        call(broker.rate_request, p.subject)
        return p

    def relay(p: Principal = Depends(principal)) -> Principal:
        if p.role != "relay": raise HTTPException(403, "Relay role required")
        if os.environ.get("HUB_ENABLE_RELAY", "0") != "1": raise HTTPException(423,"Relay endpoints are disabled")
        call(broker.rate_request, p.subject)
        return p

    def drive_coordinator(p: Principal = Depends(coordinator)) -> Principal:
        if os.environ.get("HUB_ENABLE_DRIVE", "0") != "1":
            raise HTTPException(423, "Drive bridge is disabled")
        return p

    def drive_root() -> Path:
        value=os.environ.get("HUB_DRIVE_ROOT","")
        if not value: raise HTTPException(423,"Drive root is not configured")
        try: return Path(value).expanduser().resolve(strict=True)
        except OSError: raise HTTPException(423,"Configured Drive root is unavailable") from None

    def call(fn, *args, **kwargs):
        try: return fn(*args, **kwargs)
        except HubError as exc: raise HTTPException(exc.status, {"error": exc.code, "detail": str(exc)})

    @app.get("/health")
    def health():
        return {"ok": True, "worker_execution_enabled": os.environ.get("HUB_ENABLE_WORKERS", "0") == "1",
                "relay_enabled": os.environ.get("HUB_ENABLE_RELAY", "0") == "1"}

    @app.post("/v1/dispatch")
    def dispatch(body: DispatchRequest, p: Principal = Depends(coordinator)):
        return call(broker.dispatch, **body.model_dump(), principal=p.subject)

    @app.post("/v1/drive/sync")
    def drive_sync(body: DriveSyncRequest, _p: Principal = Depends(drive_coordinator)):
        try: return drive_bridge.sync_drive_once(broker,drive_root(),limit=body.limit)
        except drive_bridge.BridgeError as exc: raise HTTPException(400,str(exc)) from None

    @app.get("/v1/drive/status")
    def drive_status(_p: Principal = Depends(drive_coordinator)):
        info=broker.drive_status()
        root=drive_root()
        info.update({"enabled":True,"local_sync_path_available":root.is_dir(),"polling":False,
                     "peer_pickup":"unknown"})
        return info

    @app.get("/v1/drive/messages")
    def drive_messages(state: str | None=None, limit: int=50, offset: int=0,
                       thread_id: str | None=None,
                       _p: Principal = Depends(drive_coordinator)):
        return call(broker.list_drive_messages,state=state,limit=limit,offset=offset,thread_id=thread_id)

    @app.post("/v1/drive/promote/{message_id}")
    def drive_promote(message_id: str, body: DrivePromoteRequest, p: Principal = Depends(drive_coordinator)):
        workspace=os.environ.get("HUB_DRIVE_WORKSPACE","")
        if not workspace: raise HTTPException(423,"Drive workspace is not configured")
        if body.target_worker not in {"worker-1","drive:agent-b","drive:agent-c"}:
            raise HTTPException(422,"Target worker is not allowlisted")
        return call(broker.promote_drive_message,message_id,request_digest=body.request_digest,
                    workspace=workspace,target_worker=body.target_worker,cost_reserved=body.cost_reserved,
                    timeout_seconds=body.timeout_seconds,principal=p.subject)

    @app.post("/v1/drive/export/{task_id}")
    def drive_export(task_id: str, p: Principal = Depends(drive_coordinator)):
        try: return call(drive_bridge.export_approved_task,broker,drive_root(),task_id,principal=p.subject)
        except drive_bridge.BridgeError as exc: raise HTTPException(409,str(exc)) from None

    @app.get("/v1/drive/status/{task_id}")
    def drive_task_status(task_id: str, _p: Principal = Depends(drive_coordinator)):
        task=broker.get_task(task_id)
        if task is None: raise HTTPException(404,"Task not found")
        export=broker.get_drive_export(task_id)
        if export:
            task["external_peer"]={"agent":export["peer"],"exported":True,"broker_state":task["state"],
                                   "reply_received":bool(export["reply_digest"]),
                                   "pickup":"unknown","remote_stop_confirmed":False}
        return task

    @app.post("/v1/drive/cancel/{task_id}")
    def drive_cancel(task_id: str, body: DriveCancelRequest, p: Principal = Depends(drive_coordinator)):
        task=call(broker.cancel,task_id,p.subject,body.reason)
        external=bool(task.get("target_worker","").startswith("drive:"))
        if external: task["external_peer"]={"pickup":"unknown","remote_stop_confirmed":False}
        return task

    @app.post("/v1/relay/dispatch")
    def relay_dispatch(body: RelayDispatchRequest, _p: Principal = Depends(relay)):
        if not broker.relay_sources_allowed(body.relay_source): raise HTTPException(403,"Relay source is not allowlisted")
        return call(broker.dispatch, **body.model_dump(), principal="relay")

    @app.get("/v1/relay/tasks/{task_id}")
    def relay_task(task_id: str, source: str, _p: Principal = Depends(relay)):
        if not broker.relay_sources_allowed(source): raise HTTPException(403,"Relay source is not allowlisted")
        task=broker.get_relay_task(source,task_id)
        if task is None: raise HTTPException(404,"Mapped relay task not found")
        return task

    @app.post("/v1/relay/cancel/{task_id}")
    def relay_cancel(task_id: str, body: RelayCancelRequest, _p: Principal = Depends(relay)):
        if not broker.relay_sources_allowed(body.source): raise HTTPException(403,"Relay source is not allowlisted")
        return call(broker.request_relay_cancel, task_id, source=body.source,
                    sender_id=body.sender_id, reason=body.reason)

    @app.get("/v1/status")
    def status(_p: Principal = Depends(coordinator)):
        return broker.status()

    @app.get("/v1/status/{task_id}")
    def task_status(task_id: str, _p: Principal = Depends(coordinator)):
        task = broker.get_task(task_id)
        if task is None: raise HTTPException(404, "Task not found")
        return task

    @app.get("/v1/logs/{task_id}")
    def task_logs(task_id: str, limit: int = 200, _p: Principal = Depends(coordinator)):
        if broker.get_task(task_id) is None: raise HTTPException(404, "Task not found")
        return broker.logs(task_id, limit)

    @app.get("/v1/relay/outbox")
    def relay_outbox(limit: int=50, state: str | None=None, _p: Principal = Depends(coordinator)):
        return broker.list_outbox(limit,state)

    @app.post("/v1/relay/outbox/{outbox_id}/approve")
    def approve_relay_outbox(outbox_id: str, body: OutboxApprovalRequest, p: Principal = Depends(coordinator)):
        return call(broker.approve_outbox,outbox_id,body.approval_digest,principal=p.subject,note=body.note)

    @app.post("/v1/relay/outbox/{outbox_id}/abandon")
    def abandon_relay_outbox(outbox_id: str, body: OutboxAbandonRequest, p: Principal = Depends(coordinator)):
        return call(broker.abandon_interrupted_outbox,outbox_id,approval_digest=body.approval_digest,
                    publication_checked=body.publication_checked,evidence_note=body.evidence_note,principal=p.subject)

    @app.post("/v1/relay/outbox/claim")
    def claim_relay_outbox(body: OutboxClaimRequest, _p: Principal = Depends(relay)):
        return call(broker.claim_outbox,_p.subject,body.lease_seconds)

    @app.post("/v1/relay/outbox/complete")
    def complete_relay_outbox(body: OutboxCompleteRequest, _p: Principal = Depends(relay)):
        if body.worker_id != _p.subject: raise HTTPException(403,"Relay identity is bound to the token")
        reference=body.outbox_id or body.delivery_id
        if not reference: raise HTTPException(422,"outbox_id is required")
        outbox_id=call(broker.resolve_relay_outbox_id,reference)
        return call(broker.complete_outbox,outbox_id,body.worker_id,body.lease_epoch,
                    delivered=body.delivered,error=body.error,receipt=body.receipt)

    @app.post("/v1/relay/outbox/heartbeat")
    def heartbeat_relay_outbox(body: OutboxHeartbeatRequest, _p: Principal = Depends(relay)):
        if body.worker_id != _p.subject: raise HTTPException(403,"Relay identity is bound to the token")
        reference=body.outbox_id or body.delivery_id
        if not reference: raise HTTPException(422,"outbox_id is required")
        outbox_id=call(broker.resolve_relay_outbox_id,reference)
        return call(broker.heartbeat_outbox,outbox_id,body.worker_id,body.lease_epoch,body.lease_seconds)

    @app.get("/v1/inbox")
    def inbox(workspace: str | None = None, limit: int = 50, offset: int = 0,
              states: str | None = None, _p: Principal = Depends(coordinator)):
        selected = None if states is None else [value.strip() for value in states.split(",") if value.strip()]
        return call(broker.inbox, workspace, limit, selected, offset)

    @app.get("/v1/thread/{thread_id}")
    def thread(thread_id: str, _p: Principal = Depends(coordinator)):
        return broker.thread(thread_id)

    @app.post("/v1/approve/{task_id}")
    def approve(task_id: str, body: ApprovalRequest, p: Principal = Depends(coordinator)):
        return call(broker.approve, task_id, task_digest=body.task_digest, principal=p.subject, note=body.note)

    @app.post("/v1/cancel/{task_id}")
    def cancel(task_id: str, body: CancelRequest, p: Principal = Depends(coordinator)):
        return call(broker.cancel, task_id, p.subject, body.reason)

    @app.post("/v1/reconcile/{task_id}")
    def reconcile_interrupted_task(task_id: str, body: TaskReconcileRequest, p: Principal = Depends(coordinator)):
        return call(broker.reconcile_interrupted,task_id,task_digest=body.task_digest,
                    process_termination_confirmed=body.process_termination_confirmed,
                    evidence_note=body.evidence_note,principal=p.subject)

    @app.post("/v1/handover/{task_id}")
    def handover(task_id: str, body: HandoverRequest, p: Principal = Depends(coordinator)):
        return call(broker.handover, task_id, body.handover, p.subject)

    @app.post("/v1/emergency-stop")
    def emergency_stop(stopped: bool = True, p: Principal = Depends(coordinator)):
        return call(broker.emergency_stop, stopped, p.subject)

    @app.post("/v1/worker/claim")
    def claim(body: WorkerClaimRequest, _p: Principal = Depends(worker)):
        return broker.claim(_p.subject, body.lease_seconds)

    @app.post("/v1/worker/heartbeat")
    def heartbeat(body: WorkerLeaseRequest, _p: Principal = Depends(worker)):
        if body.worker_id != _p.subject: raise HTTPException(403, "Worker identity is bound to the token")
        return call(broker.heartbeat, body.task_id, body.worker_id, body.lease_epoch, body.lease_seconds)

    @app.post("/v1/worker/complete")
    def complete(body: WorkerCompleteRequest, _p: Principal = Depends(worker)):
        if body.worker_id != _p.subject: raise HTTPException(403, "Worker identity is bound to the token")
        return call(broker.complete, body.task_id, body.worker_id, body.lease_epoch, body.result, body.error, body.cancelled)

    return app


