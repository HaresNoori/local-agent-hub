"""Walk one task through the whole lifecycle: submit, approve, claim, complete.

Run from the repository root with the dependencies installed:

    python examples/submit_approve_complete.py

Everything happens in process against a temporary database. The worker steps are made by hand
with the worker credential, so no command-line adapter is started.
"""
from __future__ import annotations

from _demo import broker


def main() -> dict:
    with broker() as (client, coordinator, worker, workspace):
        # 1. An agent submits a task. It is stored, not run.
        task = client.post("/v1/dispatch", headers=coordinator, json={
            "workspace": str(workspace), "payload": {"prompt": "Summarise the open items."},
            "idempotency_key": "example-1", "cost_reserved": 0.1}).json()
        print("submitted :", task["state"], "digest", task["task_digest"][:12])

        # 2. The approver approves that exact digest.
        approved = client.post("/v1/approve/" + task["id"], headers=coordinator,
                               json={"task_digest": task["task_digest"], "note": "reviewed"}).json()
        print("approved  :", approved["state"], "by", approved["approved_by"])

        # 3. A worker claims it under a lease.
        claimed = client.post("/v1/worker/claim", headers=worker, json={"lease_seconds": 30}).json()
        print("claimed   :", claimed["state"], "by", claimed["worker_id"], "epoch", claimed["lease_epoch"])

        # 4. The worker reports the result using the lease epoch it was given.
        done = client.post("/v1/worker/complete", headers=worker, json={
            "task_id": task["id"], "worker_id": claimed["worker_id"],
            "lease_epoch": claimed["lease_epoch"], "result": {"text": "Three open items."}}).json()
        print("completed :", done["state"], done["result"])

        events = client.get("/v1/logs/" + task["id"], headers=coordinator).json()
        print("audit log :", [event["event"] for event in events])
        return {"final_state": done["state"], "events": [event["event"] for event in events]}


if __name__ == "__main__":
    main()
