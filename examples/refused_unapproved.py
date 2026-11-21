"""Show the approval gate refusing work.

Run from the repository root with the dependencies installed:

    python examples/refused_unapproved.py

A task that nobody approved cannot be claimed, a wrong digest does not approve it, and an
emergency stop cancels it. Everything happens in process against a temporary database.
"""
from __future__ import annotations

from _demo import broker


def main() -> dict:
    with broker() as (client, coordinator, worker, workspace):
        task = client.post("/v1/dispatch", headers=coordinator, json={
            "workspace": str(workspace), "payload": {"prompt": "Do something."},
            "idempotency_key": "example-2"}).json()
        print("submitted          :", task["state"])

        # An unapproved task is invisible to workers: the claim returns null.
        claim = client.post("/v1/worker/claim", headers=worker, json={"lease_seconds": 30})
        print("claim, unapproved  :", claim.status_code, claim.json())

        # A digest that does not match the task's content does not approve it.
        wrong = client.post("/v1/approve/" + task["id"], headers=coordinator, json={"task_digest": "0" * 64})
        print("approve, bad digest:", wrong.status_code, wrong.json()["detail"]["error"])

        # The worker credential cannot approve at all.
        forbidden = client.post("/v1/approve/" + task["id"], headers=worker,
                                json={"task_digest": task["task_digest"]})
        print("approve as worker  :", forbidden.status_code)

        # A request with no credential is rejected before reaching the store.
        anonymous = client.get("/v1/status")
        print("status, no token   :", anonymous.status_code)

        state = client.get("/v1/status/" + task["id"], headers=coordinator).json()["state"]
        print("task is still      :", state)

        # The emergency stop cancels everything not yet running.
        client.post("/v1/emergency-stop", headers=coordinator)
        cancelled = client.get("/v1/status/" + task["id"], headers=coordinator).json()["state"]
        print("after stop         :", cancelled)
        return {"claim": claim.json(), "wrong_digest": wrong.status_code, "worker_approve": forbidden.status_code,
                "anonymous": anonymous.status_code, "still": state, "after_stop": cancelled}


if __name__ == "__main__":
    main()
