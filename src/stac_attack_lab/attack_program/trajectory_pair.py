"""Offline preparation of paired attacks from a reviewed benign trajectory.

No provider or runtime is invoked by this module. Runtime receipts must be
collected separately; a declared clean snapshot is not proof of isolation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

DEFINITIONS = {
    "Ingest": "External material enters the observed processing context.",
    "Adopt": "The agent demonstrably uses content semantically.",
    "Persist": "A change is committed to persistent state.",
    "Recall": "Previously persisted state is read later.",
    "Select": "A tool or action is selected.",
    "Bind": "Content is bound to an action parameter or object.",
    "Act": "An action is actually executed.",
    "Record": "An execution record is written.",
    "Recover": "A recovery action follows evidenced failure and feedback.",
}
ARMS = ("trajectory_only", "trajectory_with_primitives")


def digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()


def prepare(baseline: dict[str, Any], settings: dict[str, Any]) -> dict[str, Any]:
    """Check references and freeze matched inputs; never infer missing evidence."""
    if baseline.get("schema_version") != "benign-trajectory/1":
        raise ValueError("baseline_schema")
    if baseline.get("scope") not in {"synthetic", "real_development"}:
        raise ValueError("baseline_scope")
    if baseline.get("attack_present") is not False:
        raise ValueError("baseline_not_benign")
    if baseline.get("task_completed") is not True:
        raise ValueError("baseline_task_not_completed")
    if not baseline.get("initial_snapshot_sha256") or not baseline.get("task_id"):
        raise ValueError("baseline_identity_missing")
    events = baseline.get("public_events", [])
    ids = [e["event_id"] for e in events]
    sequences = [e["sequence"] for e in events]
    if not events or len(set(ids)) != len(ids):
        raise ValueError("event_identity")
    if sequences != sorted(set(sequences)):
        raise ValueError("event_order")
    by_id = {e["event_id"]: e for e in events}
    annotations = baseline.get("annotations", [])
    for annotation in annotations:
        if annotation.get("primitive") not in DEFINITIONS:
            raise ValueError("primitive_unknown")
        refs = annotation.get("evidence_refs", [])
        if not refs or any(ref not in by_id for ref in refs):
            raise ValueError("evidence_missing")
        if annotation.get("review_status") != "verified" or not annotation.get("rationale"):
            raise ValueError("annotation_not_reviewed")
        # A summary written by a model is not evidence that an action occurred.
        if all(by_id[ref].get("kind") == "model_claim" for ref in refs):
            raise ValueError("model_claim_only")
    if baseline.get("public_review") != "approved":
        raise ValueError("public_projection_not_reviewed")
    required = (
        "attack_goal", "allowed_surfaces", "planner_model", "victim_model",
        "planner_request_limit", "victim_request_limit", "seed",
    )
    if any(key not in settings for key in required):
        raise ValueError("settings_missing")
    for name in ("planner_request_limit", "victim_request_limit"):
        if type(settings[name]) is not int or settings[name] <= 0:
            raise ValueError("budget_invalid")
    if not settings["allowed_surfaces"] or not settings["attack_goal"]:
        raise ValueError("attack_contract_empty")
    common = {
        "task_id": baseline["task_id"],
        "task": baseline["public_task"],
        "trajectory": events,
        **{key: settings[key] for key in required},
    }
    requests = {arm: json.loads(json.dumps(common)) for arm in ARMS}
    requests[ARMS[1]]["primitive_definitions"] = DEFINITIONS.copy()
    requests[ARMS[1]]["primitive_annotations"] = annotations
    plan = {
        "schema_version": "trajectory-pair/1",
        "scope": baseline["scope"],
        "execution_enabled": False,
        "baseline_hash": digest(baseline),
        "initial_snapshot_sha256": baseline["initial_snapshot_sha256"],
        "requests": requests,
        "cross_arm_deduplication": False,
        "runtime_requirements": {
            "fresh_environment_per_arm": True,
            "verify_initial_snapshot": True,
            "separate_memory_and_tool_state": True,
        },
    }
    return {**plan, "plan_hash": digest(plan)}


def execution_slots(plan: dict[str, Any], candidates: dict[str, Any]) -> list[dict[str, Any]]:
    """Prepare both opportunities, even for byte-identical validated patches."""
    if digest({k: v for k, v in plan.items() if k != "plan_hash"}) != plan["plan_hash"]:
        raise ValueError("plan_tampered")
    if set(candidates) != set(ARMS):
        raise ValueError("both_arms_required")
    slots = []
    for arm in ARMS:
        candidate = candidates[arm]
        surfaces = {s["pointer"]: s for s in plan["requests"][arm]["allowed_surfaces"]}
        patches = candidate.get("patches", [])
        if not patches or len({p["pointer"] for p in patches}) != len(patches):
            raise ValueError("patches_empty_or_duplicate_pointer")
        for patch in patches:
            surface = surfaces.get(patch["pointer"])
            if surface is None or not isinstance(patch.get("value"), str):
                raise ValueError("patch_surface_invalid")
            if len(patch["value"]) > surface["max_chars"]:
                raise ValueError("patch_too_long")
        slots.append({
            "arm": arm, "slot_id": arm, "status": "prepared_disabled",
            "patch_hash": digest(sorted(patches, key=lambda p: p["pointer"])),
            "patches": patches, "initial_snapshot_sha256": plan["initial_snapshot_sha256"],
        })
    identical = slots[0]["patch_hash"] == slots[1]["patch_hash"]
    for slot in slots:
        slot["identical_across_arms"] = identical
    return slots


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    plan = prepare(
        json.loads(args.baseline.read_text(encoding="utf-8")),
        json.loads(args.settings.read_text(encoding="utf-8")),
    )
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(plan, stream, ensure_ascii=False, indent=2)
    print(json.dumps({"status": "prepared_disabled", "requests_sent": 0}))


if __name__ == "__main__":
    main()
