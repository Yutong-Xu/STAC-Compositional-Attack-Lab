"""Derived runtime review with source, usage and claim scope kept separate."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from stac_attack_lab.attack_program.file_io import write_json_exclusive
from stac_attack_lab.attack_program.r4 import replay_case
from stac_attack_lab.attack_program.r4_real_diagnosis import _usage


def committed_memory_status(events: list[dict[str, Any]]) -> str:
    return (
        "observed"
        if any(
            event.get("event_type") == "state_write"
            and event.get("status") == "committed"
            and str(event.get("resource_id", "")).startswith("memory")
            and event.get("resource_version_before") != event.get("resource_version_after")
            and event.get("resource_version_after")
            for event in events
        )
        else "unknown"
    )


def review_case(root: Path, case: Path, output: Path) -> dict[str, Any]:
    audit = replay_case(root, case, output)

    def read(name: str) -> Any:
        return json.loads((case / name).read_text())

    bundle = read("runtime_bundle.json")
    observation = read("observation.json")
    result = read("result.json")
    manifest_path = case.parent.parent / "manifest.json"
    prepared = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    delivered = [e for e in observation["events"] if e["event_type"] == "source_delivered"]
    report = {
        "schema_version": "attack-runtime-review/2",
        "source_manifest_hash": prepared.get("manifest_hash"),
        "source_case_manifest_hash": audit["source_manifest_hash"],
        "source": bundle["source"],
        "candidate_id": bundle["candidate_id"],
        "runtime": {
            "source_delivered": delivered,
            "source_delivery": "observed"
            if any(e["status"] == "observed" for e in delivered)
            else "unknown",
            "usage": _usage(bundle["relay_records"]),
            "memory_commit": committed_memory_status(observation["events"]),
            "sessions": [
                {
                    "session_id": s["session_id"],
                    "actual_session_key": s.get("actual_session_key"),
                    "preconditions_satisfied": s.get("preconditions_satisfied"),
                    "file_versions_before": s.get("file_versions_before"),
                    "file_versions_after": s.get("file_versions_after"),
                }
                for s in bundle["sessions"]
            ],
            "cleanup": bundle["cleanup"],
        },
        "official": result["official"].get("score"),
        "independent": result["independent"],
        "causal_contribution": "unknown",
    }
    write_json_exclusive(output / "review.json", report, private=True, durable=True)
    return report
