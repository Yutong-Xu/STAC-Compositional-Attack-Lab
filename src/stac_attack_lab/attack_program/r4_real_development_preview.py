"""Audited real-development public views; never promote them to synthetic or formal data."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from stac_attack_lab.attack_program.file_io import write_json_exclusive as write
from stac_attack_lab.attack_program.models import (
    PRIMITIVES,
    AttackCandidate,
    LibraryManifest,
    RawExampleView,
    StructuredExampleView,
)
from stac_attack_lab.attack_program.pipeline import GateError, build_catalog, make_split
from stac_attack_lab.attack_program.r4_real_import import _validated_source, audit_real_attempt
from stac_attack_lab.attack_program.redaction import scan_for_secrets
from stac_attack_lab.hashing import file_hash, stable_hash


def _views(root: Path, sources: list[dict[str, str]]) -> tuple[list[Any], list[Any], list[Any]]:
    raw, structured, evidence = [], [], []
    seen: set[str] = set()
    sample_ids: set[str] = set()
    for source in sources:
        required = {"batch", "review", "audit", "imports"}
        if set(source) != required:
            raise GateError("preview_source_contract_invalid")
        paths = {key: (root / value).resolve() for key, value in source.items()}
        if any(not path.is_relative_to(root.resolve()) for path in paths.values()):
            raise GateError("preview_source_outside_repository")
        audit_real_attempt(root, paths["batch"], paths["review"], paths["audit"], paths["imports"])
        manifest, sealed, result, _, _ = _validated_source(
            paths["batch"], paths["review"], paths["audit"]
        )
        identity = manifest["manifest_hash"]
        if identity in seen:
            raise GateError("preview_duplicate_measurement")
        seen.add(identity)
        candidate = AttackCandidate.model_validate_json(
            (paths["batch"] / "candidate.json").read_text()
        )
        payload = candidate.patches[0].value
        if scan_for_secrets(payload) or "CANARY_" in payload:
            raise GateError("preview_private_payload")
        sid = stable_hash(
            {
                "task": candidate.task_id,
                "patches": [p.model_dump(mode="json") for p in candidate.patches],
            }
        )[:24]
        common: dict[str, Any] = dict(
            sample_id=sid,
            source_task_group_id=candidate.task_group_id,
            source_split="development",
            validation_class="scope_limited_real_development_observation",
            raw_example=payload,
        )
        if sid not in sample_ids:
            sample_ids.add(sid)
            raw.append(RawExampleView(**common).model_dump(mode="json"))
            # Private occurrences/relations are not copied blindly into public views.
            # Preserve observed/unknown statuses while explicitly declaring missing public evidence.
            status: Any = {
                key: result["independent"]["primitive_evidence"].get(key, "unknown")
                for key in PRIMITIVES
            }
            structured.append(
                StructuredExampleView(
                    **common,
                    occurrences=[],
                    relations=[],
                    primitive_status=status,
                    preconditions=[],
                    evidence_boundary=(
                        "Real development observation; public occurrences/relations not admitted. "
                        "Status alone is not a causal or reusable primitive claim."
                    ),
                ).model_dump(mode="json")
            )
        evidence.append(
            {
                **source,
                "source_manifest_hash": identity,
                "source_case_manifest_hash": sealed["manifest_hash"],
                "sample_id": sid,
                "candidate_hash": manifest["candidate_hash"],
                "measurement_relation": manifest.get("measurement_relation"),
                "official": result["official"]["score"],
                "independent": result["independent"],
            }
        )
    return raw, structured, evidence


def create_preview(root: Path, sources: list[dict[str, str]], output: Path) -> dict[str, Any]:
    if not sources:
        raise GateError("preview_sources_required")
    raw, structured, evidence = _views(root, sources)
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    (output / "private").mkdir(mode=0o700)
    for name, value in (
        ("raw.json", raw),
        ("structured.json", structured),
        ("private/evidence.json", evidence),
    ):
        write(output / name, value, private=True)
    catalog = build_catalog(root)
    manifest = LibraryManifest(
        scope="real_development_preview",
        library_id=output.name,
        source_run="multiple_sealed_runs",
        source_manifest_hash=stable_hash([v["source_manifest_hash"] for v in evidence]),
        catalog_hash=catalog.catalog_hash,
        split_hash=make_split(catalog).split_hash,
        attempt_denominator=len(sources),
        attempt_ids=[v["source_manifest_hash"] for v in evidence],
        sample_ids=[v["sample_id"] for v in raw],
        policy="real-development-preview/1",
        rule_version="public-real-preview/1",
        file_hashes={
            name: file_hash(output / name)
            for name in ("raw.json", "structured.json", "private/evidence.json")
        },
        manifest_hash="",
    )
    body = manifest.model_dump(mode="json", exclude={"manifest_hash"})
    body["manifest_hash"] = stable_hash(body)
    write(output / "manifest.json", body)
    return {
        "status": "development_preview_created",
        "attempts": len(sources),
        "samples": len(raw),
        "formal_library": False,
    }


def audit_preview(root: Path, library: Path) -> dict[str, Any]:
    manifest = LibraryManifest.model_validate_json((library / "manifest.json").read_text())
    if (
        manifest.scope != "real_development_preview"
        or manifest.policy != "real-development-preview/1"
        or stable_hash(manifest.model_dump(mode="json", exclude={"manifest_hash"}))
        != manifest.manifest_hash
        or set(manifest.file_hashes) != {"raw.json", "structured.json", "private/evidence.json"}
        or any(file_hash(library / k) != v for k, v in manifest.file_hashes.items())
    ):
        raise GateError("preview_manifest_invalid")
    evidence = json.loads((library / "private/evidence.json").read_text())
    sources = [{key: v[key] for key in ("batch", "review", "audit", "imports")} for v in evidence]
    raw, structured, rebuilt = _views(root, sources)
    if (
        rebuilt != evidence
        or raw != json.loads((library / "raw.json").read_text())
        or structured != json.loads((library / "structured.json").read_text())
        or manifest.sample_ids != [v["sample_id"] for v in raw]
        or manifest.attempt_denominator != len(evidence)
    ):
        raise GateError("preview_semantics_mismatch")
    return {"status": "valid", "scope": manifest.scope, "samples": len(raw)}
