import json

from stac_attack_lab.attack_program import r4_real_development_preview as preview
from stac_attack_lab.attack_program.models import PRIMITIVES


def test_repeated_measurements_remain_in_denominator_without_duplicate_samples(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(preview, "audit_real_attempt", lambda *args: {"status": "valid"})

    def validated(batch, review, audit):
        return (
            {"manifest_hash": batch.name, "candidate_hash": batch.name},
            {"manifest_hash": "case-" + batch.name},
            {
                "official": {"score": {"attack_succeeded": False}},
                "independent": {"primitive_evidence": dict.fromkeys(PRIMITIVES, "unknown")},
            },
            None,
            {},
        )

    monkeypatch.setattr(preview, "_validated_source", validated)
    sources = []
    for index, text in enumerate(("same", "same", "different")):
        batch = tmp_path / f"batch-{index}"
        batch.mkdir()
        (batch / "candidate.json").write_text(
            json.dumps(
                {
                    "schema_version": "attack-candidate/1",
                    "candidate_id": batch.name,
                    "task_id": "pse-2.1-001",
                    "task_group_id": "pse-2.1",
                    "source_split": "development",
                    "patches": [
                        {"pointer": "/environment/workspace_files/4/content", "value": text}
                    ],
                    "planned_primitives": [],
                }
            )
        )
        sources.append(dict(batch=batch.name, review="review", audit="audit", imports="imports"))
    raw, structured, evidence = preview._views(tmp_path, sources)
    assert len(evidence) == 3
    assert len(raw) == len(structured) == 2
    assert evidence[0]["sample_id"] == evidence[1]["sample_id"]
    assert "source_manifest_hash" not in raw[0]
