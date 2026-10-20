import json
from pathlib import Path

import pytest

from stac_attack_lab.attack_program import development_campaign as c
from stac_attack_lab.attack_program.demo_r2 import demo
from stac_attack_lab.attack_program.pipeline import GateError

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def library(tmp_path_factory):
    base = tmp_path_factory.mktemp("rebuilt-campaign")
    demo(ROOT, base / "source")
    return base / "source/library"


@pytest.mark.parametrize("kind,count", list(c.KINDS.items()))
def test_frozen_matrix_pairing_seeds_and_zero_requests(library, tmp_path, kind, count):
    run = tmp_path / kind
    result = c.prepare(ROOT, library, run, kind=kind)
    assert result["assigned"] == count
    assert result["requests_sent"] == 0
    plan = c.load(ROOT, run)
    assert len({s["request"]["case"]["case_id"] for s in plan["slots"]}) == count
    assert all(s["request"]["case"]["planner_request_budget"] == 1 for s in plan["slots"])
    if kind == "primitive":
        assert [s["seed"] for s in plan["slots"]] == list(range(10001, 10031))
        assert len({s["block"] for s in plan["slots"]}) == 5
        assert plan["total_http_limit"] == 750
    if kind == "repeated":
        assert [s["arm"] for s in plan["slots"]] == [
            "no_library",
            "raw_examples",
            "primitive_examples",
            "raw_examples",
            "primitive_examples",
            "no_library",
            "primitive_examples",
            "no_library",
            "raw_examples",
        ]
    assert c.status(run)["victim_completed"] == 0


def test_end_to_end_keeps_denominator_deduplicates_and_independently_audits(library, tmp_path):
    run = tmp_path / "repeated"
    c.prepare(ROOT, library, run)
    result = c.run_stage(ROOT, run)
    assert result["assigned"] == 9
    assert result["planner_http"] == result["victim_http"] == 0
    assert result["planner_valid"] == result["victim_completed"] == 2
    assert sum(row["a"]["status"] == "duplicate" for row in result["rows"]) == 7
    assert c.audit(ROOT, run)["status"] == "valid"
    exported = tmp_path / "teacher"
    c.export(run, exported)
    text = (exported / "all-slots.json").read_text()
    assert len(json.loads(text)["rows"]) == 9
    assert str(ROOT) not in text
    assert "sample_id" not in text and "CANARY_" not in text
    with pytest.raises(GateError, match="already_terminal"):
        c.run_stage(ROOT, run, resume=True)


def test_primitive_no_unique_second_block_stops_but_preserves_thirty(library, tmp_path):
    run = tmp_path / "primitive"
    c.prepare(ROOT, library, run, kind="primitive")
    result = c.run_stage(ROOT, run)
    assert result["assigned"] == 30
    assert result["victim_completed"] == 1
    assert result["terminal"]["reason"] == "block_without_unique_candidate"
    assert sum(row["a"]["status"] == "not_started" for row in result["rows"]) == 18
    assert c.audit(ROOT, run)["status"] == "valid"


def test_a_and_b_authority_stages_cannot_be_reordered(library, tmp_path):
    run = tmp_path / "pilot"
    c.prepare(ROOT, library, run, kind="pilot")
    with pytest.raises(GateError, match="A_incomplete"):
        c.run_stage(ROOT, run, stage="b", block=1)
    a = c.run_stage(ROOT, run, stage="a", block=1)
    assert a["victim_completed"] == 0
    b = c.run_stage(ROOT, run, stage="b", block=1, resume=True)
    assert b["victim_completed"] == 2


def test_uncertain_request_is_never_repeated(library, tmp_path):
    run = tmp_path / "interrupted"
    c.prepare(ROOT, library, run, kind="pilot")
    c.write(run / "private/slots/slot-001/a-reservation.json", {"at": 0})
    with pytest.raises(GateError, match="uncertain_a"):
        c.run_stage(ROOT, run, resume=True)


def test_tampered_frozen_inputs_are_rejected(library, tmp_path):
    run = tmp_path / "tampered"
    c.prepare(ROOT, library, run, kind="pilot")
    (run / "frozen/slot-001.json").write_text("{}")
    with pytest.raises(GateError, match="frozen_request_changed"):
        c.run_stage(ROOT, run)


def test_real_run_cannot_use_synthetic_library(library, tmp_path):
    with pytest.raises(GateError, match="real_requires_real_preview"):
        c.prepare(
            ROOT,
            library,
            tmp_path / "real",
            mode="real",
            planner_model="test",
            expected_model="test",
            endpoint="https://example.test/v1",
        )
    assert not (tmp_path / "real").exists()


def test_diagnostic_never_starts_victim(library, tmp_path):
    run = tmp_path / "diagnostic"
    c.prepare(ROOT, library, run, kind="diagnostic")
    result = c.run_stage(ROOT, run)
    assert result["planner_valid"] == 1 and result["victim_completed"] == 0
    assert c.audit(ROOT, run)["status"] == "valid"


def test_audit_recomputes_selection_even_when_receipt_hashes_are_rewritten(library, tmp_path):
    run = tmp_path / "semantic-tamper"
    c.prepare(ROOT, library, run, kind="pilot")
    c.run_stage(ROOT, run)
    directory = run / "private/slots/slot-002"
    result = c.read(directory / "a-result.json")
    result["selected_sample_ids"] = []
    (directory / "a-result.json").write_text(json.dumps(result))
    seal = c.read(directory / "a-seal.json")
    seal["a-result.json"] = c.file_hash(directory / "a-result.json")
    (directory / "a-seal.json").write_text(json.dumps(seal))
    with pytest.raises(GateError, match="planner_semantics"):
        c.audit(ROOT, run)
