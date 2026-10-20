import json

import pytest

from stac_attack_lab.attack_program.planner_protection import inspect_response, numeric_usage
from stac_attack_lab.attack_program.r4_batch import PreparedManifest
from stac_attack_lab.attack_program.r4_real_diagnosis import _usage


def response(content="{}", **extra):
    return json.dumps(
        {
            "model": "test",
            "choices": [{"message": {"content": content, **extra}, "finish_reason": "stop"}],
            "usage": {"total_tokens": 10},
        }
    ).encode()


def test_usage_unknown_does_not_mean_zero_or_complete():
    assert _usage([])["status"] == "unknown"
    assert (
        _usage(
            [
                {
                    "accepted": True,
                    "provider_usage_observation": "complete",
                    "provider_usage": {"total_tokens": True},
                }
            ]
        )["token_total"]
        is None
    )
    assert numeric_usage({"total_tokens": "password=private-value", "prompt_tokens": 2}) == {
        "prompt_tokens": 2
    }


def test_projection_only_discards_nonrequired_generic_patterns():
    raw = response("{}", reasoning_content="password=placeholder")
    strict = inspect_response(raw, mode="archive", exact=[])
    assert strict["decision"] == "stop"
    projected = inspect_response(raw, mode="required_fields", exact=[])
    assert projected["decision"] == "allow"
    assert "password" not in json.dumps(projected["projection"])
    assert projected["raw_hash"] is None
    assert (
        inspect_response(response("password=placeholder"), mode="required_fields", exact=[])[
            "decision"
        ]
        == "reject_slot"
    )


def test_exact_values_duplicate_keys_and_sensitive_keys_fail_closed():
    raw = response("{}", reasoning_content="private-value")
    report = inspect_response(raw, mode="required_fields", exact=["private-value"])
    assert report["decision"] == "stop"
    assert "private-value" not in json.dumps(report)
    assert inspect_response(b'{"a":1,"a":2}', mode="archive", exact=[])["complete"] is False
    raw = response("{}", **{"password=private-value": "ordinary"})
    assert "private-value" not in json.dumps(
        inspect_response(raw, mode="required_fields", exact=[])
    )


def test_limits_are_explicit_and_old_defaults_remain():
    schema = PreparedManifest.model_json_schema()["properties"]
    assert schema["per_session_timeout_seconds"]["maximum"] == 720
    assert schema["episode_deadline_seconds_after_activation"]["maximum"] == 1800
    assert schema["embedding_enabled"]["default"] is False


@pytest.mark.parametrize(
    "raw", [b"not json", b"[" * 100 + b"]" * 100, b'{"usage":{"total_tokens":NaN}}']
)
def test_invalid_or_resource_limited_diagnostics_stop(raw):
    assert inspect_response(raw, mode="required_fields", exact=[])["decision"] == "stop"


def test_multiline_mail_source_is_not_lost():
    import hashlib

    from stac_attack_lab.attack_program.r4 import _full_mail_result

    body = "first\nsecond\tpart"
    material = {
        "from": "bot@example.test",
        "subject": "Test",
        "body_sha256": hashlib.sha256(body.encode()).hexdigest(),
    }
    text = "id\tabcdef0123456789\nfrom\tbot@example.test\nsubject\tTest\nbody\t" + body
    assert _full_mail_result(text, material, message_id="abcdef0123456789")
    assert not _full_mail_result(text + "tampered", material, message_id="abcdef0123456789")


def test_production_http_diagnostic_blocks_without_saving_private_values(tmp_path, monkeypatch):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread

    from stac_attack_lab.attack_program.models import R3Plan
    from stac_attack_lab.models.base import ModelCallError
    from stac_attack_lab.models.openai_compatible import (
        OpenAICompatibleClient,
        ProviderRequestLedger,
    )

    secret = "private-value-not-for-ledger"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            body = response("{}", reasoning_content=secret)
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("TEST_URL", f"http://127.0.0.1:{server.server_port}/v1")
    monkeypatch.setenv("TEST_KEY", "fake-key")
    ledger = ProviderRequestLedger(1, path=tmp_path / "ledger.jsonl", batch_id="test")
    try:
        client = OpenAICompatibleClient(
            "test",
            request_ledger=ledger,
            base_url_env="TEST_URL",
            api_key_env="TEST_KEY",
            max_response_bytes=131072,
            response_policy="required_fields",
            exact_private_values=[secret],
        )
        with pytest.raises(ModelCallError, match="response_protection_stop"):
            client.generate([], R3Plan, seed=1, timeout=3)
        assert len(ledger.records) == 1
        assert secret not in (tmp_path / "ledger.jsonl").read_text()
        assert client.last_raw_response is None
        assert client.last_projection is None
        assert ledger.records[0].status == 200
    finally:
        ledger.close()
        server.shutdown()
        server.server_close()
        thread.join()


def test_current_r4_budget_options_validate_before_creating_output(tmp_path, monkeypatch):
    from stac_attack_lab.attack_program import r4_batch
    from stac_attack_lab.attack_program.pipeline import JUDGE, PATCH, GateError

    root = __import__("pathlib").Path(__file__).resolve().parents[2]
    monkeypatch.setattr(
        r4_batch,
        "_upstream_preflight",
        lambda _: {
            "commit": r4_batch.build_catalog(root).upstream_commit,
            "judge_hash": r4_batch.file_hash(root / JUDGE),
            "patch_hash": r4_batch.file_hash(root / PATCH),
            "image_digest": "sha256:" + "1" * 64,
        },
    )
    monkeypatch.setattr(
        r4_batch,
        "_project_env",
        lambda _: {"SAFECLAW_MODEL": "test", "SAFECLAW_BASE_URL": "https://example.test/v1"},
    )
    candidate = root / "configs/attack_program/r4_development_candidate.json"
    manifest = r4_batch.prepare_disabled(
        root,
        candidate,
        tmp_path / "new",
        victim_http_attempts=24,
        session_timeout=720,
        episode_timeout=1800,
        measurement_relation={"kind": "repeat"},
    )
    assert manifest["max_http_attempts"]["victim"] == 24
    assert manifest["measurement_relation"] == {"kind": "repeat"}
    assert manifest["embedding_api_key_env"] == "SAFECLAW_EMBEDDING_API_KEY"
    r4_batch.validate_prepared(root, tmp_path / "new")
    with pytest.raises(GateError, match="limits_invalid"):
        r4_batch.prepare_disabled(root, candidate, tmp_path / "invalid", victim_http_attempts=25)
    assert not (tmp_path / "invalid").exists()


def test_diagnostics_detect_sensitive_unknown_key_without_echoing_it():
    raw = response("{}", **{"password": "generic-credential-value"})
    report = inspect_response(raw, mode="required_fields", exact=[])
    assert report["decision"] == "stop"
    assert "generic-credential-value" not in json.dumps(report)
    assert "/password" not in json.dumps(report)


@pytest.mark.parametrize(
    "state,before,after,expected",
    [
        ("committed", "old", "new", "observed"),
        ("observed", "old", "new", "unknown"),
        ("committed", "same", "same", "unknown"),
        ("committed", None, None, "unknown"),
    ],
)
def test_memory_commit_requires_committed_state_and_actual_version_change(
    state, before, after, expected
):
    from stac_attack_lab.attack_program.runtime_review import committed_memory_status

    assert (
        committed_memory_status(
            [
                {
                    "event_type": "state_write",
                    "status": state,
                    "resource_id": "memory",
                    "resource_version_before": before,
                    "resource_version_after": after,
                }
            ]
        )
        == expected
    )
