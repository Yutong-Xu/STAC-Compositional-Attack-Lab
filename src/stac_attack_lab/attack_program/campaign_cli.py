"""Command-line entrypoints reconstructed from the October design notes."""

from __future__ import annotations

import argparse
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from stac_attack_lab.attack_program import development_campaign as campaign
from stac_attack_lab.attack_program.demo_r2 import demo
from stac_attack_lab.attack_program.models import R3PlannerInput
from stac_attack_lab.attack_program.pipeline import GateError
from stac_attack_lab.attack_program.r3 import ScriptedTransport
from stac_attack_lab.attack_program.r4_real_development_preview import audit_preview, create_preview

ROOT = Path(__file__).resolve().parents[3]


class FakePlanner(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        pass

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        if not 0 < length <= 131072:
            self.send_error(413)
            return
        value = json.loads(self.rfile.read(length))
        request = R3PlannerInput.model_validate_json(value["messages"][-1]["content"])
        reply = ScriptedTransport().generate(request, "")
        body = json.dumps(
            {
                "model": "campaign-local-fake",
                "choices": [{"message": {"content": reply.text}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 20, "completion_tokens": 20, "total_tokens": 40},
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=sorted(campaign.KINDS), default="repeated")
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--library", type=Path, required=True)
    prepare.add_argument("--output", type=Path, required=True)
    prepare.add_argument("--mode", choices=("scripted", "local_fake", "real"), default="scripted")
    prepare.add_argument("--planner-model", default="scripted")
    prepare.add_argument("--expected-model", default="scripted")
    prepare.add_argument("--endpoint", default="")
    for name in (
        "preflight",
        "status",
        "summary",
        "authorization-preview",
        "a",
        "b",
        "run",
        "resume",
        "audit",
    ):
        entry = sub.add_parser(name)
        entry.add_argument("--run", type=Path, required=True)
        entry.add_argument("--block", type=int, default=0)
        entry.add_argument("--stage", choices=("run", "a", "b"), default="run")
        entry.add_argument("--authorization", type=Path)
        entry.add_argument("--acknowledge-real-authorization", action="store_true")
    exporter = sub.add_parser("export")
    exporter.add_argument("--run", type=Path, required=True)
    exporter.add_argument("--output", type=Path, required=True)
    demonstration = sub.add_parser("demo")
    demonstration.add_argument("--output", type=Path, required=True)
    demonstration.add_argument("--docker", action="store_true")
    preview = sub.add_parser("preview")
    preview.add_argument("--sources", type=Path, required=True)
    preview.add_argument("--output", type=Path, required=True)
    preview_audit = sub.add_parser("preview-audit")
    preview_audit.add_argument("--library", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result: Any
        if args.command == "prepare":
            result = campaign.prepare(
                ROOT,
                args.library,
                args.output,
                kind=args.kind,
                mode=args.mode,
                planner_model=args.planner_model,
                expected_model=args.expected_model,
                endpoint=args.endpoint,
            )
        elif args.command == "preview":
            result = create_preview(ROOT, campaign.read(args.sources), args.output)
        elif args.command == "preview-audit":
            result = audit_preview(ROOT, args.library)
        elif args.command == "demo":
            base = args.output
            base.mkdir(parents=True, exist_ok=False, mode=0o700)
            demo(ROOT, base / "library-source")
            library = base / "library-source/library"
            run = base / "campaign"
            server: ThreadingHTTPServer | None = None
            previous_key = os.environ.get("SAFECLAW_API_KEY")
            try:
                endpoint = ""
                if args.docker:
                    server = ThreadingHTTPServer(("127.0.0.1", 0), FakePlanner)
                    threading.Thread(target=server.serve_forever, daemon=True).start()
                    endpoint = f"http://127.0.0.1:{server.server_port}/v1"
                    os.environ["SAFECLAW_API_KEY"] = "campaign-local-fake-key"
                campaign.prepare(
                    ROOT,
                    library,
                    run,
                    kind=args.kind,
                    mode="local_fake" if args.docker else "scripted",
                    planner_model="campaign-local-fake" if args.docker else "scripted",
                    expected_model="campaign-local-fake" if args.docker else "scripted",
                    endpoint=endpoint,
                )
                result = campaign.run_stage(ROOT, run)
                campaign.export(run, base / "teacher")
            finally:
                if server:
                    server.shutdown()
                    server.server_close()
                if previous_key is None:
                    os.environ.pop("SAFECLAW_API_KEY", None)
                else:
                    os.environ["SAFECLAW_API_KEY"] = previous_key
        elif args.command == "export":
            result = campaign.export(args.run, args.output)
        elif args.command in {"status", "summary"}:
            result = campaign.status(args.run)
        elif args.command == "audit":
            result = campaign.audit(ROOT, args.run)
        elif args.command in {"preflight", "authorization-preview"}:
            plan = campaign.load(ROOT, args.run)
            result = (
                campaign.authorization_preview(plan, args.stage, args.block)
                if args.command == "authorization-preview"
                else {
                    "status": "preflight_valid",
                    "requests_sent": 0,
                    "plan_hash": plan["plan_hash"],
                }
            )
        else:
            result = campaign.run_stage(
                ROOT,
                args.run,
                stage=args.stage if args.command == "resume" else args.command,
                block=args.block,
                authorization=args.authorization,
                acknowledge=args.acknowledge_real_authorization,
                resume=args.command == "resume",
            )
        print(json.dumps(result, ensure_ascii=False))
        return 2 if (result.get("terminal") or {}).get("status") == "stopped" else 0
    except (GateError, ValueError, OSError) as exc:
        print(
            json.dumps(
                {
                    "status": "rejected",
                    "reason": str(exc) if isinstance(exc, GateError) else type(exc).__name__,
                }
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
