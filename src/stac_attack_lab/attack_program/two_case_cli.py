"""Two existing-candidate measurements; zero Planner requests."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from stac_attack_lab.attack_program import development_campaign as c
from stac_attack_lab.attack_program.models import AttackCandidate
from stac_attack_lab.attack_program.pipeline import (
    GateError,
    build_catalog,
    make_split,
    materialize,
)
from stac_attack_lab.attack_program.r4_batch import (
    authorization_text,
    bind_disabled,
    prepare_disabled,
    run_disabled,
    validate_prepared,
)
from stac_attack_lab.attack_program.runtime_review import review_case
from stac_attack_lab.hashing import file_hash, stable_hash

ROOT = Path(__file__).resolve().parents[3]


def prepare_pair(
    root: Path, candidates: list[Path], output: Path, *, fake: bool = False
) -> dict[str, Any]:
    if len(candidates) != 2:
        raise GateError("two_candidates_required")
    catalog = build_catalog(root)
    # Validate both before reserving the new output.
    for path in candidates:
        candidate = AttackCandidate.model_validate(c.read(path))
        materialize(root, catalog, make_split(catalog), candidate)
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    slots = []
    for index, path in enumerate(candidates):
        batch = output / f"case-{index + 1}"
        manifest = prepare_disabled(
            root,
            path,
            batch,
            local_fake="harm" if fake else None,
            victim_http_attempts=24,
            session_timeout=720,
            episode_timeout=1800,
            measurement_relation={"kind": "user_supplied_measurement", "ordinal": index + 1},
        )
        slots.append(
            {
                "batch": batch.name,
                "manifest_hash": manifest["manifest_hash"],
                "candidate_hash": manifest["candidate_hash"],
            }
        )
    plan = {
        "schema_version": "reconstructed-two-case/1",
        "scope": "local_fake" if fake else "real",
        "slots": slots,
        "planner_limit": 0,
        "victim_limit": 48,
    }
    plan["plan_hash"] = stable_hash(plan)
    c.write(output / "plan.json", plan)
    return {"status": "prepared_disabled", "plan_hash": plan["plan_hash"], "planner_http": 0}


def load_pair(root: Path, run: Path) -> dict[str, Any]:
    plan = c.read(run / "plan.json")
    if (
        plan.get("schema_version") != "reconstructed-two-case/1"
        or plan.get("plan_hash") != stable_hash({k: v for k, v in plan.items() if k != "plan_hash"})
        or len(plan["slots"]) != 2
    ):
        raise GateError("two_case_plan_invalid")
    for slot in plan["slots"]:
        validate_prepared(root, run / slot["batch"])
        if c.read(run / slot["batch"] / "manifest.json")["manifest_hash"] != slot["manifest_hash"]:
            raise GateError("two_case_manifest_changed")
    return dict(plan)


def run_pair(
    root: Path, run: Path, *, authorization: Path | None = None, acknowledge: bool = False
) -> dict[str, Any]:
    plan = load_pair(root, run)
    expected = {
        "plan_hash": plan["plan_hash"],
        "stage": "victim_only",
        "planner_limit": 0,
        "victim_limit": 48,
        "retries": 0,
    }
    if plan["scope"] == "real" and (
        not acknowledge or authorization is None or c.read(authorization) != expected
    ):
        raise GateError("two_case_real_not_authorized")
    with c.locked(run):
        c.write(
            run / "reservation.json",
            {
                "plan_hash": plan["plan_hash"],
                "parent_authorization_sha256": file_hash(authorization) if authorization else None,
            },
        )
        records = []
        for slot in plan["slots"]:
            batch = run / slot["batch"]
            manifest = c.read(batch / "manifest.json")
            auth = run / (slot["batch"] + "-authorization.json")
            c.write(
                auth,
                {
                    "schema_version": "attack-r4-authorization/1",
                    "scope": manifest["scope"],
                    "manifest_hash": manifest["manifest_hash"],
                    "text": authorization_text(manifest),
                },
            )
            kwargs = dict(
                authorization=auth,
                authorization_sha256=file_hash(auth),
                acknowledge=True,
                local_fake=plan["scope"] == "local_fake",
            )
            bind_disabled(root, batch, **kwargs)
            terminal = run_disabled(root, batch, **kwargs)
            review = review_case(root, batch / "execution/case", run / (slot["batch"] + "-review"))
            if plan["scope"] == "real":
                from stac_attack_lab.attack_program.r4_real_import import (
                    audit_real_attempt,
                    import_real_attempt,
                )

                review_dir = run / (slot["batch"] + "-review")
                imports = run / "private/imports"
                import_real_attempt(root, batch, review_dir, review_dir / "audit.json", imports)
                audit_real_attempt(root, batch, review_dir, review_dir / "audit.json", imports)
            records.append(
                {
                    "batch": slot["batch"],
                    "status": terminal["status"],
                    "victim_http": terminal["victim_http_attempts"],
                    "official": review["official"],
                    "independent": review["independent"],
                }
            )
            if terminal["cleanup"]["status"] != "completed" or any(
                terminal["cleanup"]["owned_after"].values()
            ):
                raise GateError("two_case_cleanup_incomplete")
        summary = {"assigned": 2, "completed": len(records), "planner_http": 0, "records": records}
        c.write(run / "terminal.json", summary)
        return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", choices=("prepare", "preflight", "authorization-preview", "run", "status")
    )
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, action="append", default=[])
    parser.add_argument("--local-fake", action="store_true")
    parser.add_argument("--authorization", type=Path)
    parser.add_argument("--acknowledge-real-authorization", action="store_true")
    args = parser.parse_args()
    try:
        if args.action == "prepare":
            result = prepare_pair(ROOT, args.candidate, args.run, fake=args.local_fake)
        elif args.action == "run":
            result = run_pair(
                ROOT,
                args.run,
                authorization=args.authorization,
                acknowledge=args.acknowledge_real_authorization,
            )
        else:
            plan = load_pair(ROOT, args.run)
            if args.action == "authorization-preview":
                result = {
                    "plan_hash": plan["plan_hash"],
                    "stage": "victim_only",
                    "planner_limit": 0,
                    "victim_limit": 48,
                    "retries": 0,
                }
            elif args.action == "status" and (args.run / "terminal.json").exists():
                result = c.read(args.run / "terminal.json")
            else:
                result = {
                    "status": "preflight_valid",
                    "requests_sent": 0,
                    "planned": 2,
                    "planner_http": 0,
                }
        if args.action == "status" and (args.run / "reservation.json").exists():
            records = []
            for slot in plan["slots"]:
                terminal = args.run / slot["batch"] / "execution/terminal.json"
                record = c.read(terminal) if terminal.exists() else None
                records.append(
                    {
                        "batch": slot["batch"],
                        "status": record["status"]
                        if record
                        else (
                            "uncertain"
                            if (args.run / slot["batch"] / "execution").exists()
                            else "not_started"
                        ),
                        "victim_http": record.get("victim_http_attempts") if record else None,
                    }
                )
            result = {
                "status": "completed"
                if (args.run / "terminal.json").exists()
                else "interrupted_or_active",
                "planned": 2,
                "planner_http": 0,
                "records": records,
                "automatic_retry": False,
            }
        print(json.dumps(result))
        return 0
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
