"""release verification reference-release evidence and clean-artifact gate coverage."""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tarfile
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from masugate.protected_execution import ProtectedExecutionBinding
from masugate.pss import check_pss
from masugate_openclaw_reference import release_verification_release
from masugate_openclaw_reference.audit_validation import authorization_digest

ROOT = Path(__file__).parents[1]
CONTAINMENT = ROOT / "integrations" / "openclaw-reference" / "containment"
RUNNER = ROOT / "scripts" / "run-reference-release-gate.py"
DOCKER = os.environ.get("MASUGATE_DOCKER_BIN", "docker")


def _summary(samples: list[float], elapsed_ms: float) -> dict[str, object]:
    return release_verification_release.measurement_summary(samples, elapsed_ms)


def _spend_authorization_fixture() -> dict[str, object]:
    manifest = json.loads((ROOT / "release" / "reference-release.json").read_text(encoding="utf-8"))
    declared = cast(dict[str, object], manifest["reference_demo_spend_authorization"])
    return {
        "configuration_digest": declared["configuration_digest"],
        "policy": deepcopy(declared["policy"]),
    }


def _release_descriptor_fixture() -> dict[str, object]:
    return {
        "schema_version": "masugate.reference_demo-release-descriptor/v1",
        "release_id": "masugate-openclaw-reference/0.1.0",
        "source_revision": "a" * 40,
        "staging_realization_revision": "b" * 40,
        "release_manifest_sha256": "b" * 64,
        "provenance_sha256": "c" * 64,
        "checksums_sha256": "d" * 64,
        "sbom_sha256": "e" * 64,
        "artifact_inventory_sha256": "1" * 64,
        "runtime_target": {"os": "linux", "architecture": "amd64", "python_abi": "cp312"},
        "spend_authorization": _spend_authorization_fixture(),
    }


def _governance_record(
    *,
    operation_id: str,
    key: str,
    principal: str,
    amount_cents: int,
    merchant_id: str,
    request_ref: str,
    status: str,
    read_value: int,
    read_version: int,
    budget_version: int | None = None,
) -> dict[str, object]:
    arguments = {
        "amount_cents": amount_cents,
        "merchant_id": merchant_id,
        "request_ref": request_ref,
    }
    committed = status == "committed"
    evaluated_at = "2026-07-21T12:00:00+00:00"
    resolved_at = "2026-07-21T12:00:00.500000+00:00"
    observed_at = "2026-07-21T12:00:00.750000+00:00"
    recorded_at = "2026-07-21T12:00:01+00:00"
    read = {
        "arguments": ["research"],
        "function": "spend.available_cents",
        "latency_ms": 0.1,
        "scope": "spend:team:research",
        "value": read_value,
        "version": read_version,
    }
    approval_required = committed and key.startswith("reference_demo-")
    anchor = _spend_authorization_fixture()
    provenance = cast(dict[str, object], deepcopy(anchor["policy"]))
    runtime_version = cast(str, provenance["policy_runtime_version"])
    evaluated_policies = [{"policy_id": "spend_budget_guard", "policy_version": runtime_version}]
    authorization = {
        "effect": "escalate" if approval_required else ("allow" if committed else "deny"),
        "evaluated_policies": evaluated_policies,
        "policy_id": "spend_budget_guard",
        "policy_provenance": [provenance],
        "policy_version": runtime_version,
        "reads": [read],
        "reason": (
            "rule ask_first evaluated to true"
            if approval_required
            else ("default rule" if committed else "rule budget_cap evaluated to true")
        ),
        "rule_id": (
            "ask_first" if approval_required else ("otherwise" if committed else "budget_cap")
        ),
    }
    effect_authorization = {
        name: value for name, value in authorization.items() if name != "policy_provenance"
    }
    effect_authorization["reads"] = [
        {name: value for name, value in read.items() if name != "latency_ms"}
    ]
    adapter_invocation_digest = hashlib.sha256(f"masugate.openclaw:{key}".encode()).hexdigest()
    request = {
        "action": "spend.purchase",
        "adapter_invocation_digest": adapter_invocation_digest,
        "args": arguments,
        "idempotency_key": key,
        "principal": {
            "attributes": {"masugate_require_adapter_invocation": True, "team": "research"},
            "id": principal,
        },
        "request_time": evaluated_at,
        "timestamp": evaluated_at,
        "trace_id": f"release_verification:{key}"
        if key.startswith("release_verification-")
        else f"reference_demo:{key}",
    }
    resolution = (
        {
            "actor_id": "operator",
            "approved": True,
            "evidence": {
                "decision": "allow-once",
                "scenario": "e2-procurement-race",
                "source": "reference-demo-demo",
            },
            "kind": "human",
            "resolved_at": resolved_at,
        }
        if approval_required
        else None
    )
    authorization_digest_value = authorization_digest(
        request,
        authorization,
        budget_version=cast(int, budget_version) if committed else read_version,
        configuration_digest=cast(str, anchor["configuration_digest"]),
        resolution=resolution,
    )
    entitlement_id = f"entitlement:{operation_id}"
    binding = {
        "action": "spend.purchase",
        "arguments": arguments,
        "authorization_digest": authorization_digest_value,
        "connector_id": "reference-purchase-v1",
        "coordination_domain_id": "masugate.spend.reference.domain.v1",
        "entitlement_id": entitlement_id,
        "idempotency_key": key,
        "policies": [
            {
                "bundle_digest": provenance["bundle_digest"],
                "bundle_id": provenance["bundle_id"],
                "bundle_version": provenance["bundle_version"],
                "policy_digest": provenance["policy_digest"],
                "policy_id": provenance["policy_id"],
                "policy_version": provenance["policy_declared_version"],
            }
        ],
        "principal_id": principal,
        "provider_identity": {
            "configuration_version": anchor["configuration_digest"],
            "implementation_version": "masugate.spend.reference-v1",
            "provider_id": "masugate.spend.reference",
        },
        "scopes": ["spend:team:research"],
        "tool_call_id": request["trace_id"],
    }
    canonical = json.dumps(binding, separators=(",", ":"), sort_keys=True)
    binding_digest = hashlib.sha256(canonical.encode()).hexdigest()
    external_operation_id = f"purchase:{binding_digest[:32]}"
    receipt_payload = {"amount_cents": amount_cents, "merchant_id": merchant_id}
    receipt = {
        "connector_id": "reference-purchase-v1",
        "evidence_id": f"purchase-evidence:{binding_digest[:32]}",
        "external_operation_id": external_operation_id,
        "idempotency_key": f"masugate:{binding_digest}",
        "observed_at": observed_at,
        "outcome": "succeeded",
        "payload": receipt_payload,
    }
    record: dict[str, object] = {
        "operation_id": operation_id,
        "status": status,
        "request": request,
        "policy": {
            "catalog": {
                "bundle_digest": provenance["bundle_digest"],
                "policy_digest": provenance["policy_digest"],
            },
            "evaluated_policies": evaluated_policies,
            "evaluated_policy_provenance": [provenance],
            "policy_id": "spend_budget_guard",
            "policy_version": runtime_version,
        },
        "entitlement": {
            "authorization_digest": authorization_digest_value,
            "entitlement_id": entitlement_id,
        },
        "authorization_evaluations": [
            {
                "certified_inputs": [],
                "decision": authorization,
                "evaluated_at": evaluated_at,
                "phase": "admission",
            }
        ],
        "decision": (
            {
                "effect": "allow",
                "reason": "reference purchase committed with connector receipt",
                "rule_id": "approval.approved" if approval_required else "otherwise",
            }
            if committed
            else {
                "effect": "deny",
                "reason": "rule budget_cap evaluated to true",
                "rule_id": "budget_cap",
            }
        ),
        "view_reads": [read],
        "effect": (
            {
                "action": "spend.purchase",
                "args": arguments,
                "payload": {
                    **arguments,
                    "authorization": effect_authorization,
                    "authorization_digest": authorization_digest_value,
                    "budget_version": budget_version,
                    "entitlement_id": entitlement_id,
                    "entitlement_state": "consumed",
                    "handoff": {"binding_digest": binding_digest, "state": "succeeded"},
                    "protected_execution": {
                        "binding_digest": binding_digest,
                        "dispatch_started": True,
                        "entitlement_state": "consumed",
                        "execution_id": f"px:{binding_digest}",
                        "external_operation_id": external_operation_id,
                        "fence_token": 1,
                        "lease": None,
                        "receipt": receipt,
                        "status": "succeeded",
                    },
                    "team_id": "research",
                    **({"resolution": resolution} if resolution is not None else {}),
                },
            }
            if committed
            else None
        ),
        "protected_execution": (
            {
                "binding": binding,
                "binding_canonical_json": canonical,
                "binding_digest": binding_digest,
                "dispatch_started": True,
                "entitlement_state": "consumed",
                "execution_id": f"px:{binding_digest}",
                "external_operation_id": external_operation_id,
                "last_fence_token": 1,
                "lease": None,
                "receipt": receipt,
                "result": receipt_payload,
                "status": "succeeded",
            }
            if committed
            else None
        ),
        "terminal_serialization": {
            "authorization_basis": (
                "preserved-admission-evaluation" if approval_required else "admission-evaluation"
            ),
            "evaluation_at": evaluated_at,
            "evaluation_phase": "admission",
            "kind": "effect-commit" if committed else "denial-record",
            "provider_atomic": False,
            "recorded_at": recorded_at,
        },
        "recorded_at": recorded_at,
    }
    if approval_required:
        record["human_resolution"] = {
            name: value
            for name, value in cast(dict[str, object], resolution).items()
            if name != "kind"
        }
    return record


def _concurrency_addon() -> dict[str, object]:
    scope = "spend:team:research"
    governed_history = [
        {
            "operation_id": "committed:reservation",
            "causal_operation_id": "committed",
            "event_kind": "coordination-reservation",
            "begin_ns": 1,
            "terminal_ns": 3,
            "committed": True,
            "policy_reads": [{"scope": scope, "version": 0}],
            "effect_reads": [],
            "effect_writes": [{"scope": scope, "version": 1}],
        },
        {
            "operation_id": "denied",
            "causal_operation_id": "denied",
            "event_kind": "terminal-denial",
            "begin_ns": 1,
            "terminal_ns": 4,
            "committed": False,
            "policy_reads": [{"scope": scope, "version": 1}],
            "effect_reads": [],
            "effect_writes": [],
        },
        {
            "operation_id": "committed:settlement",
            "causal_operation_id": "committed",
            "event_kind": "terminal-settlement",
            "begin_ns": 5,
            "terminal_ns": 6,
            "committed": True,
            "policy_reads": [],
            "effect_reads": [{"scope": scope, "version": 1}],
            "effect_writes": [{"scope": scope, "version": 2}],
        },
    ]
    weak_history = [
        {
            "operation_id": "weak-alpha",
            "causal_operation_id": "weak-alpha",
            "event_kind": "terminal-effect",
            "begin_ns": 1,
            "terminal_ns": 3,
            "committed": True,
            "policy_reads": [{"scope": scope, "version": 0}],
            "effect_reads": [],
            "effect_writes": [{"scope": scope, "version": 1}],
        },
        {
            "operation_id": "weak-beta",
            "causal_operation_id": "weak-beta",
            "event_kind": "terminal-effect",
            "begin_ns": 1,
            "terminal_ns": 4,
            "committed": True,
            "policy_reads": [{"scope": scope, "version": 0}],
            "effect_reads": [],
            "effect_writes": [{"scope": scope, "version": 2}],
        },
    ]
    governed_verdict = check_pss(
        release_verification_release._validate_concurrent_history(
            governed_history, "fixture governed history", kind="governed"
        )
    )
    weak_verdict = check_pss(
        release_verification_release._validate_concurrent_history(
            weak_history, "fixture weak history", kind="weak"
        )
    )
    governed = {
        "kind": "governed-product-coordination",
        "assumptions": {
            "budget_cents": 10_000,
            "agents": 2,
            "amount_cents_each": 6_000,
            "coordination": "PostgreSQL spend entitlement/reservation plus protected runner",
            "artifact_boundary": (
                "calls the running reference demonstration clean-artifact compose service"
            ),
        },
        "committed_cents": 6_000,
        "budget_valid": True,
        "terminal_statuses": ["committed", "denied"],
        "pss": {"valid": governed_verdict.pss, "reason": governed_verdict.reason},
        "history": governed_history,
        "final_policy_state": {
            "scope": scope,
            "version": 2,
            "limit_cents": 10_000,
            "spent_cents": 6_000,
            "held_cents": 0,
            "available_cents": 4_000,
        },
        "governance_records": [
            _governance_record(
                operation_id="committed",
                key="reference_demo-e2-alpha",
                principal="openclaw:buyer-alpha",
                amount_cents=6_000,
                merchant_id="reference-demo-procurement",
                request_ref="reference_demo-e2-alpha",
                status="committed",
                read_value=10_000,
                read_version=0,
                budget_version=1,
            ),
            _governance_record(
                operation_id="denied",
                key="reference_demo-e2-beta",
                principal="openclaw:buyer-beta",
                amount_cents=6_000,
                merchant_id="reference-demo-procurement",
                request_ref="reference_demo-e2-beta",
                status="denied",
                read_value=4_000,
                read_version=1,
            ),
        ],
    }
    weak = {
        "kind": "deliberately-weak-request-time-baseline",
        "assumptions": {
            "budget_cents": 10_000,
            "agents": 2,
            "amount_cents_each": 6_000,
            "interleaving": "both requests read remaining budget version 0 before either effect",
            "coordination": "none after the request-time read",
        },
        "committed_cents": 12_000,
        "overshoot_cents": 2_000,
        "stale_authorization": True,
        "effect_ledger": [
            {"operation_id": "weak-alpha", "amount_cents": 6_000, "budget_version": 1},
            {"operation_id": "weak-beta", "amount_cents": 6_000, "budget_version": 2},
        ],
        "pss": {"valid": weak_verdict.pss, "reason": weak_verdict.reason},
        "history": weak_history,
    }
    return {
        "scenario": "E2 procurement workload",
        "governed": governed,
        "weak_baseline": weak,
        "measured_asymmetry": {
            "weak_committed_cents": weak["committed_cents"],
            "governed_committed_cents": governed["committed_cents"],
            "weak_overshoot_cents": weak["overshoot_cents"],
            "governed_pss_valid": governed["pss"],
        },
    }


def _valid_evidence() -> dict[str, object]:
    source_cases = release_verification_release._slice_cases()
    cases: list[dict[str, object]] = []
    for case_id, source in source_cases.items():
        fixture = release_verification_release._fixture_for_case(case_id)
        translation = source["translation"]
        assert isinstance(translation, dict)
        governed: dict[str, object] = {
            "attack_success": False,
            "outcome": translation["expected_outcome"],
            "status_code": translation["expected_status"],
        }
        if translation["expected_outcome"] == "denied":
            governed.update(
                decision=translation["expected_decision"],
                audit={
                    "effect_present": False,
                    "protected_execution_present": False,
                    "status": "denied",
                },
            )
        else:
            governed["error"] = translation["expected_error"]
        cases.append(
            {
                "case_id": case_id,
                "corpus": source["corpus"],
                "fixture_id": source["fixture_id"],
                "prompt_sha256": fixture["prompt_sha256"],
                "attack_class": source["attack_class"],
                "execution_surface": source["execution_surface"],
                "action": source["action"],
                "governed": governed,
                "ungoverned_comparison": {
                    "attack_success": True,
                    "claim_boundary": release_verification_release._ADVERSARIAL_COMPARISON_BOUNDARY,
                    "comparison_action": "spend.purchase",
                    "execution_surface": (
                        "server-to-server connector credential in disposable stack"
                    ),
                    "external_operation_id": f"ungoverned-{case_id}",
                    "outcome": "succeeded",
                },
            }
        )
    baseline = _summary([1.0] * 6, 6.0)
    governed = _summary([2.0] * 6, 12.0)
    return {
        "schema_version": "masugate.release_verification-reference-release-evidence/v1",
        "release": _release_descriptor_fixture(),
        "adversarial": {
            "benchmarks": release_verification_release._benchmark_metadata(),
            "scope": release_verification_release._adversarial_slice()["scope"],
            "cases": cases,
            "governed_attack_successes": 0,
            "concurrent_addon": _concurrency_addon(),
            "gateway_jailbreak": {
                "mode": "attack",
                "case_id": "agentdojo-over-budget",
                "status": "denied",
                "elapsed_ms": 1.0,
                "prompt_sha256": release_verification_release.gateway_jailbreak_prompt_sha256(
                    "agentdojo-over-budget"
                ),
            },
            "direct_access": {
                "status": "blocked",
                "oracle": "scripts/run-reference-containment-live.py",
                "output_sha256": "f" * 64,
            },
        },
        "negative_boundaries": {
            "wrong_but_authorized": {
                "authorization_status": "committed",
                "governance_record": _governance_record(
                    operation_id="wrong-but-authorized-operation",
                    key="release_verification-wrong-but-authorized",
                    principal="openclaw:buyer-alpha",
                    amount_cents=400,
                    merchant_id="wrong-but-authorized",
                    request_ref="release_verification-wrong-but-authorized",
                    status="committed",
                    read_value=3_100,
                    read_version=0,
                    budget_version=1,
                ),
                "merchant_id": "wrong-but-authorized",
                "operation_id": "wrong-but-authorized-operation",
                "task_semantically_correct": False,
            },
            "out_of_band_mutation": {
                "premise_broken": True,
                "detected": True,
                "delta_cents": 17,
                "before": {
                    "limit_cents": 10_000,
                    "spent_cents": 7_300,
                    "held_cents": 0,
                    "version": 2,
                    "unexplained_spent_cents": 0,
                    "recorded_spent_cents": 7_300,
                },
                "after": {
                    "limit_cents": 10_000,
                    "spent_cents": 7_317,
                    "held_cents": 0,
                    "version": 3,
                    "unexplained_spent_cents": 17,
                    "recorded_spent_cents": 7_300,
                },
            },
        },
        "performance": {
            "workload": {
                "actors": ["openclaw:buyer-alpha", "openclaw:buyer-beta"],
                "action": "spend.purchase",
                "amount_cents": 100,
                "samples_per_path": 6,
                "name": "two-principal reference-purchase fleet slice",
            },
            "ungoverned_connector_comparison": {
                "claim_boundary": (
                    "comparison only; it bypasses provider admission and is not governed"
                ),
                "execution_surface": "server-to-server connector credential",
                **baseline,
            },
            "governed_fleet": governed,
            "p50_overhead_percent": 100.0,
            "resource_use": {
                "driver_process": {
                    "max_rss_kib": 1,
                    "system_cpu_seconds": 0.0,
                    "user_cpu_seconds": 0.0,
                },
                "stack": {
                    "source": "docker stats --no-stream",
                    "containers": [
                        {
                            "container": "masugated",
                            "cpu_percent": "0.00%",
                            "memory_usage": "1MiB / 1GiB",
                            "network_io": "0B / 0B",
                            "block_io": "0B / 0B",
                        }
                    ],
                },
            },
        },
        "availability": {
            "consequential_action": {
                "case_id": "coordinator-down",
                "elapsed_ms": 1.0,
                "mode": "down",
                "status": "blocked",
            },
            "benign_action": {
                "case_id": "coordinator-down",
                "elapsed_ms": 1.0,
                "mode": "safe",
                "status": "available",
            },
        },
        "integration": {
            "artifact_context": "clean release artifact context",
            "compatibility_pin": "2026.7.1",
            "configuration_files": ["integrations/openclaw-reference/plugin-config.example.json"],
            "configuration_loc": 1,
            "integration_files": ["integrations/openclaw/src/plugin.ts"],
            "integration_loc": 1,
            "no_fork": True,
            "time_to_governed_definition": (
                "compose up start through first committed Gateway MasuGate-owned action"
            ),
            "time_to_governed_ms": 1.0,
        },
        "external_validity": {
            "status": "deferred",
            "claim": False,
            "reason": "T7 realistic-workload validity is intentionally deferred.",
        },
    }


def _docker_available() -> bool:
    if shutil.which(DOCKER) is None and not Path(DOCKER).is_file():
        return False
    try:
        return subprocess.run([DOCKER, "info"], check=False, capture_output=True).returncode == 0
    except OSError:
        return False


def test_stack_resources_preserves_docker_stats_memory_usage_field() -> None:
    module = _release_gate_module()

    class _FakeRunner:
        def _compose(self, *_args: object) -> str:
            return "container-id\n"

        def _run(self, *_args: object, **_kwargs: object) -> str:
            return json.dumps(
                {
                    "Name": "masugate-release_verification-service",
                    "CPUPerc": "0.10%",
                    "MemUsage": "1MiB / 1GiB",
                    "NetIO": "1kB / 2kB",
                    "BlockIO": "0B / 0B",
                }
            )

    observed = module._stack_resources(_FakeRunner(), "release_verification-project", {})

    assert observed == {
        "containers": [
            {
                "block_io": "0B / 0B",
                "container": "masugate-release_verification-service",
                "cpu_percent": "0.10%",
                "memory_usage": "1MiB / 1GiB",
                "network_io": "1kB / 2kB",
            }
        ],
        "source": "docker stats --no-stream",
    }


def test_measurement_summary_uses_nearest_rank_percentiles() -> None:
    summary = release_verification_release.measurement_summary([1.0, 2.0, 3.0, 4.0], 10.0)
    assert summary == {
        "count": 4,
        "elapsed_ms": 10.0,
        "samples_ms": [1.0, 2.0, 3.0, 4.0],
        "p50_ms": 2.0,
        "p95_ms": 4.0,
        "p99_ms": 4.0,
        "throughput_ops_per_second": 400.0,
    }


def test_release_evidence_validator_accepts_complete_bounded_contract(tmp_path: Path) -> None:
    evidence = _valid_evidence()
    assert release_verification_release.validate_release_evidence(evidence) is evidence
    path = tmp_path / "reference-release-evidence.json"
    path.write_text(json.dumps(evidence), encoding="utf-8")
    completed = subprocess.run(
        [
            sys.executable,
            str(RUNNER),
            "--verify-evidence",
            str(path),
            "--offline-npm-cache",
            str(tmp_path / "offline-cache"),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode != 0
    assert "retained release" in completed.stderr


def _release_gate_module() -> Any:
    spec = importlib.util.spec_from_file_location("release_verification_release_gate_test", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_release_gate_copies_only_the_verified_alpine_closure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _release_gate_module()
    closure = tmp_path / "closure"
    artifacts: list[dict[str, object]] = []

    def add(kind: str, relative: str, *, repository: str | None = None) -> None:
        path = closure.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(relative.encode("utf-8"))
        item: dict[str, object] = {
            "kind": kind,
            "path": relative.replace("/", "\\"),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        if repository is not None:
            item["repository"] = repository
        artifacts.append(item)

    add("public_key", "trust/alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub")
    for repository in ("main", "community"):
        add("signed_index", f"indexes/{repository}/APKINDEX.tar.gz", repository=repository)
    for index in range(32):
        add("apk", f"apk/v3.21/main/x86_64/fixture-{index}.apk")
    manifest = closure / "MANIFEST.json"
    manifest.write_text(
        json.dumps({"artifacts": artifacts, "closure_manifest_sha256": "f" * 64}),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        module,
        "_ALPINE_CLOSURE_FILE_SHA256",
        hashlib.sha256(manifest.read_bytes()).hexdigest(),
    )
    monkeypatch.setattr(module, "_ALPINE_CLOSURE_CONTENT_SHA256", "f" * 64)

    destination = tmp_path / "staged"
    module._copy_alpine_closure(closure, destination)

    assert (destination / "keys" / "alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub").is_file()
    assert (destination / "repositories" / "main" / "x86_64" / "APKINDEX.tar.gz").is_file()
    assert (destination / "repositories" / "community" / "x86_64" / "APKINDEX.tar.gz").is_file()
    assert len(list((destination / "repositories" / "main" / "x86_64").glob("*.apk"))) == 32


def test_release_gate_accepts_only_the_hash_bound_pycache_overlay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _release_gate_module()
    artifact = tmp_path / module._ALPINE_PYTHON_PYC_NAME
    artifact.write_bytes(b"pycache overlay")
    monkeypatch.setattr(
        module,
        "_ALPINE_PYTHON_PYC_SHA256",
        hashlib.sha256(artifact.read_bytes()).hexdigest(),
    )
    destination = tmp_path / "staged"
    (destination / "repositories" / "main" / "x86_64").mkdir(parents=True)

    module._copy_alpine_python_pyc_overlay(artifact, destination)

    assert (
        destination / "repositories" / "main" / "x86_64" / module._ALPINE_PYTHON_PYC_NAME
    ).read_bytes() == b"pycache overlay"
    artifact.write_bytes(b"tampered")
    with pytest.raises(module.ReleaseGateError, match="does not match"):
        module._copy_alpine_python_pyc_overlay(artifact, destination)


def test_release_gate_allows_bundled_masugate_dependencies_but_rejects_openclaw_runtime(
    tmp_path: Path,
) -> None:
    module = _release_gate_module()
    context = tmp_path / "artifact-context"
    package = context / "package"
    (package / "dist" / "src").mkdir(parents=True)
    (package / "node_modules" / "@masugate" / "client").mkdir(parents=True)
    (package / "package.json").write_text('{"name":"@masugate/openclaw"}', encoding="utf-8")
    (package / "dist" / "src" / "plugin.js").write_text("export {};\n", encoding="utf-8")
    (package / "node_modules" / "@masugate" / "client" / "package.json").write_text(
        '{"name":"@masugate/client"}', encoding="utf-8"
    )
    tarballs = context / "artifacts" / "npm"
    tarballs.mkdir(parents=True)
    tarball = tarballs / "masugate-openclaw-0.1.0.tgz"

    with tarfile.open(tarball, "w:gz") as archive:
        archive.add(package, arcname="package")
    artifact, files = module._adapter_artifact(context)
    assert artifact["name"] == "@masugate/openclaw"
    assert [name for name, _ in files] == [
        "artifacts/npm/masugate-openclaw-0.1.0.tgz!package/dist/src/plugin.js"
    ]

    (package / "node_modules" / "openclaw").mkdir()
    (package / "node_modules" / "openclaw" / "package.json").write_text(
        '{"name":"openclaw"}', encoding="utf-8"
    )
    with tarfile.open(tarball, "w:gz") as archive:
        archive.add(package, arcname="package")
    with pytest.raises(module.ReleaseGateError, match="copied OpenClaw runtime"):
        module._adapter_artifact(context)


def test_live_gate_reuses_retained_release_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _release_gate_module()
    release = tmp_path / "release"
    release.mkdir()
    source_revision = "a" * 40
    staging_revision = "b" * 40
    (release / "provenance.json").write_text(
        json.dumps(
            {
                "source_revision": source_revision,
                "staging_realization_revision": staging_revision,
            }
        ),
        encoding="utf-8",
    )
    descriptor = _release_descriptor_fixture()
    descriptor["source_revision"] = source_revision
    descriptor["staging_realization_revision"] = staging_revision

    class _FakeRunner:
        def _current_source_revision(self) -> str:
            raise AssertionError("retained release must not use the umbrella workspace revision")

        def _verify_release_output(
            self,
            observed_release: Path,
            *,
            expected_source_revision: str,
            expected_staging_realization_revision: str,
        ) -> dict[str, object]:
            assert observed_release == release
            assert expected_source_revision == source_revision
            assert expected_staging_realization_revision == staging_revision
            return dict(descriptor)

    observed_release, observed_descriptor = module._build_or_verify_release(
        _FakeRunner(), tmp_path / "output", release
    )

    assert observed_release == release
    assert observed_descriptor == descriptor


def test_offline_verification_binds_evidence_to_retained_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = _valid_evidence()
    path = tmp_path / "reference-release-evidence.json"
    path.write_text(json.dumps(evidence), encoding="utf-8")
    retained_release = tmp_path / "release"
    retained_release.mkdir()
    offline_cache = tmp_path / "offline-cache"
    descriptor = dict(cast(dict[str, object], evidence["release"]))
    retained_integration = cast(dict[str, object], evidence["integration"])
    derived_integration = {
        key: retained_integration[key]
        for key in (
            "artifact_context",
            "compatibility_pin",
            "configuration_files",
            "configuration_loc",
            "integration_files",
            "integration_loc",
            "no_fork",
        )
    }
    module = _release_gate_module()

    class _FakeRunner:
        def _verify_release_output(
            self,
            release: Path,
            *,
            expected_source_revision: str,
            expected_staging_realization_revision: str,
        ) -> dict[str, object]:
            assert release == retained_release
            assert expected_source_revision == descriptor["source_revision"]
            assert (
                expected_staging_realization_revision == descriptor["staging_realization_revision"]
            )
            return dict(descriptor)

        def _stage_artifact_context(
            self, release: Path, staging: Path, *, offline_npm_cache: Path
        ) -> Path:
            assert release == retained_release
            assert offline_npm_cache == offline_cache
            return staging / "artifact-context"

    monkeypatch.setattr(module, "_reference_demo", lambda: _FakeRunner())
    monkeypatch.setattr(module, "_integration_footprint", lambda _path: derived_integration)
    module._validate_existing(path, None, offline_npm_cache=offline_cache)
    descriptor["sbom_sha256"] = "0" * 64
    with pytest.raises(module.ReleaseGateError, match="does not match"):
        module._validate_existing(path, None, offline_npm_cache=offline_cache)
    descriptor["sbom_sha256"] = cast(dict[str, object], evidence["release"])["sbom_sha256"]
    derived_integration["configuration_loc"] = 2
    with pytest.raises(module.ReleaseGateError, match="integration footprint"):
        module._validate_existing(path, None, offline_npm_cache=offline_cache)


def test_release_gate_retains_portable_fields_from_bound_reference_demo_descriptor() -> None:
    module = _release_gate_module()
    portable = _release_descriptor_fixture()
    bound = {
        **portable,
        "staged_compose": {"bundle_sha256": "2" * 64, "files": {}},
    }
    assert module._release_descriptor(bound) == portable
    bound["unexpected"] = True
    with pytest.raises(module.ReleaseGateError, match="incomplete"):
        module._release_descriptor(bound)


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        (
            lambda value: value["adversarial"]["cases"][0]["governed"].update(
                {"attack_success": True}
            ),
            "governed attack boundary",
        ),
        (
            lambda value: value["adversarial"]["cases"][0].update({"prompt_sha256": "0" * 64}),
            "selected fixture",
        ),
        (
            lambda value: value["negative_boundaries"]["out_of_band_mutation"]["after"].update(
                {"unexplained_spent_cents": 0}
            ),
            "reconciled",
        ),
        (
            lambda value: value["performance"]["governed_fleet"].update({"p99_ms": 1.0}),
            "not derived",
        ),
        (
            lambda value: value["external_validity"].update({"claim": True}),
            "T7",
        ),
        (
            lambda value: value["adversarial"]["cases"][0]["ungoverned_comparison"].update(
                {"comparison_action": "native.purchase"}
            ),
            "governed attack boundary",
        ),
        (
            lambda value: value["integration"].update({"compatibility_pin": "wrong-pin"}),
            "integration evidence is incomplete",
        ),
    ],
)
def test_release_evidence_validator_rejects_claim_and_measurement_mutants(
    mutation: Any,
    match: str,
) -> None:
    evidence = deepcopy(_valid_evidence())
    mutation(evidence)
    with pytest.raises(release_verification_release.ReleaseVerificationReleaseError, match=match):
        release_verification_release.validate_release_evidence(evidence)


def test_ungoverned_native_route_comparison_uses_declared_purchase_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    class _FakePurchaseApi:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        async def initialize(self) -> None:
            return None

        async def execute(
            self,
            binding: object,
            *,
            idempotency_key: str,
            fence_token: int,
        ) -> SimpleNamespace:
            captured.update(
                binding=binding,
                idempotency_key=idempotency_key,
                fence_token=fence_token,
            )
            return SimpleNamespace(
                outcome=SimpleNamespace(value="succeeded"),
                external_operation_id="comparison-effect",
            )

        async def close(self) -> None:
            return None

    from masugate_openclaw_reference import gateway_recovery_live

    monkeypatch.setattr(gateway_recovery_live, "_purchase_credentials", lambda: ("token", object()))
    monkeypatch.setattr(release_verification_release, "HttpReferencePurchaseApi", _FakePurchaseApi)
    result = asyncio.run(
        release_verification_release._ungoverned_attack_effect(
            index=1,
            case_id="agentdojo-undeclared-native-route",
            amount_cents=100,
            merchant_id="release_verification-agentdojo-native-route",
        )
    )
    binding = cast(ProtectedExecutionBinding, captured["binding"])
    assert binding.action == "spend.purchase"
    assert result["comparison_action"] == "spend.purchase"


def test_adversarial_blocked_case_rejects_a_success_shaped_error_response() -> None:
    source = release_verification_release._slice_cases()["agentdojo-undeclared-native-route"]
    translation = cast(dict[str, object], source["translation"])
    with pytest.raises(
        release_verification_release.ReleaseVerificationReleaseError, match="expected blocked error"
    ):
        release_verification_release._validate_adversarial_response(
            "agentdojo-undeclared-native-route",
            translation,
            release_verification_release._TimedResponse(
                body={"status": "committed", "operation_id": "unrelated"},
                elapsed_ms=1.0,
                status_code=409,
            ),
        )


def test_release_evidence_replays_concurrency_and_e6_transitions() -> None:
    evidence = _valid_evidence()
    concurrent = cast(dict[str, object], evidence["adversarial"])["concurrent_addon"]
    weak = cast(dict[str, object], cast(dict[str, object], concurrent)["weak_baseline"])
    history = cast(list[dict[str, object]], weak["history"])
    history[1]["policy_reads"] = [{"scope": "spend:team:research", "version": 1}]
    with pytest.raises(
        release_verification_release.ReleaseVerificationReleaseError,
        match="weak evidence does not replay",
    ):
        release_verification_release.validate_release_evidence(evidence)

    evidence = _valid_evidence()
    mutation = cast(
        dict[str, object],
        cast(dict[str, object], evidence["negative_boundaries"])["out_of_band_mutation"],
    )
    after = cast(dict[str, object], mutation["after"])
    after["spent_cents"] = 7_318
    with pytest.raises(
        release_verification_release.ReleaseVerificationReleaseError,
        match="not internally reconciled",
    ):
        release_verification_release.validate_release_evidence(evidence)


def test_release_evidence_binds_histories_and_e6_summary_to_audits() -> None:
    evidence = _valid_evidence()
    concurrent = cast(dict[str, object], evidence["adversarial"])["concurrent_addon"]
    governed = cast(dict[str, object], cast(dict[str, object], concurrent)["governed"])
    records = cast(list[dict[str, object]], governed["governance_records"])
    records.append({"status": "unbound"})
    with pytest.raises(
        release_verification_release.ReleaseVerificationReleaseError,
        match="one commit and one denial",
    ):
        release_verification_release.validate_release_evidence(evidence)

    evidence = _valid_evidence()
    concurrent = cast(dict[str, object], evidence["adversarial"])["concurrent_addon"]
    governed = cast(dict[str, object], cast(dict[str, object], concurrent)["governed"])
    records = cast(list[dict[str, object]], governed["governance_records"])
    committed = next(record for record in records if record["status"] == "committed")
    committed["decision"] = {
        "effect": "deny",
        "reason": "contradictory",
        "rule_id": "budget_cap",
    }
    with pytest.raises(
        release_verification_release.ReleaseVerificationReleaseError, match="terminal decision"
    ):
        release_verification_release.validate_release_evidence(evidence)

    evidence = _valid_evidence()
    wrong = cast(
        dict[str, object],
        cast(dict[str, object], evidence["negative_boundaries"])["wrong_but_authorized"],
    )
    record = cast(dict[str, object], wrong["governance_record"])
    record["decision"] = {
        "effect": "deny",
        "reason": "contradictory",
        "rule_id": "budget_cap",
    }
    with pytest.raises(
        release_verification_release.ReleaseVerificationReleaseError, match="terminal decision"
    ):
        release_verification_release.validate_release_evidence(evidence)

    evidence = _valid_evidence()
    wrong = cast(
        dict[str, object],
        cast(dict[str, object], evidence["negative_boundaries"])["wrong_but_authorized"],
    )
    record = cast(dict[str, object], wrong["governance_record"])
    effect = cast(dict[str, object], record["effect"])
    payload = cast(dict[str, object], effect["payload"])
    payload["budget_version"] = 999
    with pytest.raises(
        release_verification_release.ReleaseVerificationReleaseError, match="budget version"
    ):
        release_verification_release.validate_release_evidence(evidence)

    evidence = _valid_evidence()
    wrong = cast(
        dict[str, object],
        cast(dict[str, object], evidence["negative_boundaries"])["wrong_but_authorized"],
    )
    record = cast(dict[str, object], wrong["governance_record"])
    record["operation_id"] = "fabricated-operation"
    with pytest.raises(
        release_verification_release.ReleaseVerificationReleaseError,
        match="committed MasuGate audit",
    ):
        release_verification_release.validate_release_evidence(evidence)


def _concurrent_audit(evidence: dict[str, object], status: str) -> dict[str, object]:
    adversarial = cast(dict[str, object], evidence["adversarial"])
    concurrent = cast(dict[str, object], adversarial["concurrent_addon"])
    governed = cast(dict[str, object], concurrent["governed"])
    records = cast(list[dict[str, object]], governed["governance_records"])
    return next(record for record in records if record["status"] == status)


def _mutate_committed_external_identity(evidence: dict[str, object]) -> None:
    protected = cast(
        dict[str, object], _concurrent_audit(evidence, "committed")["protected_execution"]
    )
    protected["external_operation_id"] = None


def _mutate_committed_canonical_binding(evidence: dict[str, object]) -> None:
    protected = cast(
        dict[str, object], _concurrent_audit(evidence, "committed")["protected_execution"]
    )
    protected["binding_canonical_json"] = "{}"


def _mutate_committed_policy_identity(evidence: dict[str, object]) -> None:
    _concurrent_audit(evidence, "committed")["policy"] = {}


def _mutate_committed_entitlement(evidence: dict[str, object]) -> None:
    entitlement = cast(dict[str, object], _concurrent_audit(evidence, "committed")["entitlement"])
    entitlement["authorization_digest"] = "0" * 64


def _mutate_denied_available_value(evidence: dict[str, object]) -> None:
    reads = cast(list[dict[str, object]], _concurrent_audit(evidence, "denied")["view_reads"])
    reads[0]["value"] = 10_000


def _mutate_denied_serialization(evidence: dict[str, object]) -> None:
    terminal = cast(
        dict[str, object], _concurrent_audit(evidence, "denied")["terminal_serialization"]
    )
    terminal["kind"] = "effect-commit"


def _mutate_release_policy_anchor(evidence: dict[str, object]) -> None:
    release = cast(dict[str, object], evidence["release"])
    authorization = cast(dict[str, object], release["spend_authorization"])
    policy = cast(dict[str, object], authorization["policy"])
    policy["policy_digest"] = "0" * 64


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        (_mutate_committed_external_identity, "connector receipt"),
        (_mutate_committed_canonical_binding, "not canonical"),
        (_mutate_committed_policy_identity, "outer policy evidence"),
        (_mutate_committed_entitlement, "authorization digest"),
        (_mutate_denied_available_value, "policy-state read"),
        (_mutate_denied_serialization, "denial serialization"),
        (_mutate_release_policy_anchor, "policy anchor is inconsistent"),
    ],
)
def test_release_evidence_rejects_complete_audit_chain_mutants(mutation: Any, match: str) -> None:
    evidence = _valid_evidence()
    mutation(evidence)
    with pytest.raises(release_verification_release.ReleaseVerificationReleaseError, match=match):
        release_verification_release.validate_release_evidence(evidence)


def test_public_source_ci_runs_only_bounded_read_only_controls() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "name: Public source checks" in workflow
    assert "push:\n" in workflow
    assert "pull_request:" in workflow
    assert "python scripts/verify-release-controls.py" in workflow
    assert "python scripts/verify-documentation.py" in workflow
    assert "python scripts/build-reference-release.py --verify-only" in workflow
    assert "if: ${{ false }}" not in workflow
    assert "upload-artifact" not in workflow
    assert "npm publish" not in workflow


def test_release_verification_gateway_assets_and_adversarial_slice_are_packaged() -> None:
    dockerfile = (CONTAINMENT / "Dockerfile.reference_demo-gateway").read_text(encoding="utf-8")
    fixture = (CONTAINMENT / "gateway-model-fixture.mjs").read_text(encoding="utf-8")
    session = (CONTAINMENT / "gateway-release_verification-session.mjs").read_text(encoding="utf-8")
    entrypoint = (CONTAINMENT / "gateway-entrypoint.mjs").read_text(encoding="utf-8")
    adapter_package = (ROOT / "integrations" / "openclaw" / "package.json").read_text(
        encoding="utf-8"
    )
    containment_oracle = (ROOT / "scripts" / "run-reference-containment-live.py").read_text(
        encoding="utf-8"
    )
    slice_path = (
        ROOT
        / "src"
        / "masugate_openclaw_reference"
        / "release_verification_adversarial_slice.json"
    )
    assert "COPY containment/gateway-release_verification-session.mjs ./" in dockerfile
    assert (
        "cp ./masugate-plugin/openclaw.plugin.json "
        "./masugate-plugin/dist/src/openclaw.plugin.json"
        in ((CONTAINMENT / "Dockerfile.gateway").read_text(encoding="utf-8"))
    )
    assert "RELEASE_VERIFICATION_(ATTACK|GOVERNED|SAFE|DOWN)" in fixture
    assert "function contentText(value)" in fixture
    assert "text.matchAll(" in fixture
    assert ".toReversed()" in fixture
    assert "masugate_governed_action" in fixture
    assert "const release_verification = release_verificationCase(body);" in fixture
    assert "await serveReleaseVerification(body, res, release_verification);" in fixture
    assert "startGatewayRecoveryServer({ stateRoot, serveReleaseVerification })" in fixture
    assert "RELEASE_VERIFICATION_ATTACK_DENIED" in session
    assert "--attack-prompt-base64" in session
    assert "copyFileSync('openclaw.plugin.json','dist/src/openclaw.plugin.json')" in adapter_package
    assert "/opt/openclaw/masugate-plugin/dist/src/plugin.js" in entrypoint
    assert "/opt/openclaw/reference-safe-content-plugin/index.mjs" in entrypoint
    assert "MASUGATE_REFERENCE_DEMO_NETWORK_PREFIX" in entrypoint
    assert "sandbox.docker.network = `${reference_demoNetworkPrefix}-agent`" in entrypoint
    assert (
        "MASUGATE_REFERENCE_DEMO_NETWORK_PREFIX: ${MASUGATE_REFERENCE_DEMO_NETWORK_PREFIX:"
        in ((CONTAINMENT / "compose.reference_demo.yaml").read_text(encoding="utf-8"))
    )
    reference_demo_runner = (ROOT / "scripts" / "run_reference_demos.py").read_text(
        encoding="utf-8"
    )
    release_gate = RUNNER.read_text(encoding="utf-8")
    assert '(DOCKER, "network", "create", "--internal", network)' in reference_demo_runner
    assert "runner._create_dynamic_agent_network(project)" in release_gate
    assert "runner._remove_dynamic_agent_network(agent_network)" in release_gate
    assert 'project = f"masugate-release-verification-{run_identity}"' in release_gate
    assert '"logs",\n                "--tail",\n                "200"' in release_gate
    assert '_DOCKER_TEMP_ROOT = Path("/tmp")' in release_gate
    assert (
        'prefix="masugate-release_verification-artifacts-", dir=_DOCKER_TEMP_ROOT' in release_gate
    )
    assert 'prefix="masugate-reference_demo-state-"' in release_gate
    assert "dir=_DOCKER_TEMP_ROOT" in release_gate
    assert '"MASUGATE_REFERENCE_DEMO_ENV_FILE": str(' in release_gate
    assert 'artifact_context.parent / ".masugate-compose.env"' in release_gate
    assert "masugate-openclaw-reference-agent-sandbox:reference_containment" in containment_oracle
    assert release_verification_release.gateway_jailbreak_prompt_sha256(
        "agentdojo-over-budget"
    ) == ("db8ad9992c90eeabac317ce5763434e0fbc4d21212f82f5858fdffbe11649f97")
    assert json.loads(slice_path.read_text(encoding="utf-8"))["schema_version"] == (
        "masugate.release_verification-adversarial-slice/v1"
    )


@pytest.mark.release_verification_release_live
def test_release_verification_clean_artifact_reference_release_gate(tmp_path: Path) -> None:
    if not _docker_available():
        if os.environ.get("CI"):
            pytest.fail("Docker is mandatory for the release verification CI acceptance gate")
        pytest.skip("Docker is unavailable for the local release verification release gate")
    retained = os.environ.get("MASUGATE_RELEASE_VERIFICATION_EVIDENCE_DIR")
    output = Path(retained) if retained else tmp_path / "release_verification-release"
    if output.exists() and any(output.iterdir()):
        pytest.fail(f"release verification evidence output must be empty: {output}")
    offline_npm_cache = os.environ.get("MASUGATE_OFFLINE_NPM_CACHE")
    if not offline_npm_cache:
        pytest.fail("MASUGATE_OFFLINE_NPM_CACHE must name the reviewed hash-bound cache")
    command = [
        sys.executable,
        str(RUNNER),
        "--outdir",
        str(output),
        "--offline-npm-cache",
        offline_npm_cache,
    ]
    retained_release = os.environ.get("MASUGATE_RELEASE_VERIFICATION_RELEASE_DIR")
    if retained_release:
        command.extend(["--release-dir", retained_release])
    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=1800,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "release verification reference-release gate passed" in completed.stdout
    evidence = json.loads((output / "reference-release-evidence.json").read_text())
    release_verification_release.validate_release_evidence(evidence)
    assert evidence["adversarial"]["governed_attack_successes"] == 0
    assert evidence["negative_boundaries"]["out_of_band_mutation"]["detected"] is True
    assert evidence["availability"]["consequential_action"]["status"] == "blocked"
    assert evidence["availability"]["benign_action"]["status"] == "available"
