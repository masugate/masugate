"""reference demonstration clean-artifact Compose demo and procurement-evidence coverage."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import zipfile
from copy import deepcopy
from pathlib import Path
from typing import Any, cast

import pytest

from masugate.providers import ReferencePurchaseCredentialManifest
from masugate.pss import History, Operation, ScopeAccess, check_pss
from masugate_openclaw_reference import gateway_recovery_live
from masugate_openclaw_reference.procurement_workload import weak_request_time_baseline

ROOT = Path(__file__).parents[1]
CONTAINMENT = ROOT / "integrations" / "openclaw-reference" / "containment"
RUNNER = ROOT / "scripts" / "run_reference_demos.py"
RUNNER_ENTRYPOINT = ROOT / "scripts" / "run-reference-demos.py"
PREPARER = ROOT / "scripts" / "prepare-reference-demo.py"
DOCKER = os.environ.get("MASUGATE_DOCKER_BIN", "docker")


def _runner() -> Any:
    spec = importlib.util.spec_from_file_location("reference_demo_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _preparer() -> Any:
    spec = importlib.util.spec_from_file_location("reference_demo_preparer", PREPARER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _docker_available() -> bool:
    if shutil.which(DOCKER) is None and not Path(DOCKER).is_file():
        return False
    try:
        return subprocess.run([DOCKER, "info"], check=False, capture_output=True).returncode == 0
    except OSError:
        return False


def _release_descriptor_fixture(runner: Any) -> dict[str, object]:
    files = {
        "containment/compose.yaml": "1" * 64,
        "containment/compose.reference_demo.yaml": "2" * 64,
        "containment/gateway-entrypoint.mjs": "3" * 64,
    }
    return {
        "schema_version": runner._RELEASE_DESCRIPTOR_SCHEMA,
        "release_id": "masugate-openclaw-reference/0.1.1",
        "source_revision": "a" * 40,
        "staging_realization_revision": "b" * 40,
        "release_manifest_sha256": "4" * 64,
        "provenance_sha256": "5" * 64,
        "checksums_sha256": "6" * 64,
        "sbom_sha256": "7" * 64,
        "artifact_inventory_sha256": "8" * 64,
        "runtime_target": dict(runner._RUNTIME_TARGET),
        "spend_authorization": _spend_authorization_fixture(runner),
        "staged_compose": {
            "files": files,
            "bundle_sha256": runner._canonical_digest(files),
        },
    }


def _spend_authorization_fixture(runner: Any) -> dict[str, object]:
    manifest = json.loads(runner.RELEASE_MANIFEST.read_text(encoding="utf-8"))
    return cast(dict[str, object], runner._spend_authorization_anchor_from_manifest(manifest))


def _committed_audit_fixture(
    runner: Any,
    *,
    idempotency_key: str = "reference_demo-receipt",
    operation_id: str = "11111111-1111-4111-8111-111111111111",
) -> dict[str, object]:
    principal, arguments, authorization_basis = runner._EXPECTED_REQUESTS[idempotency_key]
    entitlement_id = "entitlement:reference_demo-fixture"
    trace_id = f"reference_demo:{idempotency_key}"
    anchor = _spend_authorization_fixture(runner)
    provenance = deepcopy(anchor["policy"])
    assert isinstance(provenance, dict)
    runtime_version = provenance["policy_runtime_version"]
    assert isinstance(runtime_version, str)
    evaluated_policies = [{"policy_id": "spend_budget_guard", "policy_version": runtime_version}]
    view_read = {
        "arguments": ["research"],
        "function": "spend.available_cents",
        "latency_ms": 0.25,
        "scope": "spend:team:research",
        "value": 10_000,
        "version": 0,
    }
    escalated = authorization_basis == "preserved-admission-evaluation"
    evaluated_at = "2026-07-21T12:00:00+00:00"
    resolved_at = "2026-07-21T12:00:00.500000+00:00"
    observed_at = "2026-07-21T12:00:00.750000+00:00"
    recorded_at = "2026-07-21T12:00:01+00:00"
    request = {
        "idempotency_key": idempotency_key,
        "adapter_invocation_digest": hashlib.sha256(
            f"masugate.openclaw:{idempotency_key}".encode()
        ).hexdigest(),
        "principal": {
            "attributes": deepcopy(runner._EXPECTED_PRINCIPAL_ATTRIBUTES[principal]),
            "id": principal,
        },
        "action": runner._ACTION,
        "args": arguments,
        "request_time": evaluated_at,
        "timestamp": evaluated_at,
        "trace_id": trace_id,
    }
    admission_decision = {
        "effect": "escalate" if escalated else "allow",
        "evaluated_policies": evaluated_policies,
        "policy_id": "spend_budget_guard",
        "policy_provenance": [provenance],
        "policy_version": runtime_version,
        "reads": [view_read],
        "reason": "rule ask_first evaluated to true" if escalated else "default rule",
        "rule_id": "ask_first" if escalated else "otherwise",
    }
    resolution_evidence = (
        None
        if not escalated
        else {
            "decision": "allow-once",
            "scenario": (
                "approval-replay"
                if idempotency_key == "reference_demo-revalidation"
                else "e2-procurement-race"
            ),
            "source": "reference-demo-demo",
        }
    )
    resolution = (
        None
        if resolution_evidence is None
        else {
            "actor_id": "operator",
            "approved": True,
            "evidence": resolution_evidence,
            "kind": "human",
            "resolved_at": resolved_at,
        }
    )
    configuration_digest = anchor["configuration_digest"]
    assert isinstance(configuration_digest, str)
    authorization_digest = runner._authorization_digest(
        request,
        admission_decision,
        budget_version=1,
        configuration_digest=configuration_digest,
        resolution=resolution,
    )
    binding: dict[str, object] = {
        "principal_id": principal,
        "action": runner._ACTION,
        "arguments": arguments,
        "idempotency_key": idempotency_key,
        "policies": [
            {
                "policy_id": provenance["policy_id"],
                "policy_version": provenance["policy_declared_version"],
                "policy_digest": provenance["policy_digest"],
                "bundle_id": provenance["bundle_id"],
                "bundle_version": provenance["bundle_version"],
                "bundle_digest": provenance["bundle_digest"],
            }
        ],
        "provider_identity": {
            "provider_id": runner._PROVIDER_ID,
            "implementation_version": runner._PROVIDER_IMPLEMENTATION,
            "configuration_version": configuration_digest,
        },
        "coordination_domain_id": "masugate.spend.reference.domain.v1",
        "scopes": ["spend:team:research"],
        "tool_call_id": trace_id,
        "connector_id": runner._CONNECTOR_ID,
        "entitlement_id": entitlement_id,
        "authorization_digest": authorization_digest,
    }
    canonical = json.dumps(binding, separators=(",", ":"), sort_keys=True)
    binding_digest = hashlib.sha256(canonical.encode()).hexdigest()
    external_operation_id = f"purchase:{binding_digest[:32]}"
    receipt_payload = {
        "amount_cents": arguments["amount_cents"],
        "merchant_id": arguments["merchant_id"],
    }
    receipt = {
        "connector_id": runner._CONNECTOR_ID,
        "evidence_id": f"purchase-evidence:{binding_digest[:32]}",
        "idempotency_key": f"masugate:{binding_digest}",
        "external_operation_id": external_operation_id,
        "observed_at": observed_at,
        "outcome": "succeeded",
        "payload": receipt_payload,
    }
    return {
        "operation_id": operation_id,
        "status": "committed",
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
            "entitlement_id": entitlement_id,
            "authorization_digest": authorization_digest,
        },
        "view_reads": [view_read],
        "authorization_evaluations": [
            {
                "certified_inputs": [],
                "decision": admission_decision,
                "evaluated_at": evaluated_at,
                "phase": "admission",
            }
        ],
        "decision": {
            "effect": "allow",
            "reason": "reference purchase committed with connector receipt",
            "rule_id": "approval.approved" if escalated else "otherwise",
        },
        "terminal_serialization": {
            "kind": "effect-commit",
            "authorization_basis": authorization_basis,
            "provider_atomic": False,
            "recorded_at": recorded_at,
            "evaluation_phase": "admission",
            "evaluation_at": evaluated_at,
        },
        "protected_execution": {
            "execution_id": f"px:{binding_digest}",
            "binding_digest": binding_digest,
            "binding": binding,
            "binding_canonical_json": canonical,
            "status": "succeeded",
            "entitlement_state": "consumed",
            "dispatch_started": True,
            "external_operation_id": external_operation_id,
            "last_fence_token": 1,
            "lease": None,
            "receipt": receipt,
            "result": receipt_payload,
        },
        "effect": {
            "action": runner._ACTION,
            "args": arguments,
            "payload": {
                **arguments,
                "authorization": runner._effect_authorization(admission_decision),
                "entitlement_id": entitlement_id,
                "authorization_digest": authorization_digest,
                "budget_version": 1,
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
        },
        "recorded_at": recorded_at,
        **(
            {}
            if resolution is None
            else {
                "human_resolution": {
                    "actor_id": "operator",
                    "approved": True,
                    "evidence": resolution_evidence,
                    "resolved_at": resolved_at,
                }
            }
        ),
    }


def _denied_audit_fixture(
    runner: Any,
    *,
    idempotency_key: str = "reference_demo-e2-beta",
    operation_id: str = "22222222-2222-4222-8222-222222222222",
) -> dict[str, object]:
    principal, arguments, _authorization_basis = runner._EXPECTED_REQUESTS[idempotency_key]
    anchor = _spend_authorization_fixture(runner)
    provenance = deepcopy(anchor["policy"])
    assert isinstance(provenance, dict)
    runtime_version = provenance["policy_runtime_version"]
    assert isinstance(runtime_version, str)
    evaluated_policies = [{"policy_id": "spend_budget_guard", "policy_version": runtime_version}]
    view_read = {
        "arguments": ["research"],
        "function": "spend.available_cents",
        "latency_ms": 0.25,
        "scope": "spend:team:research",
        "value": 4_000,
        "version": 1,
    }
    admission_decision = {
        "effect": "deny",
        "evaluated_policies": evaluated_policies,
        "policy_id": "spend_budget_guard",
        "policy_provenance": [provenance],
        "policy_version": runtime_version,
        "reads": [view_read],
        "reason": "rule budget_cap evaluated to true",
        "rule_id": "budget_cap",
    }
    evaluated_at = "2026-07-21T12:00:00+00:00"
    recorded_at = "2026-07-21T12:00:01+00:00"
    request = {
        "idempotency_key": idempotency_key,
        "adapter_invocation_digest": hashlib.sha256(
            f"masugate.openclaw:{idempotency_key}".encode()
        ).hexdigest(),
        "principal": {
            "attributes": deepcopy(runner._EXPECTED_PRINCIPAL_ATTRIBUTES[principal]),
            "id": principal,
        },
        "action": runner._ACTION,
        "args": arguments,
        "request_time": evaluated_at,
        "timestamp": evaluated_at,
        "trace_id": f"reference_demo:{idempotency_key}",
    }
    configuration_digest = anchor["configuration_digest"]
    assert isinstance(configuration_digest, str)
    authorization_digest = runner._authorization_digest(
        request,
        admission_decision,
        budget_version=1,
        configuration_digest=configuration_digest,
        resolution=None,
    )
    return {
        "operation_id": operation_id,
        "status": "denied",
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
            "entitlement_id": "entitlement:reference_demo-denied-fixture",
            "authorization_digest": authorization_digest,
        },
        "view_reads": [view_read],
        "authorization_evaluations": [
            {
                "certified_inputs": [],
                "decision": admission_decision,
                "evaluated_at": evaluated_at,
                "phase": "admission",
            }
        ],
        "decision": {
            "effect": "deny",
            "reason": "rule budget_cap evaluated to true",
            "rule_id": "budget_cap",
        },
        "terminal_serialization": {
            "authorization_basis": "admission-evaluation",
            "evaluation_at": evaluated_at,
            "evaluation_phase": "admission",
            "kind": "denial-record",
            "provider_atomic": False,
            "recorded_at": recorded_at,
        },
        "effect": None,
        "recorded_at": recorded_at,
    }


def _refresh_binding(audit: dict[str, object]) -> None:
    protected = audit["protected_execution"]
    assert isinstance(protected, dict)
    binding = protected["binding"]
    assert isinstance(binding, dict)
    canonical = json.dumps(binding, separators=(",", ":"), sort_keys=True)
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    protected["binding_canonical_json"] = canonical
    protected["binding_digest"] = digest
    protected["execution_id"] = f"px:{digest}"
    receipt = protected["receipt"]
    assert isinstance(receipt, dict)
    receipt["idempotency_key"] = f"masugate:{digest}"
    receipt["external_operation_id"] = f"purchase:{digest[:32]}"
    receipt["evidence_id"] = f"purchase-evidence:{digest[:32]}"
    protected["external_operation_id"] = f"purchase:{digest[:32]}"
    effect = audit["effect"]
    assert isinstance(effect, dict)
    payload = effect["payload"]
    assert isinstance(payload, dict)
    handoff = payload["handoff"]
    assert isinstance(handoff, dict)
    handoff["binding_digest"] = digest


def _refresh_authorization(audit: dict[str, object], runner: Any) -> None:
    request = audit["request"]
    assert isinstance(request, dict)
    evaluations = audit["authorization_evaluations"]
    assert isinstance(evaluations, list)
    evaluation = evaluations[0]
    assert isinstance(evaluation, dict)
    decision = evaluation["decision"]
    assert isinstance(decision, dict)
    entitlement = audit["entitlement"]
    assert isinstance(entitlement, dict)
    human = audit.get("human_resolution")
    resolution = None
    if human is not None:
        assert isinstance(human, dict)
        resolution = {**human, "kind": "human"}
    protected = audit["protected_execution"]
    assert isinstance(protected, dict)
    binding = protected["binding"]
    assert isinstance(binding, dict)
    provider = binding["provider_identity"]
    assert isinstance(provider, dict)
    configuration_digest = provider["configuration_version"]
    effect = audit["effect"]
    assert isinstance(effect, dict)
    payload = effect["payload"]
    assert isinstance(payload, dict)
    budget_version = payload["budget_version"]
    assert isinstance(configuration_digest, str)
    assert isinstance(budget_version, int)
    digest = runner._authorization_digest(
        request,
        decision,
        budget_version=budget_version,
        configuration_digest=configuration_digest,
        resolution=resolution,
    )
    entitlement["authorization_digest"] = digest
    binding["authorization_digest"] = digest
    payload["authorization_digest"] = digest
    _refresh_binding(audit)


def _governed_envelope_fixture(runner: Any) -> tuple[dict[str, object], dict[str, object]]:
    release = _release_descriptor_fixture(runner)
    operation_id = "11111111-1111-4111-8111-111111111111"
    audit = _committed_audit_fixture(
        runner,
        idempotency_key="reference_demo-e2-alpha",
        operation_id=operation_id,
    )
    evidence = {
        "schema_version": runner._EVIDENCE_SCHEMA,
        "scenario_id": "race",
        "started_ns": 1,
        "finished_ns": 10,
        "release": release,
        "evidence": {
            "scenario": "Race",
            "governed": {
                "kind": "governed-product-coordination",
                "assumptions": {
                    "budget_cents": 10_000,
                    "agents": 2,
                    "amount_cents_each": 6_000,
                    "coordination": (
                        "PostgreSQL spend entitlement/reservation plus protected runner"
                    ),
                    "artifact_boundary": (
                        "calls the running reference demonstration clean-artifact compose service"
                    ),
                },
                "committed_cents": 6_000,
                "budget_valid": True,
                "pss": {
                    "valid": True,
                    "reason": "fixture",
                    "decision_semantics_checked": True,
                },
                "initial_policy_state": [
                    {"scope": "spend:team:research", "version": 0, "value": 10_000}
                ],
                "terminal_statuses": ["committed", "denied"],
                "history": [
                    {
                        "operation_id": f"{operation_id}:reservation",
                        "causal_operation_id": operation_id,
                        "event_kind": "coordination-reservation",
                        "begin_ns": 1,
                        "terminal_ns": 3,
                        "committed": True,
                        "policy_reads": [
                            {"scope": "spend:team:research", "version": 0, "value": 10_000}
                        ],
                        "effect_reads": [],
                        "effect_writes": [
                            {"scope": "spend:team:research", "version": 1, "value": 4_000}
                        ],
                    },
                    {
                        "operation_id": "22222222-2222-4222-8222-222222222222",
                        "causal_operation_id": "22222222-2222-4222-8222-222222222222",
                        "event_kind": "terminal-denial",
                        "begin_ns": 1,
                        "terminal_ns": 4,
                        "committed": False,
                        "policy_reads": [
                            {"scope": "spend:team:research", "version": 1, "value": 4_000}
                        ],
                        "effect_reads": [],
                        "effect_writes": [],
                    },
                    {
                        "operation_id": f"{operation_id}:settlement",
                        "causal_operation_id": operation_id,
                        "event_kind": "terminal-settlement",
                        "begin_ns": 5,
                        "terminal_ns": 6,
                        "committed": True,
                        "policy_reads": [],
                        "effect_reads": [
                            {"scope": "spend:team:research", "version": 1, "value": 4_000}
                        ],
                        "effect_writes": [
                            {"scope": "spend:team:research", "version": 2, "value": 4_000}
                        ],
                    },
                ],
                "final_policy_state": {
                    "scope": "spend:team:research",
                    "version": 2,
                    "limit_cents": 10_000,
                    "spent_cents": 6_000,
                    "held_cents": 0,
                    "available_cents": 4_000,
                },
                "governance_records": [audit, _denied_audit_fixture(runner)],
            },
        },
    }
    payload = evidence["evidence"]
    assert isinstance(payload, dict)
    governed = payload["governed"]
    assert isinstance(governed, dict)
    history = runner._validate_history(
        governed["history"],
        "fixture.governed.history",
        kind="governed",
        initial_policy_state=governed["initial_policy_state"],
    )
    verdict = check_pss(
        history,
        decision_validator=runner.REFERENCE_SPEND_DECISION_VALIDATOR,
    )
    governed["pss"] = {
        "valid": verdict.pss,
        "reason": verdict.reason,
        "decision_semantics_checked": True,
    }
    return evidence, release


def test_e2_weak_request_time_baseline_overshoots_and_fails_pss() -> None:
    report = weak_request_time_baseline()

    assert report["kind"] == "deliberately-weak-request-time-baseline"
    assert report["committed_cents"] == 12_000
    assert report["overshoot_cents"] == 2_000
    assert report["stale_authorization"] is True
    assert report["initial_policy_state"] == [
        {"scope": "spend:team:research", "version": 0, "value": 10_000}
    ]
    assert report["pss"] == {
        "valid": False,
        "reason": "serialization cycle (RW -> RW) among weak-alpha -> weak-beta -> weak-alpha",
        "decision_semantics_checked": True,
    }
    history = report["history"]
    assert isinstance(history, list)
    assert [operation["operation_id"] for operation in history] == ["weak-alpha", "weak-beta"]
    assert all(operation["begin_ns"] > 0 for operation in history)
    assert all(operation["terminal_ns"] >= operation["begin_ns"] for operation in history)
    assert max(operation["begin_ns"] for operation in history) <= min(
        operation["terminal_ns"] for operation in history
    )
    assert all(
        operation["policy_reads"]
        == [{"scope": "spend:team:research", "version": 0, "value": 10_000}]
        for operation in history
    )
    assert {operation["effect_writes"][0]["version"] for operation in history} == {1, 2}
    assert {operation["effect_writes"][0]["value"] for operation in history} == {4_000, -2_000}
    assert all(operation["decision"] == "allow" for operation in history)
    ledger = report["effect_ledger"]
    assert isinstance(ledger, list)
    assert {row["operation_id"] for row in ledger} == {"weak-alpha", "weak-beta"}
    assert {row["budget_version"] for row in ledger} == {1, 2}
    assert all(row["amount_cents"] == 6_000 for row in ledger)
    replay = History(
        tuple(
            Operation(
                op_id=operation["operation_id"],
                begin_ns=operation["begin_ns"],
                commit_ns=operation["terminal_ns"],
                committed=operation["committed"],
                policy_reads=tuple(ScopeAccess(**read) for read in operation["policy_reads"]),
                effect_reads=tuple(ScopeAccess(**read) for read in operation["effect_reads"]),
                effect_writes=tuple(ScopeAccess(**write) for write in operation["effect_writes"]),
            )
            for operation in history
        )
    )
    assert check_pss(replay).pss is False
    ledger = report["effect_ledger"]
    assert isinstance(ledger, list)
    assert sum(effect["amount_cents"] for effect in ledger) == 12_000
    assert {effect["budget_version"] for effect in ledger} == {1, 2}


def test_committed_evidence_rejects_self_consistent_wrong_bindings() -> None:
    runner = _runner()
    valid = _committed_audit_fixture(runner)
    runner._validate_committed_record(
        valid,
        "receipt.record",
        scenario="receipt",
        spend_authorization=_spend_authorization_fixture(runner),
        expected_operation_id="11111111-1111-4111-8111-111111111111",
    )

    recovered = deepcopy(valid)
    recovered_protected = recovered["protected_execution"]
    assert isinstance(recovered_protected, dict)
    recovered_protected["last_fence_token"] = 2
    recovered_effect = recovered["effect"]
    assert isinstance(recovered_effect, dict)
    recovered_payload = recovered_effect["payload"]
    assert isinstance(recovered_payload, dict)
    recovered_payload_protected = recovered_payload["protected_execution"]
    assert isinstance(recovered_payload_protected, dict)
    recovered_payload_protected["fence_token"] = 2
    runner._validate_committed_record(
        recovered,
        "recovered-receipt.record",
        scenario="receipt",
        spend_authorization=_spend_authorization_fixture(runner),
        expected_operation_id="11111111-1111-4111-8111-111111111111",
    )

    mutants: list[dict[str, object]] = []

    wrong_fence = deepcopy(recovered)
    wrong_fence_effect = wrong_fence["effect"]
    assert isinstance(wrong_fence_effect, dict)
    wrong_fence_payload = wrong_fence_effect["payload"]
    assert isinstance(wrong_fence_payload, dict)
    wrong_fence_protected = wrong_fence_payload["protected_execution"]
    assert isinstance(wrong_fence_protected, dict)
    wrong_fence_protected["fence_token"] = 1
    mutants.append(wrong_fence)

    missing_terminal = deepcopy(valid)
    missing_terminal.pop("terminal_serialization")
    mutants.append(missing_terminal)

    wrong_principal = deepcopy(valid)
    protected = wrong_principal["protected_execution"]
    assert isinstance(protected, dict)
    binding = protected["binding"]
    assert isinstance(binding, dict)
    binding["principal_id"] = "wrong-principal"
    _refresh_binding(wrong_principal)
    mutants.append(wrong_principal)

    wrong_connector = deepcopy(valid)
    protected = wrong_connector["protected_execution"]
    assert isinstance(protected, dict)
    binding = protected["binding"]
    assert isinstance(binding, dict)
    binding["connector_id"] = "wrong-connector"
    receipt = protected["receipt"]
    assert isinstance(receipt, dict)
    receipt["connector_id"] = "wrong-connector"
    _refresh_binding(wrong_connector)
    mutants.append(wrong_connector)

    wrong_provider = deepcopy(valid)
    protected = wrong_provider["protected_execution"]
    assert isinstance(protected, dict)
    binding = protected["binding"]
    assert isinstance(binding, dict)
    provider = binding["provider_identity"]
    assert isinstance(provider, dict)
    provider["provider_id"] = "wrong-provider"
    _refresh_binding(wrong_provider)
    mutants.append(wrong_provider)

    wrong_authorization = deepcopy(valid)
    protected = wrong_authorization["protected_execution"]
    assert isinstance(protected, dict)
    binding = protected["binding"]
    assert isinstance(binding, dict)
    binding["authorization_digest"] = "e" * 64
    _refresh_binding(wrong_authorization)
    mutants.append(wrong_authorization)

    wrong_basis = deepcopy(valid)
    terminal = wrong_basis["terminal_serialization"]
    assert isinstance(terminal, dict)
    terminal["authorization_basis"] = "mechanism-denial"
    mutants.append(wrong_basis)

    wrong_external_operation = deepcopy(valid)
    protected = wrong_external_operation["protected_execution"]
    assert isinstance(protected, dict)
    receipt = protected["receipt"]
    assert isinstance(receipt, dict)
    receipt["external_operation_id"] = "purchase:other"
    mutants.append(wrong_external_operation)

    missing_binding_policy = deepcopy(valid)
    protected = missing_binding_policy["protected_execution"]
    assert isinstance(protected, dict)
    binding = protected["binding"]
    assert isinstance(binding, dict)
    binding["policies"] = []
    _refresh_binding(missing_binding_policy)
    mutants.append(missing_binding_policy)

    wrong_outer_policy = deepcopy(valid)
    policy = wrong_outer_policy["policy"]
    assert isinstance(policy, dict)
    policy["evaluated_policies"] = [{"policy_id": "spend_budget_guard", "policy_version": "f" * 16}]
    mutants.append(wrong_outer_policy)

    wrong_admission_policy = deepcopy(valid)
    evaluations = wrong_admission_policy["authorization_evaluations"]
    assert isinstance(evaluations, list)
    evaluation = evaluations[0]
    assert isinstance(evaluation, dict)
    decision = evaluation["decision"]
    assert isinstance(decision, dict)
    decision["evaluated_policies"] = [
        {"policy_id": "spend_budget_guard", "policy_version": "f" * 16}
    ]
    mutants.append(wrong_admission_policy)

    fabricated_read = deepcopy(valid)
    reads = fabricated_read["view_reads"]
    assert isinstance(reads, list)
    read = reads[0]
    assert isinstance(read, dict)
    read["value"] = 123
    read["version"] = 7
    effect = fabricated_read["effect"]
    assert isinstance(effect, dict)
    payload = effect["payload"]
    assert isinstance(payload, dict)
    authorization = payload["authorization"]
    assert isinstance(authorization, dict)
    authorization_reads = authorization["reads"]
    assert isinstance(authorization_reads, list)
    authorization_read = authorization_reads[0]
    assert isinstance(authorization_read, dict)
    authorization_read["value"] = 123
    authorization_read["version"] = 7
    mutants.append(fabricated_read)

    fabricated_provenance = deepcopy(valid)
    evaluations = fabricated_provenance["authorization_evaluations"]
    assert isinstance(evaluations, list)
    evaluation = evaluations[0]
    assert isinstance(evaluation, dict)
    decision = evaluation["decision"]
    assert isinstance(decision, dict)
    provenance = decision["policy_provenance"]
    assert isinstance(provenance, list)
    artifact = provenance[0]
    assert isinstance(artifact, dict)
    artifact["bundle_id"] = "fabricated.bundle"
    protected = fabricated_provenance["protected_execution"]
    assert isinstance(protected, dict)
    binding = protected["binding"]
    assert isinstance(binding, dict)
    binding_policies = binding["policies"]
    assert isinstance(binding_policies, list)
    binding_policy = binding_policies[0]
    assert isinstance(binding_policy, dict)
    binding_policy["bundle_id"] = "fabricated.bundle"
    _refresh_binding(fabricated_provenance)
    mutants.append(fabricated_provenance)

    fabricated_release_policy = deepcopy(valid)
    policy = fabricated_release_policy["policy"]
    assert isinstance(policy, dict)
    catalog = policy["catalog"]
    assert isinstance(catalog, dict)
    catalog["policy_digest"] = "f" * 64
    catalog["bundle_digest"] = "e" * 64
    evaluations = fabricated_release_policy["authorization_evaluations"]
    assert isinstance(evaluations, list)
    evaluation = evaluations[0]
    assert isinstance(evaluation, dict)
    decision = evaluation["decision"]
    assert isinstance(decision, dict)
    provenance = decision["policy_provenance"]
    assert isinstance(provenance, list)
    artifact = provenance[0]
    assert isinstance(artifact, dict)
    artifact["policy_digest"] = "f" * 64
    artifact["bundle_digest"] = "e" * 64
    artifact["policy_runtime_version"] = "f" * 16
    decision["policy_version"] = "f" * 16
    decision["evaluated_policies"] = [
        {"policy_id": "spend_budget_guard", "policy_version": "f" * 16}
    ]
    policy["policy_version"] = "f" * 16
    policy["evaluated_policies"] = decision["evaluated_policies"]
    protected = fabricated_release_policy["protected_execution"]
    assert isinstance(protected, dict)
    binding = protected["binding"]
    assert isinstance(binding, dict)
    binding_policies = binding["policies"]
    assert isinstance(binding_policies, list)
    binding_policy = binding_policies[0]
    assert isinstance(binding_policy, dict)
    binding_policy["policy_digest"] = "f" * 64
    binding_policy["bundle_digest"] = "e" * 64
    effect = fabricated_release_policy["effect"]
    assert isinstance(effect, dict)
    payload = effect["payload"]
    assert isinstance(payload, dict)
    authorization = payload["authorization"]
    assert isinstance(authorization, dict)
    authorization["policy_version"] = "f" * 16
    authorization["evaluated_policies"] = decision["evaluated_policies"]
    _refresh_authorization(fabricated_release_policy, runner)
    mutants.append(fabricated_release_policy)

    fabricated_configuration = deepcopy(valid)
    protected = fabricated_configuration["protected_execution"]
    assert isinstance(protected, dict)
    binding = protected["binding"]
    assert isinstance(binding, dict)
    provider = binding["provider_identity"]
    assert isinstance(provider, dict)
    provider["configuration_version"] = "f" * 64
    _refresh_authorization(fabricated_configuration, runner)
    mutants.append(fabricated_configuration)

    fabricated_budget_version = deepcopy(valid)
    effect = fabricated_budget_version["effect"]
    assert isinstance(effect, dict)
    payload = effect["payload"]
    assert isinstance(payload, dict)
    payload["budget_version"] = 999
    _refresh_authorization(fabricated_budget_version, runner)
    mutants.append(fabricated_budget_version)

    fabricated_receipt_payload = deepcopy(valid)
    protected = fabricated_receipt_payload["protected_execution"]
    assert isinstance(protected, dict)
    receipt = protected["receipt"]
    assert isinstance(receipt, dict)
    receipt["payload"] = {"amount_cents": 999_999, "merchant_id": "fabricated-merchant"}
    protected["result"] = dict(receipt["payload"])
    mutants.append(fabricated_receipt_payload)

    fabricated_principal_attributes = deepcopy(valid)
    request = fabricated_principal_attributes["request"]
    assert isinstance(request, dict)
    principal = request["principal"]
    assert isinstance(principal, dict)
    principal["attributes"] = {
        "masugate_require_adapter_invocation": True,
        "team": "executive",
    }
    mutants.append(fabricated_principal_attributes)

    missing_request_time = deepcopy(valid)
    request = missing_request_time["request"]
    assert isinstance(request, dict)
    request.pop("request_time")
    mutants.append(missing_request_time)

    for mutant in mutants:
        with pytest.raises(runner.DemoRunnerError):
            runner._validate_committed_record(
                mutant,
                "receipt.record",
                scenario="receipt",
                spend_authorization=_spend_authorization_fixture(runner),
                expected_operation_id="11111111-1111-4111-8111-111111111111",
            )

    missing_human_resolution = _committed_audit_fixture(
        runner,
        idempotency_key="reference_demo-revalidation",
    )
    missing_human_resolution.pop("human_resolution")
    with pytest.raises(runner.DemoRunnerError, match="human_resolution"):
        runner._validate_committed_record(
            missing_human_resolution,
            "approval.record",
            scenario="stale-approval",
            spend_authorization=_spend_authorization_fixture(runner),
        )

    receipt_before_approval = _committed_audit_fixture(
        runner,
        idempotency_key="reference_demo-revalidation",
    )
    protected = receipt_before_approval["protected_execution"]
    assert isinstance(protected, dict)
    receipt = protected["receipt"]
    assert isinstance(receipt, dict)
    request = receipt_before_approval["request"]
    assert isinstance(request, dict)
    receipt["observed_at"] = request["request_time"]
    with pytest.raises(runner.DemoRunnerError, match="predates human approval"):
        runner._validate_committed_record(
            receipt_before_approval,
            "approval.record",
            scenario="stale-approval",
            spend_authorization=_spend_authorization_fixture(runner),
        )


def test_governed_evidence_binds_terminal_state_and_release() -> None:
    runner = _runner()
    valid, release = _governed_envelope_fixture(runner)

    runner._validate_demo_evidence(
        valid,
        expected_release_descriptor=release,
    )

    semantic_value_drift = deepcopy(valid)
    payload = semantic_value_drift["evidence"]
    assert isinstance(payload, dict)
    governed = payload["governed"]
    assert isinstance(governed, dict)
    history = governed["history"]
    assert isinstance(history, list)
    denial = history[1]
    assert isinstance(denial, dict)
    reads = denial["policy_reads"]
    assert isinstance(reads, list)
    read = reads[0]
    assert isinstance(read, dict)
    read["value"] = 10_000
    with pytest.raises(runner.DemoRunnerError, match="governed history does not replay as PSS"):
        runner._validate_demo_evidence(
            semantic_value_drift,
            expected_release_descriptor=release,
        )

    status_only_denial = deepcopy(valid)
    payload = status_only_denial["evidence"]
    assert isinstance(payload, dict)
    governed = payload["governed"]
    assert isinstance(governed, dict)
    governed["governance_records"] = [
        governed["governance_records"][0],
        {"status": "denied"},
    ]
    with pytest.raises(runner.DemoRunnerError):
        runner._validate_demo_evidence(
            status_only_denial,
            expected_release_descriptor=release,
        )

    denied_history_identity_drift = deepcopy(valid)
    payload = denied_history_identity_drift["evidence"]
    assert isinstance(payload, dict)
    governed = payload["governed"]
    assert isinstance(governed, dict)
    history = governed["history"]
    assert isinstance(history, list)
    denial = history[1]
    assert isinstance(denial, dict)
    denial["operation_id"] = "33333333-3333-4333-8333-333333333333"
    denial["causal_operation_id"] = "33333333-3333-4333-8333-333333333333"
    with pytest.raises(runner.DemoRunnerError, match="operation identity"):
        runner._validate_demo_evidence(
            denied_history_identity_drift,
            expected_release_descriptor=release,
        )

    denied_read_drift = deepcopy(valid)
    payload = denied_read_drift["evidence"]
    assert isinstance(payload, dict)
    governed = payload["governed"]
    assert isinstance(governed, dict)
    records = governed["governance_records"]
    assert isinstance(records, list)
    denied_audit = records[1]
    assert isinstance(denied_audit, dict)
    reads = denied_audit["view_reads"]
    assert isinstance(reads, list)
    read = reads[0]
    assert isinstance(read, dict)
    read["version"] = 2
    with pytest.raises(runner.DemoRunnerError):
        runner._validate_demo_evidence(
            denied_read_drift,
            expected_release_descriptor=release,
        )

    committed_budget_drift = deepcopy(valid)
    payload = committed_budget_drift["evidence"]
    assert isinstance(payload, dict)
    governed = payload["governed"]
    assert isinstance(governed, dict)
    records = governed["governance_records"]
    assert isinstance(records, list)
    committed_audit = records[0]
    assert isinstance(committed_audit, dict)
    effect = committed_audit["effect"]
    assert isinstance(effect, dict)
    effect_payload = effect["payload"]
    assert isinstance(effect_payload, dict)
    effect_payload["budget_version"] = 2
    with pytest.raises(runner.DemoRunnerError, match="budget version"):
        runner._validate_demo_evidence(
            committed_budget_drift,
            expected_release_descriptor=release,
        )

    missing_settlement = deepcopy(valid)
    payload = missing_settlement["evidence"]
    assert isinstance(payload, dict)
    governed = payload["governed"]
    assert isinstance(governed, dict)
    history = governed["history"]
    assert isinstance(history, list)
    settlement = history[2]
    assert isinstance(settlement, dict)
    settlement["effect_writes"] = []
    with pytest.raises(runner.DemoRunnerError):
        runner._validate_demo_evidence(
            missing_settlement,
            expected_release_descriptor=release,
        )

    wrong_final_state = deepcopy(valid)
    payload = wrong_final_state["evidence"]
    assert isinstance(payload, dict)
    governed = payload["governed"]
    assert isinstance(governed, dict)
    final_state = governed["final_policy_state"]
    assert isinstance(final_state, dict)
    final_state["version"] = 1
    with pytest.raises(runner.DemoRunnerError, match="final policy state"):
        runner._validate_demo_evidence(
            wrong_final_state,
            expected_release_descriptor=release,
        )

    sequential_admissions = deepcopy(valid)
    payload = sequential_admissions["evidence"]
    assert isinstance(payload, dict)
    governed = payload["governed"]
    assert isinstance(governed, dict)
    history = governed["history"]
    assert isinstance(history, list)
    first = history[0]
    second = history[1]
    assert isinstance(first, dict)
    assert isinstance(second, dict)
    first.update({"begin_ns": 1, "terminal_ns": 2})
    second.update({"begin_ns": 3, "terminal_ns": 4})
    with pytest.raises(runner.DemoRunnerError, match="overlapping race windows"):
        runner._validate_demo_evidence(
            sequential_admissions,
            expected_release_descriptor=release,
        )

    early_settlement = deepcopy(valid)
    payload = early_settlement["evidence"]
    assert isinstance(payload, dict)
    governed = payload["governed"]
    assert isinstance(governed, dict)
    history = governed["history"]
    assert isinstance(history, list)
    settlement = history[2]
    assert isinstance(settlement, dict)
    settlement["begin_ns"] = 3
    with pytest.raises(runner.DemoRunnerError, match="before both governed admissions"):
        runner._validate_demo_evidence(
            early_settlement,
            expected_release_descriptor=release,
        )

    wrong_release = deepcopy(valid)
    embedded_release = wrong_release["release"]
    assert isinstance(embedded_release, dict)
    embedded_release["release_manifest_sha256"] = "f" * 64
    with pytest.raises(runner.DemoRunnerError, match="executed release"):
        runner._validate_demo_evidence(
            wrong_release,
            expected_release_descriptor=release,
        )


def test_approval_replay_requires_two_overlapping_resolution_attempts() -> None:
    runner = _runner()
    release = _release_descriptor_fixture(runner)
    operation_id = "11111111-1111-4111-8111-111111111111"
    envelope = {
        "schema_version": runner._EVIDENCE_SCHEMA,
        "scenario_id": "stale-approval",
        "started_ns": 1,
        "finished_ns": 10,
        "release": release,
        "evidence": {
            "scenario": "Approval Replay",
            "operation_id": operation_id,
            "resolution_attempts": [
                {
                    "begin_ns": 2,
                    "operation_id": operation_id,
                    "status": "committed",
                    "terminal_ns": 6,
                },
                {
                    "begin_ns": 3,
                    "operation_id": operation_id,
                    "status": "in_progress",
                    "terminal_ns": 7,
                },
            ],
            "governance_record": _committed_audit_fixture(
                runner,
                idempotency_key="reference_demo-revalidation",
                operation_id=operation_id,
            ),
        },
    }

    runner._validate_demo_evidence(envelope, expected_release_descriptor=release)

    missing_attempt = deepcopy(envelope)
    evidence = missing_attempt["evidence"]
    assert isinstance(evidence, dict)
    attempts = evidence["resolution_attempts"]
    assert isinstance(attempts, list)
    attempts.pop()
    with pytest.raises(runner.DemoRunnerError, match="two resolution attempts"):
        runner._validate_demo_evidence(missing_attempt, expected_release_descriptor=release)

    non_overlapping = deepcopy(envelope)
    evidence = non_overlapping["evidence"]
    assert isinstance(evidence, dict)
    attempts = evidence["resolution_attempts"]
    assert isinstance(attempts, list)
    second = attempts[1]
    assert isinstance(second, dict)
    second.update({"begin_ns": 7, "terminal_ns": 8})
    with pytest.raises(runner.DemoRunnerError, match="did not overlap"):
        runner._validate_demo_evidence(non_overlapping, expected_release_descriptor=release)


def test_procurement_evidence_binds_executable_ledger_totals_and_asymmetry() -> None:
    runner = _runner()
    envelope, release = _governed_envelope_fixture(runner)
    envelope["scenario_id"] = "procurement"
    evidence = envelope["evidence"]
    assert isinstance(evidence, dict)
    evidence["scenario"] = "E2 procurement workload"
    weak = weak_request_time_baseline()
    evidence["weak_baseline"] = weak
    governed = evidence["governed"]
    assert isinstance(governed, dict)
    evidence["measured_asymmetry"] = {
        "weak_committed_cents": weak["committed_cents"],
        "governed_committed_cents": governed["committed_cents"],
        "weak_overshoot_cents": weak["overshoot_cents"],
        "governed_pss_valid": governed["pss"],
    }

    runner._validate_demo_evidence(envelope, expected_release_descriptor=release)

    empty_ledger = deepcopy(envelope)
    payload = empty_ledger["evidence"]
    assert isinstance(payload, dict)
    weak_payload = payload["weak_baseline"]
    assert isinstance(weak_payload, dict)
    weak_payload["effect_ledger"] = []
    with pytest.raises(runner.DemoRunnerError, match="two effects"):
        runner._validate_demo_evidence(empty_ledger, expected_release_descriptor=release)

    fabricated_totals = deepcopy(envelope)
    payload = fabricated_totals["evidence"]
    assert isinstance(payload, dict)
    weak_payload = payload["weak_baseline"]
    assert isinstance(weak_payload, dict)
    weak_payload.update({"committed_cents": 0, "overshoot_cents": 1})
    with pytest.raises(runner.DemoRunnerError, match="totals"):
        runner._validate_demo_evidence(fabricated_totals, expected_release_descriptor=release)

    fabricated_asymmetry = deepcopy(envelope)
    payload = fabricated_asymmetry["evidence"]
    assert isinstance(payload, dict)
    payload["measured_asymmetry"] = {"fabricated": True}
    with pytest.raises(runner.DemoRunnerError, match="measured asymmetry"):
        runner._validate_demo_evidence(
            fabricated_asymmetry,
            expected_release_descriptor=release,
        )

    sequential_weak_history = deepcopy(envelope)
    payload = sequential_weak_history["evidence"]
    assert isinstance(payload, dict)
    weak_payload = payload["weak_baseline"]
    assert isinstance(weak_payload, dict)
    history = weak_payload["history"]
    assert isinstance(history, list)
    first = history[0]
    second = history[1]
    assert isinstance(first, dict)
    assert isinstance(second, dict)
    first.update({"begin_ns": 1, "terminal_ns": 2})
    second.update({"begin_ns": 3, "terminal_ns": 4})
    with pytest.raises(runner.DemoRunnerError, match="overlapping race windows"):
        runner._validate_demo_evidence(
            sequential_weak_history,
            expected_release_descriptor=release,
        )


def test_reference_demo_fleet_extension_is_explicit_and_manifest_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connector = "reference-containment-connector-token"
    alpha = "reference-containment-reference-token"
    beta = "reference-demo-beta-token"
    resolver = "gateway-recovery-resolver-token"
    manifest = ReferencePurchaseCredentialManifest.from_credentials(
        connector_service_token=connector,
        masugate_bearer_credentials=(alpha, beta, resolver),
    )
    monkeypatch.setenv("MASUGATE_REFERENCE_DEMO_DEMO", "1")
    monkeypatch.setenv("MASUGATE_BUYER_ALPHA_TOKEN", alpha)
    monkeypatch.setenv("MASUGATE_BUYER_BETA_TOKEN", beta)
    monkeypatch.setenv("MASUGATE_RESOLVER_TOKEN", resolver)
    monkeypatch.setenv("REFERENCE_PURCHASE_SERVICE_TOKEN", connector)
    monkeypatch.setenv(
        "MASUGATE_REFERENCE_CREDENTIAL_MANIFEST_JSON",
        json.dumps(
            {
                "connector_credential_fingerprint": manifest.connector_credential_fingerprint,
                "masugate_bearer_credential_fingerprints": list(
                    manifest.masugate_bearer_credential_fingerprints
                ),
            }
        ),
    )

    actual_alpha, actual_beta, actual_resolver, actual_connector, actual_manifest = (
        gateway_recovery_live._masugated_credentials()
    )

    assert (actual_alpha, actual_beta, actual_resolver, actual_connector) == (
        alpha,
        beta,
        resolver,
        connector,
    )
    assert actual_manifest == manifest


def test_reference_demo_compose_builds_only_from_clean_release_context() -> None:
    compose = (CONTAINMENT / "compose.reference_demo.yaml").read_text(encoding="utf-8")
    base_compose = (CONTAINMENT / "compose.yaml").read_text(encoding="utf-8")
    reference = (CONTAINMENT / "Dockerfile.reference_demo-reference").read_text(encoding="utf-8")
    gateway = (CONTAINMENT / "Dockerfile.reference_demo-gateway").read_text(encoding="utf-8")
    entrypoint = (CONTAINMENT / "gateway-entrypoint.mjs").read_text(encoding="utf-8")

    assert compose.count("${MASUGATE_REFERENCE_DEMO_ARTIFACT_CONTEXT") == 5
    assert compose.count("${MASUGATE_REFERENCE_DEMO_NETWORK_PREFIX") == 5
    assert "masugate-openclaw-reference-governance:" in compose
    assert "-governance" in compose
    assert 'MASUGATE_REFERENCE_DEMO_DEMO: "1"' in compose
    assert "MASUGATE_BUYER_BETA_TOKEN" in compose
    assert '"masugate_openclaw_reference.gateway_recovery_live", "masugated"' in compose
    assert '"masugate_openclaw_reference.gateway_recovery_live", "purchase"' in compose
    assert "ports:" not in compose
    assert "FROM python:3.12.11-slim-bookworm@sha256:" in reference
    assert "COPY src/" not in reference
    assert "artifacts/python/masugate/*.whl" in reference
    assert "artifacts/python/masugate-connector-sdk/*.whl" in reference
    assert "artifacts/python/masugate-client/*.whl" in reference
    assert "artifacts/python/reference/*.whl" in reference
    assert "--no-index" in reference
    assert "--require-hashes" in reference
    assert "artifacts/python/runtime/wheelhouse" in reference
    assert "FROM docker:27.5.1-cli-alpine3.21@sha256:" in gateway
    assert "apk add" not in gateway
    assert "FROM node:24.16.0-alpine@sha256:" in gateway
    assert "artifacts/npm/masugate-openclaw-*.tgz" in gateway
    assert "COPY integrations/" not in gateway
    assert "MASUGATE_REFERENCE_DEMO_DEMO" in entrypoint
    assert "MASUGATE_AGENT_SANDBOX_IMAGE" in entrypoint
    assert "MASUGATE_REFERENCE_DEMO_NETWORK_PREFIX" in entrypoint
    assert "sandbox.docker.image = sandboxImage" in entrypoint
    assert "sandbox.docker.network = `${reference_demoNetworkPrefix}-agent`" in entrypoint
    assert '"buyer-beta"' in entrypoint
    assert '"MASUGATE_REFERENCE_DEMO_NETWORK_PREFIX": project' in RUNNER.read_text(
        encoding="utf-8"
    )
    assert '"MASUGATE_AGENT_SANDBOX_IMAGE": sandbox_image' in RUNNER.read_text(encoding="utf-8")
    assert compose.count("platform: linux/amd64") == 7
    assert "image: ${MASUGATE_AGENT_SANDBOX_IMAGE:?" in compose
    assert (
        base_compose.count("masugate-openclaw-reference-agent-sandbox:reference_containment") == 2
    )
    assert compose.count("${MASUGATE_AGENT_SANDBOX_IMAGE:?") == 2
    assert RUNNER.read_text(encoding="utf-8").count('"--wait-timeout",') >= 3


def test_runner_stages_containment_assets_from_reference_wheel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _runner()
    release = tmp_path / "release"
    wheel_dir = release / "python" / "reference"
    wheel_dir.mkdir(parents=True)
    (release / "python" / "masugate").mkdir(parents=True)
    (release / "python" / "masugate-connector-sdk").mkdir(parents=True)
    (release / "python" / "masugate-client").mkdir(parents=True)
    runtime = release / "python" / "runtime"
    runtime.mkdir(parents=True)
    (runtime / "requirements.txt").write_text("fixture\n", encoding="utf-8")
    (runtime / "wheelhouse").mkdir()
    (release / "npm").mkdir(parents=True)
    contract = release / "deployment" / "openclaw-contract"
    contract.mkdir(parents=True)
    for name in ("package.json", "package-lock.json"):
        shutil.copy2(ROOT / "integrations" / "openclaw-contract" / name, contract / name)
    wheel = wheel_dir / "masugate_openclaw_reference-0.1.1-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for name in (
            "masugate_openclaw_reference/containment/Dockerfile.reference_demo-reference",
            "masugate_openclaw_reference/containment/Dockerfile.reference_demo-gateway",
            "masugate_openclaw_reference/containment/Dockerfile.reference_demo-safe-content",
            "masugate_openclaw_reference/containment/Dockerfile.reference_demo-agent-probe",
            "masugate_openclaw_reference/containment/compose.yaml",
            "masugate_openclaw_reference/containment/compose.reference_demo.yaml",
            "masugate_openclaw_reference/containment/gateway-entrypoint.mjs",
            "masugate_openclaw_reference/safe-content-plugin/index.mjs",
            "masugate_openclaw_reference/fleet-roster.example.json",
            "masugate_openclaw_reference/plugin-config.example.json",
            "masugate_openclaw_reference/plugin-config.native-approval.example.json",
        ):
            archive.writestr(name, name)

    offline_cache = tmp_path / "offline-cache"
    copied_cache_sources: list[Path] = []

    def fake_copy_offline_npm_cache(source: Path, artifacts: Path) -> None:
        copied_cache_sources.append(source)
        (artifacts / "offline" / "npm" / "cache").mkdir(parents=True)

    monkeypatch.setattr(runner, "_copy_offline_npm_cache", fake_copy_offline_npm_cache)

    context = runner._stage_artifact_context(
        release, tmp_path / "stage", offline_npm_cache=offline_cache
    )

    assert (context / "containment" / "Dockerfile.reference_demo-reference").is_file()
    assert (context / "containment" / "safe-content-plugin" / "index.mjs").is_file()
    assert (context / "containment" / "openclaw-contract" / "package-lock.json").is_file()
    assert (context / "reference-config" / "plugin-config.example.json").is_file()
    assert (context / "artifacts" / "python" / "reference" / wheel.name).is_file()
    assert (context / "artifacts" / "python" / "masugate-client").is_dir()
    assert (context / "artifacts" / "python" / "masugate-connector-sdk").is_dir()
    assert copied_cache_sources == [offline_cache]
    assert (context / "artifacts" / "offline" / "npm" / "cache").is_dir()


def test_runner_copies_only_a_validated_npm_cache_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _runner()
    payload = b"payload"
    integrity = "sha512-" + base64.b64encode(hashlib.sha512(payload).digest()).decode("ascii")
    url = "https://registry.npmjs.org/example/-/example-1.0.0.tgz"
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "fixture"},
                    "node_modules/example": {"resolved": url, "integrity": integrity},
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(runner, "_OFFLINE_NPM_LOCK", lock)
    cache_root = tmp_path / "cache-root"
    raw_cache = cache_root / "_cacache"
    content = runner._cache_content_path(raw_cache, integrity)
    content.parent.mkdir(parents=True)
    content.write_bytes(payload)
    key = runner._NPM_CACHE_KEY_PREFIX + url
    index = runner._cache_index_path(raw_cache, key)
    index.parent.mkdir(parents=True)
    encoded = json.dumps(
        {
            "key": key,
            "integrity": integrity,
            "time": 1,
            "size": len(payload),
            "metadata": {"url": url},
        },
        separators=(",", ":"),
    ).encode("utf-8")
    index.write_bytes(b"\n" + hashlib.sha1(encoded).hexdigest().encode("ascii") + b"\t" + encoded)

    artifacts = tmp_path / "artifacts"
    runner._copy_offline_npm_cache(cache_root, artifacts)
    copied = artifacts / "offline" / "npm" / "cache"
    assert copied.joinpath(content.relative_to(cache_root)).read_bytes() == payload
    assert copied.joinpath(index.relative_to(cache_root)).read_bytes() == index.read_bytes()

    (cache_root / "unexpected").mkdir()
    with pytest.raises(runner.DemoRunnerError, match="exactly one non-symlink _cacache"):
        runner._validate_offline_npm_cache(cache_root)

    unwrapped = tmp_path / "unwrapped-cache"
    (unwrapped / "content-v2").mkdir(parents=True)
    with pytest.raises(runner.DemoRunnerError, match="exactly one non-symlink _cacache"):
        runner._validate_offline_npm_cache(unwrapped)


def test_runner_handles_npm_platform_constraints() -> None:
    runner = _runner()

    assert runner._matches_npm_platform(None, "linux")
    assert runner._matches_npm_platform(["linux"], "linux")
    assert runner._matches_npm_platform(["!darwin", "!win32"], "linux")
    assert not runner._matches_npm_platform(["darwin"], "linux")
    assert not runner._matches_npm_platform(["!linux"], "linux")
    with pytest.raises(runner.DemoRunnerError, match="invalid platform metadata"):
        runner._matches_npm_platform("linux", "linux")


def _write_verified_release_fixture(
    release: Path,
    runner: Any,
    *,
    revision: str,
) -> None:
    artifact = release / "python" / "masugate" / "masugate-0.1.1.whl"
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b"verified artifact")
    deployment = release / "deployment"
    deployment.mkdir()
    shutil.copy2(runner.RELEASE_MANIFEST, deployment / "reference-release.json")
    artifacts = {
        path.relative_to(release).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(release.rglob("*"))
        if path.is_file()
    }
    (release / "checksums.sha256").write_text(
        "".join(f"{digest}  {path}\n" for path, digest in artifacts.items()),
        encoding="utf-8",
    )
    manifest = json.loads(runner.RELEASE_MANIFEST.read_text(encoding="utf-8"))
    (release / "provenance.json").write_text(
        json.dumps(
            {
                "schema_version": "masugate.reference-release.provenance/v1",
                "release_id": manifest["release_id"],
                "source_revision": revision,
                "source_date_epoch": 1_700_000_000,
                "staging_realization_revision": revision,
                "staging_realization_date_epoch": 1_700_000_000,
                "release_manifest_sha256": hashlib.sha256(
                    runner.RELEASE_MANIFEST.read_bytes()
                ).hexdigest(),
                "artifacts": [
                    {"path": path, "sha256": digest} for path, digest in artifacts.items()
                ],
            }
        ),
        encoding="utf-8",
    )
    (release / "sbom.cdx.json").write_text("{}", encoding="utf-8")


def test_reused_release_verification_closes_artifact_and_provenance_sets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner()
    release = tmp_path / "release"
    release.mkdir()
    revision = "a" * 40
    _write_verified_release_fixture(release, runner, revision=revision)
    monkeypatch.setattr(runner, "_run", lambda *_args, **_kwargs: "")

    descriptor = runner._verify_release_output(
        release,
        expected_source_revision=revision,
        expected_staging_realization_revision=revision,
    )
    assert descriptor["source_revision"] == revision
    assert descriptor["staging_realization_revision"] == revision
    assert descriptor["runtime_target"] == runner._RUNTIME_TARGET
    assert descriptor["artifact_inventory_sha256"]

    with pytest.raises(runner.DemoRunnerError, match="requested source revision"):
        runner._verify_release_output(
            release,
            expected_source_revision="different-revision",
            expected_staging_realization_revision=revision,
        )

    checksum_path = release / "checksums.sha256"
    valid_checksums = checksum_path.read_text(encoding="utf-8")
    checksum_path.write_text(f"{'0' * 64}  ../escape.whl\n", encoding="utf-8")
    with pytest.raises(runner.DemoRunnerError, match="unsafe artifact path"):
        runner._verify_release_output(
            release,
            expected_source_revision=revision,
            expected_staging_realization_revision=revision,
        )
    checksum_path.write_text(valid_checksums, encoding="utf-8")

    unchecked = release / "python" / "masugate" / "unchecked.whl"
    unchecked.write_bytes(b"not attested")
    with pytest.raises(runner.DemoRunnerError, match="do not match exactly"):
        runner._verify_release_output(
            release,
            expected_source_revision=revision,
            expected_staging_realization_revision=revision,
        )
    unchecked.unlink()

    (release / "provenance.json").write_text("not JSON", encoding="utf-8")
    with pytest.raises(runner.DemoRunnerError, match="not valid JSON"):
        runner._verify_release_output(
            release,
            expected_source_revision=revision,
            expected_staging_realization_revision=revision,
        )


def test_runner_clears_temporary_state_from_scoped_container(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner()
    state_root = tmp_path / "masugate-reference_demo-state-example"
    state_root.mkdir()
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def run(arguments: tuple[object, ...], **kwargs: object) -> str:
        calls.append((arguments, kwargs))
        return ""

    monkeypatch.setattr(runner, "_run", run)

    runner._clear_state_root_from_container(state_root)

    assert calls == [
        (
            (
                runner.DOCKER,
                "run",
                "--rm",
                "--network",
                "none",
                "--volume",
                f"{state_root}:/state:rw",
                runner._STATE_CLEANUP_IMAGE,
                "sh",
                "-ec",
                "rm -rf /state/* /state/.[!.]* /state/..?*",
            ),
            {"environment": dict(os.environ)},
        )
    ]


def test_reviewer_setup_allowlists_caller_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preparer = _preparer()
    dangerous = {
        "UV_EXTRA_INDEX_URL": "https://user:pass@example.invalid/simple",
        "PIP_EXTRA_INDEX_URL": "https://example.invalid/simple",
        "NPM_CONFIG_REGISTRY": "https://example.invalid/",
        "HTTP_PROXY": "http://user:pass@example.invalid:8080",
        "DOCKER_AUTH_CONFIG": '{"auths":{"example.invalid":{"auth":"secret"}}}',
        "NETRC": str(tmp_path / "netrc"),
        "GIT_ASKPASS": "/tmp/untrusted-askpass",
    }
    for key, value in dangerous.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("LANG", "C.UTF-8")

    environment = preparer._base_environment(tmp_path)

    for key, value in dangerous.items():
        assert environment.get(key) != value
    assert {
        "UV_EXTRA_INDEX_URL",
        "PIP_EXTRA_INDEX_URL",
        "HTTP_PROXY",
        "DOCKER_AUTH_CONFIG",
        "NETRC",
    }.isdisjoint(environment)
    assert environment["LANG"] == "C.UTF-8"
    assert environment["HOME"] == str(tmp_path / "empty-home")
    assert environment["DOCKER_CONFIG"] == str(tmp_path / "empty-docker-config")
    assert environment["PIP_CONFIG_FILE"] == "/dev/null"
    assert environment["UV_DEFAULT_INDEX"] == "https://pypi.org/simple"
    assert environment["NPM_CONFIG_REGISTRY"] == "https://registry.npmjs.org/"
    assert environment["NO_PROXY"] == environment["no_proxy"] == "*"


def test_runner_removes_only_sandboxes_for_its_unique_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner()
    image = "masugate-openclaw-reference-agent-sandbox:reference_demo-example"
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
    outputs = iter(("sandbox-one\nsandbox-two\n", "", ""))

    def run(arguments: tuple[object, ...], **kwargs: object) -> str:
        calls.append((arguments, kwargs))
        return next(outputs)

    monkeypatch.setattr(runner, "_run", run)
    monkeypatch.setattr(
        runner.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess((), 0),
    )

    runner._remove_sandbox_image(image)

    assert calls == [
        (
            (
                runner.DOCKER,
                "ps",
                "--all",
                "--quiet",
                "--filter",
                f"ancestor={image}",
            ),
            {"environment": dict(os.environ)},
        ),
        (
            (runner.DOCKER, "rm", "--force", "sandbox-one", "sandbox-two"),
            {"environment": dict(os.environ)},
        ),
        (
            (runner.DOCKER, "image", "rm", image),
            {"environment": dict(os.environ)},
        ),
    ]

    calls.clear()
    monkeypatch.setattr(
        runner.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess((), 1),
    )
    runner._remove_sandbox_image(image)
    assert calls == []


def test_runner_removes_only_its_unique_compose_service_images(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner()
    project = "masugate-reference-demo-race-0123456789ab"
    owned = (
        f"{project}-openclaw-gateway:latest",
        f"{project}-masugated:latest",
        f"{project}-reference-purchase:latest",
        f"{project}-safe-content:latest",
    )
    calls: list[tuple[object, ...]] = []
    listings = iter(("\n".join((*owned, "unrelated:latest")) + "\n", ""))

    def run(arguments: tuple[object, ...], **_kwargs: object) -> str:
        calls.append(arguments)
        if arguments[1:3] == ("image", "ls"):
            return next(listings)
        return ""

    monkeypatch.setattr(runner, "_run", run)
    runner._remove_compose_service_images(project, {"PATH": "/bin"})

    assert [call for call in calls if call[1:3] == ("image", "rm")] == [
        (runner.DOCKER, "image", "rm", image) for image in owned
    ]
    with pytest.raises(
        runner.DemoRunnerError, match="outside the reference demonstration namespace"
    ):
        runner._remove_compose_service_images("unrelated", {"PATH": "/bin"})


def test_runner_attempts_service_image_cleanup_when_compose_teardown_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner()
    project = "masugate-reference-demo-race-0123456789ab"
    calls: list[str] = []

    def compose(*_arguments: object) -> str:
        calls.append("down")
        raise runner.DemoRunnerError("simulated Compose teardown failure")

    def remove_images(*_arguments: object) -> None:
        calls.append("images")
        raise runner.DemoRunnerError("simulated image cleanup failure")

    monkeypatch.setattr(runner, "_compose", compose)
    monkeypatch.setattr(runner, "_remove_compose_service_images", remove_images)

    with pytest.raises(ExceptionGroup) as raised:
        runner._cleanup_compose_project(project, {"PATH": "/bin"}, remove_local_images=True)

    assert calls == ["down", "images"]
    assert {str(error) for error in raised.value.exceptions} == {
        "simulated Compose teardown failure",
        "simulated image cleanup failure",
    }


def test_runner_owns_only_its_dynamic_agent_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner()
    project = "masugate-release-verification-example"
    network = f"{project}-agent"
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def run(arguments: tuple[object, ...], **kwargs: object) -> str:
        calls.append((arguments, kwargs))
        return ""

    monkeypatch.setattr(runner, "_run", run)
    monkeypatch.setattr(
        runner.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess((), 0),
    )

    assert runner._create_dynamic_agent_network(project) == network
    runner._remove_dynamic_agent_network(network)

    assert calls == [
        (
            (runner.DOCKER, "network", "create", "--internal", network),
            {"environment": dict(os.environ)},
        ),
        (
            (runner.DOCKER, "network", "rm", network),
            {"environment": dict(os.environ)},
        ),
    ]
    with pytest.raises(
        runner.DemoRunnerError, match=r"outside the reference demonstration namespace"
    ):
        runner._create_dynamic_agent_network("unrelated-project")


def test_runner_rejects_incompatible_docker_architecture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner()
    monkeypatch.setattr(runner, "_run", lambda *_args, **_kwargs: "aarch64\n")

    with pytest.raises(runner.DemoRunnerError, match="linux/amd64"):
        runner._verify_docker_runtime()


def test_runner_cleans_state_after_partial_compose_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner()
    state_root = tmp_path / "masugate-reference_demo-state-example"
    state_root.mkdir()
    compose_calls: list[tuple[object, ...]] = []
    cleanup_calls: list[Path] = []
    removed_images: list[str] = []
    removed_service_images: list[str] = []
    created_networks: list[str] = []
    removed_networks: list[str] = []

    def compose(*arguments: object) -> str:
        compose_calls.append(arguments)
        if "up" in arguments:
            raise runner.DemoRunnerError("simulated partial Compose start")
        return ""

    def create_dynamic_agent_network(project: str) -> str:
        created_networks.append(project)
        return f"{project}-agent"

    monkeypatch.setattr(runner, "_compose", compose)
    monkeypatch.setattr(
        runner,
        "_clear_state_root_from_container",
        lambda state: cleanup_calls.append(state),
    )
    monkeypatch.setattr(
        runner,
        "_remove_sandbox_image",
        lambda image: removed_images.append(image),
    )
    monkeypatch.setattr(
        runner,
        "_remove_compose_service_images",
        lambda project, _environment: removed_service_images.append(project),
    )
    monkeypatch.setattr(
        runner,
        "_create_dynamic_agent_network",
        create_dynamic_agent_network,
    )
    monkeypatch.setattr(
        runner,
        "_remove_dynamic_agent_network",
        lambda network: removed_networks.append(network),
    )

    for _ in range(2):
        with pytest.raises(runner.DemoRunnerError, match="simulated partial Compose start"):
            runner._run_one(
                "race",
                artifact_context=tmp_path / "artifact-context",
                release_descriptor={"source_revision": "a" * 40},
                state_root=state_root,
                keep_stack=False,
            )

    assert sum("down" in call for call in compose_calls) == 4
    assert sum(call[-1] == "openclaw-gateway" for call in compose_calls) == 2
    assert cleanup_calls == [state_root, state_root]
    assert len(removed_images) == 2
    assert len(set(removed_images)) == 2
    assert len(created_networks) == 2
    assert removed_service_images == [str(call[0]) for call in compose_calls if call[2] == "down"]
    assert removed_networks == [f"{project}-agent" for project in created_networks]
    assert len({str(call[0]) for call in compose_calls}) == 2
    assert {
        str(call[1]["MASUGATE_AGENT_SANDBOX_IMAGE"])
        for call in compose_calls
        if isinstance(call[1], dict)
    } == set(removed_images)
    assert all(
        image.startswith("masugate-openclaw-reference-agent-sandbox:reference_demo-aaaaaaaaaaaa-")
        for image in removed_images
    )


@pytest.mark.reference_demo_demo_live
def test_reference_demo_headless_clean_artifact_all_scenarios(tmp_path: Path) -> None:
    if not _docker_available():
        if os.environ.get("CI"):
            pytest.fail("Docker is mandatory for the reference demonstration CI acceptance gate")
        pytest.skip("Docker is unavailable for the local reference demonstration live demo")
    offline_npm_cache = os.environ.get("MASUGATE_OFFLINE_NPM_CACHE")
    if not offline_npm_cache:
        pytest.fail("MASUGATE_OFFLINE_NPM_CACHE must name the reviewed hash-bound cache")
    command = [
        sys.executable,
        str(RUNNER_ENTRYPOINT),
        "all",
        "--outdir",
        str(tmp_path / "evidence"),
        "--offline-npm-cache",
        offline_npm_cache,
    ]
    source_revision = os.environ.get("MASUGATE_SOURCE_REVISION")
    source_epoch = os.environ.get("MASUGATE_SOURCE_DATE_EPOCH")
    if (source_revision is None) != (source_epoch is None):
        pytest.fail("MASUGATE_SOURCE_REVISION and MASUGATE_SOURCE_DATE_EPOCH must be paired")
    if source_revision is not None and source_epoch is not None:
        command.extend(["--source-revision", source_revision, "--source-date-epoch", source_epoch])
    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=1800,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    runner_scenarios = (
        "race",
        "stale-approval",
        "blast-radius",
        "receipt",
        "recovery",
        "procurement",
    )
    for scenario in runner_scenarios:
        evidence = json.loads((tmp_path / "evidence" / "evidence" / f"{scenario}.json").read_text())
        assert evidence["schema_version"] == "masugate.reference_demo-demo-evidence/v3"
        assert evidence["scenario_id"] == scenario
        assert evidence["finished_ns"] >= evidence["started_ns"] > 0
        assert evidence["release"]["source_revision"]
        assert evidence["release"]["staged_compose"]["bundle_sha256"]
        payload = evidence["evidence"]
        if scenario in {"race", "procurement"}:
            assert payload["governed"]["budget_valid"] is True
            assert payload["governed"]["pss"]["valid"] is True
            assert sorted(payload["governed"]["terminal_statuses"]) == [
                "committed",
                "denied",
            ]
            assert any(operation["effect_writes"] for operation in payload["governed"]["history"])
            assert [operation["event_kind"] for operation in payload["governed"]["history"]] == [
                "coordination-reservation",
                "terminal-denial",
                "terminal-settlement",
            ]
            assert payload["governed"]["final_policy_state"]["version"] == 2
            if scenario == "procurement":
                assert payload["weak_baseline"]["overshoot_cents"] == 2_000
                assert payload["weak_baseline"]["pss"]["valid"] is False
        elif scenario in {"receipt", "stale-approval", "blast-radius"}:
            record = payload["governance_record"]
            assert record["status"] == "committed"
            assert record["view_reads"]
            assert record["policy"]["evaluated_policies"]
            assert record["protected_execution"]["binding"]["principal_id"]
            assert record["protected_execution"]["receipt"]["outcome"] == "succeeded"
            assert record["terminal_serialization"]["kind"] == "effect-commit"
            if scenario == "stale-approval":
                attempts = payload["resolution_attempts"]
                assert len(attempts) == 2
                assert {attempt["operation_id"] for attempt in attempts} == {
                    payload["operation_id"]
                }
                assert max(attempt["begin_ns"] for attempt in attempts) <= min(
                    attempt["terminal_ns"] for attempt in attempts
                )
            if scenario == "blast-radius":
                assert payload["blocked_impersonation_status"] == 401
        else:
            assert payload["external_effect_count"] == 1
            assert payload["accounting"] == {"spent_cents": 400, "held_cents": 0}
            assert payload["governance_record"]["status"] == "committed"
    assert len(runner_scenarios) == 6
