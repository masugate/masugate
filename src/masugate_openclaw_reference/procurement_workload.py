"""Deterministic reference demonstration procurement evidence workload.

The weak side is intentionally *not* a MasuGate implementation.  It models the
common request-time-only pattern: two agents read the same remaining budget,
then both commit after a barrier.  The governed side calls the running MasuGate
reference deployment over its public deployment API and captures the returned
audit reads as a PSS history.  Keeping the two paths in one small program
makes the asymmetry inspectable without pretending that the weak baseline is a
product component.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import threading
import time
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import cast

import httpx
import psycopg
from masugate_client import canonical_adapter_envelope, create_adapter_invocation

from masugate.pss import History, Operation, ScopeAccess, check_pss

_MASUGATED_URL = "http://127.0.0.1:8000"
_ALPHA_TOKEN = "reference-containment-reference-token"
_BETA_TOKEN = "reference-demo-beta-token"
_RESOLVER_TOKEN = "gateway-recovery-resolver-token"
_OWNER_HEADERS = {
    "MasuGate-Expected-Provider": "masugate.spend.reference",
    "MasuGate-Expected-Position": "protected-external",
    "MasuGate-Expected-Connector": "reference-purchase-v1",
}
_BUDGET_CENTS = 10_000
_RACE_AMOUNT_CENTS = 6_000


class DemoError(RuntimeError):
    """A bounded demo did not establish the result it advertises."""


@dataclass(frozen=True)
class _TimedResult:
    result: dict[str, object]
    begin_ns: int
    terminal_ns: int


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise DemoError(f"{label} must be an object")
    return cast(dict[str, object], value)


def _list(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise DemoError(f"{label} must be a list")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise DemoError(f"{label} must be a non-empty string")
    return value


def _int(value: object, label: str) -> int:
    if type(value) is not int:
        raise DemoError(f"{label} must be an integer")
    return value


def _owner_headers(principal: str, token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "MasuGate-Expected-Principal": principal,
        **_OWNER_HEADERS,
    }


def _action_payload(
    *,
    principal: str,
    key: str,
    amount_cents: int,
    request_ref: str,
) -> dict[str, object]:
    args = {
        "amount_cents": amount_cents,
        "merchant_id": "reference-demo-procurement",
        "request_ref": request_ref,
    }
    return {
        "action": "spend.purchase",
        "args": args,
        "idempotency_key": key,
        "trace_id": f"reference_demo:{key}",
        "adapter_invocation": canonical_adapter_envelope(
            create_adapter_invocation(
                {
                    "principal": {"id": principal},
                    "source": {"namespace": "openclaw", "id": f"reference_demo:{key}"},
                    "adapter": {
                        "id": "masugate.openclaw",
                        "contract_version": "masugate.host-adapter.v1",
                        "capabilities": ["locator", "pending-presentation"],
                    },
                    "action": {"name": "spend.purchase", "arguments": args},
                }
            )
        ),
    }


async def _request(
    client: httpx.AsyncClient,
    *,
    principal: str,
    token: str,
    key: str,
    amount_cents: int,
    request_ref: str,
) -> dict[str, object]:
    response = await client.post(
        "/v1/actions",
        headers=_owner_headers(principal, token),
        json=_action_payload(
            principal=principal,
            key=key,
            amount_cents=amount_cents,
            request_ref=request_ref,
        ),
    )
    if response.status_code != 200:
        raise DemoError(f"governed action {key} failed: {response.status_code} {response.text}")
    return _mapping(response.json(), f"governed action {key} response")


async def _timed_request(
    client: httpx.AsyncClient,
    *,
    principal: str,
    token: str,
    key: str,
    amount_cents: int,
    request_ref: str,
) -> _TimedResult:
    begin_ns = time.monotonic_ns()
    result = await _request(
        client,
        principal=principal,
        token=token,
        key=key,
        amount_cents=amount_cents,
        request_ref=request_ref,
    )
    return _TimedResult(result=result, begin_ns=begin_ns, terminal_ns=time.monotonic_ns())


async def _resolve(
    client: httpx.AsyncClient,
    pending: Mapping[str, object],
    *,
    scenario: str,
) -> dict[str, object]:
    pending_id = _string(pending.get("pending_id"), "pending_id")
    response = await client.post(
        f"/v1/pending/{pending_id}/resolve",
        headers={"Authorization": f"Bearer {_RESOLVER_TOKEN}"},
        json={
            "approved": True,
            "evidence": {
                "source": "reference-demo-demo",
                "scenario": scenario,
                "decision": "allow-once",
            },
        },
    )
    if response.status_code != 200:
        raise DemoError(f"resolution {pending_id} failed: {response.status_code} {response.text}")
    return _mapping(response.json(), f"resolution {pending_id} response")


async def _timed_resolve(
    client: httpx.AsyncClient,
    pending: Mapping[str, object],
    *,
    scenario: str,
) -> _TimedResult:
    begin_ns = time.monotonic_ns()
    result = await _resolve(client, pending, scenario=scenario)
    return _TimedResult(result=result, begin_ns=begin_ns, terminal_ns=time.monotonic_ns())


async def _audit(
    client: httpx.AsyncClient,
    result: Mapping[str, object],
) -> dict[str, object]:
    operation_id = _string(result.get("operation_id"), "operation_id")
    response = await client.get(
        f"/v1/audit/{operation_id}",
        headers={"Authorization": f"Bearer {_RESOLVER_TOKEN}"},
    )
    if response.status_code != 200:
        raise DemoError(f"audit {operation_id} failed: {response.status_code} {response.text}")
    return _mapping(response.json(), f"audit {operation_id}")


def _policy_reads(audit: Mapping[str, object]) -> tuple[ScopeAccess, ...]:
    reads = _list(audit.get("view_reads"), "audit view_reads")
    return tuple(
        ScopeAccess(
            scope=_string(_mapping(read, "audit view_read").get("scope"), "view_read scope"),
            version=_int(_mapping(read, "audit view_read").get("version"), "view_read version"),
        )
        for read in reads
    )


def _terminal_history_operation(
    audit: Mapping[str, object],
    *,
    begin_ns: int,
    terminal_ns: int,
) -> Operation:
    operation_id = _string(audit.get("operation_id"), "audit operation_id")
    policy_reads = _policy_reads(audit)
    committed = audit.get("status") == "committed"
    effect_writes: tuple[ScopeAccess, ...] = ()
    if committed:
        effect = _mapping(audit.get("effect"), "committed audit effect")
        payload = _mapping(effect.get("payload"), "committed audit effect payload")
        produced_version = _int(payload.get("budget_version"), "committed budget_version")
        scopes = {read.scope for read in policy_reads if read.scope.startswith("spend:")}
        if len(scopes) != 1:
            raise DemoError("committed procurement audit must identify one spend scope")
        effect_writes = (ScopeAccess(scope=scopes.pop(), version=produced_version),)
    if begin_ns <= 0 or terminal_ns < begin_ns:
        raise DemoError("governed history contains invalid observed event timestamps")
    return Operation(
        op_id=operation_id,
        begin_ns=begin_ns,
        commit_ns=terminal_ns,
        committed=committed,
        policy_reads=policy_reads,
        effect_writes=effect_writes,
    )


def _history_payload(
    history: History,
    *,
    event_kinds: Mapping[str, str] | None = None,
    causal_operation_ids: Mapping[str, str] | None = None,
) -> list[dict[str, object]]:
    return [
        {
            "operation_id": operation.op_id,
            "causal_operation_id": (
                causal_operation_ids.get(operation.op_id, operation.op_id)
                if causal_operation_ids is not None
                else operation.op_id
            ),
            "event_kind": (
                event_kinds.get(operation.op_id, "terminal-effect")
                if event_kinds is not None
                else "terminal-effect"
            ),
            "begin_ns": operation.begin_ns,
            "terminal_ns": operation.commit_ns,
            "committed": operation.committed,
            "policy_reads": [
                {"scope": read.scope, "version": read.version} for read in operation.policy_reads
            ],
            "effect_reads": [
                {"scope": read.scope, "version": read.version} for read in operation.effect_reads
            ],
            "effect_writes": [
                {"scope": write.scope, "version": write.version}
                for write in operation.effect_writes
            ],
        }
        for operation in history.operations
    ]


def _budget_snapshot(team_id: str) -> dict[str, object]:
    """Read the authoritative terminal provider state for the evidence witness."""

    dsn = os.environ.get("MASUGATE_POSTGRES_DSN")
    if not dsn:
        raise DemoError("governed procurement requires MASUGATE_POSTGRES_DSN")
    with psycopg.connect(dsn) as connection:
        row = connection.execute(
            """
            SELECT limit_cents, spent_cents, held_cents, version
            FROM spend_budgets WHERE team_id = %s
            """,
            (team_id,),
        ).fetchone()
    if row is None:
        raise DemoError("governed procurement has no authoritative budget state")
    limit_cents, spent_cents, held_cents, version = (int(value) for value in row)
    return {
        "scope": f"spend:team:{team_id}",
        "version": version,
        "limit_cents": limit_cents,
        "spent_cents": spent_cents,
        "held_cents": held_cents,
        "available_cents": limit_cents - spent_cents - held_cents,
    }


def weak_request_time_baseline() -> dict[str, object]:
    """Execute a deliberately broken request-time-only procurement race."""

    scope = "spend:team:research"
    barrier = threading.Barrier(2)
    state_lock = threading.Lock()
    committed_cents = 0
    budget_version = 0
    effects: list[dict[str, object]] = []

    def execute(principal: str) -> Operation:
        nonlocal budget_version, committed_cents
        begin_ns = time.monotonic_ns()
        with state_lock:
            observed_version = budget_version
            observed_available = _BUDGET_CENTS - committed_cents
        if observed_available < _RACE_AMOUNT_CENTS:
            raise DemoError("weak race did not observe enough request-time budget")
        try:
            barrier.wait(timeout=5)
        except threading.BrokenBarrierError as exc:
            raise DemoError("weak request-time race barrier did not release") from exc
        with state_lock:
            # This is the deliberately weak action: it commits using the stale
            # request-time authorization without rechecking the shared budget.
            committed_cents += _RACE_AMOUNT_CENTS
            budget_version += 1
            produced_version = budget_version
            effects.append(
                {
                    "operation_id": principal,
                    "amount_cents": _RACE_AMOUNT_CENTS,
                    "budget_version": produced_version,
                }
            )
        return Operation(
            op_id=principal,
            begin_ns=begin_ns,
            commit_ns=time.monotonic_ns(),
            committed=True,
            policy_reads=(ScopeAccess(scope=scope, version=observed_version),),
            effect_writes=(ScopeAccess(scope=scope, version=produced_version),),
        )

    with ThreadPoolExecutor(
        max_workers=2, thread_name_prefix="masugate-reference_demo-weak"
    ) as pool:
        operations = tuple(pool.map(execute, ("weak-alpha", "weak-beta")))
    history = History(operations=operations)
    verdict = check_pss(history)
    if verdict.pss:
        raise AssertionError(
            "the intentionally stale request-time baseline unexpectedly passed PSS"
        )
    if committed_cents != 2 * _RACE_AMOUNT_CENTS or budget_version != 2:
        raise DemoError("weak executable baseline did not commit both stale authorizations")
    return {
        "kind": "deliberately-weak-request-time-baseline",
        "assumptions": {
            "budget_cents": _BUDGET_CENTS,
            "agents": 2,
            "amount_cents_each": _RACE_AMOUNT_CENTS,
            "interleaving": "both requests read remaining budget version 0 before either effect",
            "coordination": "none after the request-time read",
        },
        "committed_cents": committed_cents,
        "overshoot_cents": committed_cents - _BUDGET_CENTS,
        "stale_authorization": True,
        "effect_ledger": effects,
        "pss": {"valid": verdict.pss, "reason": verdict.reason},
        "history": _history_payload(history),
    }


async def governed_procurement_workload() -> dict[str, object]:
    """Drive two approval-required procurements through real product coordination."""

    async with httpx.AsyncClient(base_url=_MASUGATED_URL, timeout=30) as client:
        initial = await asyncio.gather(
            _timed_request(
                client,
                principal="openclaw:buyer-alpha",
                token=_ALPHA_TOKEN,
                key="reference_demo-e2-alpha",
                amount_cents=_RACE_AMOUNT_CENTS,
                request_ref="reference_demo-e2-alpha",
            ),
            _timed_request(
                client,
                principal="openclaw:buyer-beta",
                token=_BETA_TOKEN,
                key="reference_demo-e2-beta",
                amount_cents=_RACE_AMOUNT_CENTS,
                request_ref="reference_demo-e2-beta",
            ),
        )
        pending = [event for event in initial if event.result.get("status") == "pending"]
        denied = [event for event in initial if event.result.get("status") == "denied"]
        # The governed product reserves capacity at admission.  Two 6,000-cent
        # holds cannot coexist under the 10,000-cent budget, so the concurrent
        # request race must yield exactly one durable approval and one durable
        # capacity denial *before* either external effect is eligible.
        if len(pending) != 1 or len(denied) != 1:
            raise DemoError(
                "governed admission did not converge to one approval and one capacity denial: "
                f"{initial!r}"
            )
        resolution = await _timed_resolve(
            client,
            pending[0].result,
            scenario="e2-procurement-race",
        )
        if resolution.result.get("status") != "committed":
            raise DemoError(
                "governed approval did not produce one committed effect: " f"{resolution.result!r}"
            )
        terminal = [resolution.result, denied[0].result]
        committed = [resolution.result]
        audits = await asyncio.gather(*(_audit(client, result) for result in terminal))

    committed_operation_id = _string(audits[0].get("operation_id"), "committed operation_id")
    committed_reads = _policy_reads(audits[0])
    spend_scopes = {read.scope for read in committed_reads if read.scope.startswith("spend:")}
    if len(spend_scopes) != 1:
        raise DemoError("committed procurement audit must identify one spend scope")
    scope = spend_scopes.pop()
    effect = _mapping(audits[0].get("effect"), "committed audit effect")
    payload = _mapping(effect.get("payload"), "committed audit effect payload")
    reservation_version = _int(payload.get("budget_version"), "reservation budget_version")
    final_policy_state = _budget_snapshot("research")
    if final_policy_state.get("scope") != scope:
        raise DemoError("terminal budget snapshot names the wrong policy-state scope")
    terminal_version = _int(final_policy_state.get("version"), "terminal budget version")
    if terminal_version != reservation_version + 1:
        raise DemoError(
            "terminal budget state does not follow the durable reservation: "
            f"reservation={reservation_version}, terminal={terminal_version}"
        )
    reservation_id = f"{committed_operation_id}:reservation"
    settlement_id = f"{committed_operation_id}:settlement"
    reservation = Operation(
        op_id=reservation_id,
        begin_ns=pending[0].begin_ns,
        commit_ns=pending[0].terminal_ns,
        committed=True,
        policy_reads=committed_reads,
        effect_writes=(ScopeAccess(scope=scope, version=reservation_version),),
    )
    denial = _terminal_history_operation(
        audits[1],
        begin_ns=denied[0].begin_ns,
        terminal_ns=denied[0].terminal_ns,
    )
    settlement = Operation(
        op_id=settlement_id,
        begin_ns=resolution.begin_ns,
        commit_ns=resolution.terminal_ns,
        committed=True,
        effect_reads=(ScopeAccess(scope=scope, version=reservation_version),),
        effect_writes=(ScopeAccess(scope=scope, version=terminal_version),),
    )
    history = History((reservation, denial, settlement))
    event_kinds = {
        reservation_id: "coordination-reservation",
        denial.op_id: "terminal-denial",
        settlement_id: "terminal-settlement",
    }
    causal_operation_ids = {
        reservation_id: committed_operation_id,
        denial.op_id: denial.op_id,
        settlement_id: committed_operation_id,
    }
    if final_policy_state != {
        "scope": scope,
        "version": terminal_version,
        "limit_cents": _BUDGET_CENTS,
        "spent_cents": _RACE_AMOUNT_CENTS,
        "held_cents": 0,
        "available_cents": _BUDGET_CENTS - _RACE_AMOUNT_CENTS,
    }:
        raise DemoError(
            f"governed procurement terminal budget state is invalid: {final_policy_state!r}"
        )
    if (
        max(
            write.version
            for operation in history.operations
            for write in operation.effect_writes
            if write.scope == scope
        )
        != terminal_version
    ):
        raise DemoError("governed procurement history omits the terminal budget write")
    verdict = check_pss(history)
    if not verdict.pss:
        raise DemoError(f"governed procurement history failed PSS: {verdict.reason}")
    committed_cents = sum(
        _int(_mapping(result.get("payload"), "terminal payload").get("amount_cents"), "amount")
        for result in committed
    )
    if committed_cents > _BUDGET_CENTS:
        raise DemoError("governed procurement committed more than the fixed budget")
    return {
        "kind": "governed-product-coordination",
        "assumptions": {
            "budget_cents": _BUDGET_CENTS,
            "agents": 2,
            "amount_cents_each": _RACE_AMOUNT_CENTS,
            "coordination": "PostgreSQL spend entitlement/reservation plus protected runner",
            "artifact_boundary": (
                "calls the running reference demonstration clean-artifact compose service"
            ),
        },
        "committed_cents": committed_cents,
        "budget_valid": committed_cents <= _BUDGET_CENTS,
        "terminal_statuses": [cast(str, result["status"]) for result in terminal],
        "pss": {"valid": verdict.pss, "reason": verdict.reason},
        "history": _history_payload(
            history,
            event_kinds=event_kinds,
            causal_operation_ids=causal_operation_ids,
        ),
        "final_policy_state": final_policy_state,
        "governance_records": audits,
    }


async def run_named_demo(name: str) -> dict[str, object]:
    """Run a named service-level scenario and return only inspectable evidence."""

    if name in {"race", "procurement"}:
        strong = await governed_procurement_workload()
        if name == "race":
            return {
                "scenario": "Race",
                "guarantee": "two overlapping purchases remain within one reserved budget",
                "governed": strong,
            }
        weak = weak_request_time_baseline()
        return {
            "scenario": "E2 procurement workload",
            "weak_baseline": weak,
            "governed": strong,
            "measured_asymmetry": {
                "weak_committed_cents": weak["committed_cents"],
                "governed_committed_cents": strong["committed_cents"],
                "weak_overshoot_cents": weak["overshoot_cents"],
                "governed_pss_valid": strong["pss"],
            },
        }

    async with httpx.AsyncClient(base_url=_MASUGATED_URL, timeout=30) as client:
        if name == "recovery-request":
            # The host runner kills this request at the deployment's durable
            # after-provider hook.  A normal return would be a test failure:
            # it means the crash did not interrupt the post-effect boundary.
            return await _request(
                client,
                principal="openclaw:buyer-alpha",
                token=_ALPHA_TOKEN,
                key="reference_demo-recovery",
                amount_cents=400,
                request_ref="reference_demo-recovery",
            )

        if name == "receipt":
            result = await _request(
                client,
                principal="openclaw:buyer-alpha",
                token=_ALPHA_TOKEN,
                key="reference_demo-receipt",
                amount_cents=400,
                request_ref="reference_demo-receipt",
            )
            if result.get("status") != "committed":
                raise DemoError(f"receipt action did not commit: {result!r}")
            audit = await _audit(client, result)
            return {
                "scenario": "Receipt",
                "guarantee": "the receipt binds policy reads, owner, and protected effect evidence",
                "operation_id": _string(result.get("operation_id"), "receipt operation_id"),
                "governance_record": audit,
            }

        if name == "stale-approval":
            pending = await _request(
                client,
                principal="openclaw:buyer-alpha",
                token=_ALPHA_TOKEN,
                key="reference_demo-revalidation",
                amount_cents=_RACE_AMOUNT_CENTS,
                request_ref="reference_demo-revalidation",
            )
            if pending.get("status") != "pending":
                raise DemoError("approval-replay scenario did not create a pending record")
            resolution_events = await asyncio.gather(
                *(_timed_resolve(client, pending, scenario="approval-replay") for _ in range(2))
            )
            resolutions = [event.result for event in resolution_events]
            if any(
                result.get("status") not in {"committed", "in_progress"} for result in resolutions
            ):
                raise DemoError(
                    f"duplicate approval did not settle the pending record: {resolutions!r}"
                )
            operation_ids = {
                _string(result.get("operation_id"), "approval-replay operation_id")
                for result in resolutions
            }
            if len(operation_ids) != 1:
                raise DemoError("duplicate approval resolution produced multiple operations")
            deadline = time.monotonic() + 30
            replay_audit: dict[str, object] | None = None
            while time.monotonic() < deadline:
                replay_audit = await _audit(client, resolutions[0])
                if replay_audit.get("status") == "committed":
                    break
                await asyncio.sleep(0.1)
            if replay_audit is None or replay_audit.get("status") != "committed":
                raise DemoError("duplicate approval did not settle to one committed operation")
            protected = _mapping(
                replay_audit.get("protected_execution"), "approval-replay protected record"
            )
            receipt = _mapping(protected.get("receipt"), "approval-replay connector receipt")
            if receipt.get("outcome") != "succeeded":
                raise DemoError("approval replay did not retain the committed connector receipt")
            return {
                "scenario": "Approval Replay",
                "guarantee": (
                    "duplicate approval resolutions converge on one durable operation and receipt"
                ),
                "operation_id": next(iter(operation_ids)),
                "resolution_attempts": [
                    {
                        "begin_ns": event.begin_ns,
                        "operation_id": _string(
                            event.result.get("operation_id"), "approval-replay operation_id"
                        ),
                        "status": _string(
                            event.result.get("status"), "approval-replay resolution status"
                        ),
                        "terminal_ns": event.terminal_ns,
                    }
                    for event in resolution_events
                ],
                "governance_record": replay_audit,
            }

        if name == "blast-radius":
            blocked = await client.post(
                "/v1/actions",
                headers=_owner_headers("openclaw:buyer-alpha", _BETA_TOKEN),
                json=_action_payload(
                    principal="openclaw:buyer-alpha",
                    key="reference_demo-blast-impersonation",
                    amount_cents=400,
                    request_ref="reference_demo-blast-impersonation",
                ),
            )
            if blocked.status_code != 401:
                raise DemoError(
                    "buyer credential impersonated another fleet identity: " f"{blocked.text}"
                )
            result = await _request(
                client,
                principal="openclaw:buyer-beta",
                token=_BETA_TOKEN,
                key="reference_demo-blast-beta",
                amount_cents=400,
                request_ref="reference_demo-blast-beta",
            )
            if result.get("status") != "committed":
                raise DemoError(f"bounded beta action did not commit: {result!r}")
            return {
                "scenario": "Blast Radius",
                "guarantee": "one fleet credential cannot impersonate another principal",
                "blocked_impersonation_status": blocked.status_code,
                "operation_id": _string(result.get("operation_id"), "blast operation_id"),
                "governance_record": await _audit(client, result),
            }

    raise DemoError(f"unknown reference demonstration scenario: {name}")


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "scenario",
        choices=(
            "race",
            "stale-approval",
            "blast-radius",
            "receipt",
            "procurement",
            "recovery-request",
        ),
    )
    arguments = parser.parse_args(argv)
    started_ns = time.time_ns()
    evidence = asyncio.run(run_named_demo(arguments.scenario))
    print(
        json.dumps(
            {"started_ns": started_ns, "finished_ns": time.time_ns(), "evidence": evidence},
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    try:
        main()
    except (DemoError, httpx.HTTPError) as exc:
        raise SystemExit(f"reference demonstration demo failed: {exc}") from exc
