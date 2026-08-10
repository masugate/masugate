"""Runnable reference calendar profile through the connector worker connector worker.

This deployment composition is deliberately separate from the generic MasuGate
package.  It owns a reference calendar connector and authenticated host
boundary, while the calendar provider remains the durable PostgreSQL policy
state and the worker is the only code that can invoke the connector.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, cast
from uuid import NAMESPACE_URL, uuid4, uuid5

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse
from masugate_connector_sdk import SDK_CONTRACT_VERSION, SecretHandle
from masugate_operation_calendar import operation_pack
from masugate_operation_calendar.reference import (
    ReferenceCalendarConnector,
    ReferenceCalendarState,
)

from masugate.contracts import ContractRegistry, GovernanceViewContract, ResourceSession
from masugate.errors import ContractError
from masugate.language.compiler import PolicyCompiler
from masugate.language.parser import parse_policy
from masugate.language.serialize import dumps
from masugate.model import (
    ActionRequest,
    CertificationPhase,
    DecisionEffect,
    Duration,
    JsonValue,
    PolicyDecision,
    Principal,
    Scalar,
    TypeName,
)
from masugate.operations import (
    ConnectorHandoff,
    ConnectorWorker,
    ConnectorWorkerDeployment,
    canonical_operation_pack,
    compile_operation_pack,
    load_deployment_binding,
)
from masugate.operations.artifacts import SqliteArtifactStore
from masugate.operations.compiler import provider_identity_digests
from masugate.operations.worker import SqliteConnectorHandoffStore
from masugate.policy import AsyncPolicyRuntime, PolicySet
from masugate.protected_execution import (
    PolicyBinding,
    PostgresProtectedExecutionStore,
    ProtectedExecutionAuthority,
    ProtectedExecutionBinding,
    ProtectedExecutionRecord,
    ProtectedExecutionStatus,
    ProtectedExecutionStore,
)
from masugate.masugated.app import ActionBody, ResolveBody, _adapter_invocation_digest
from masugate.provider_assembly import CoordinationDomain, EffectExecutionPosition
from masugate.providers.calendar import CalendarError, CalendarPolicy, CalendarProvider
from masugate.resources.postgres import AsyncPostgresLedger

_CREATE = "calendar.event.create"
_CANCEL = "calendar.event.cancel"
_CONNECTOR_ID = "calendar-reference-v1"
_BUNDLE_DIGEST = hashlib.sha256(b"masugate-calendar-reference-bundle-v1").hexdigest()
_CONFIGURATION_DIGEST = hashlib.sha256(b"masugate-calendar-reference-connector-v1").hexdigest()

_REFERENCE_POLICIES = (
    """
    policy calendar_reference_create on calendar.event.create {
      deny blocked_principal when principal.team == "blocked";
      escalate long_event_review when
        calendar.requires_review(args.start_at, args.end_at, args.timezone);
      allow otherwise;
    }
    """,
    """
    policy calendar_reference_cancel on calendar.event.cancel {
      deny blocked_principal when principal.team == "blocked";
      allow otherwise;
    }
    """,
)


class CalendarReferenceUnauthorized(Exception):
    """The caller is not one of this profile's configured host identities."""


class _NoSecrets:
    """The reference connector has no credentials; any request is a deployment error."""

    def resolve(self, reference: str) -> SecretHandle:
        raise ValueError(f"reference calendar has no credential {reference!r}")


@dataclass(frozen=True)
class CalendarActionResult:
    """The exact governed lifecycle state returned to an authenticated host."""

    request: ActionRequest
    decision: PolicyDecision
    record: ProtectedExecutionRecord | None = None
    pending_id: str | None = None
    replayed: bool = False


_PENDING_TABLE = "calendar_reference_pending"
_PENDING_CLAIM_SECONDS = 30


@dataclass(frozen=True)
class _CalendarPending:
    request: ActionRequest
    admission: dict[str, JsonValue]
    state: str
    resolution: dict[str, JsonValue] | None
    resolver_id: str | None
    approved: bool | None
    evidence: dict[str, JsonValue] | None
    execution_id: str | None
    claim_token: str | None
    claim_expires_at: datetime | None


def _policy_runtime(provider: CalendarProvider) -> AsyncPolicyRuntime:
    """Compile the reference policy over the provider's real protected effects."""

    registry = ContractRegistry()
    for binding in provider.provider_module().effects:
        registry.register_effect(binding.contract)

    async def requires_review(
        _session: ResourceSession, arguments: tuple[Scalar | Duration, ...], _scope: str
    ) -> tuple[bool, int]:
        if len(arguments) != 3 or any(type(value) is not str for value in arguments):
            raise CalendarError("calendar review view received invalid request arguments")
        try:
            start = datetime.fromisoformat(cast(str, arguments[0]).replace("Z", "+00:00"))
            end = datetime.fromisoformat(cast(str, arguments[1]).replace("Z", "+00:00"))
        except ValueError as exc:
            raise CalendarError("calendar review view needs RFC3339 timestamps") from exc
        if start.tzinfo is None or end.tzinfo is None:
            raise CalendarError("calendar review view needs offset-aware timestamps")
        return (end - start).total_seconds() > 60 * 60, 0

    registry.register_view(
        GovernanceViewContract(
            name="calendar.requires_review",
            argument_types=(TypeName.STRING, TypeName.STRING, TypeName.STRING),
            return_type=TypeName.BOOL,
            owner="calendar",
            consistency="calendar-policy-state",
            max_latency_ms=100,
            bounded=True,
            scope_resolver=lambda _arguments: provider.scope,
            resolver=requires_review,
            provider_identity=provider.policy.provider_identity,
        )
    )
    policies = PolicySet()
    compiler = PolicyCompiler(registry, principal_attributes={"team": TypeName.STRING})
    for source in _REFERENCE_POLICIES:
        policies.add(compiler.compile(parse_policy(source)))
    return AsyncPolicyRuntime(registry, policies)


def _policy_digest(policy_id: str) -> str:
    for source in _REFERENCE_POLICIES:
        definition = parse_policy(source)
        if definition.name == policy_id:
            return hashlib.sha256(dumps(definition).encode("utf-8")).hexdigest()
    raise CalendarError("calendar decision does not name an installed policy")


@dataclass
class CalendarReferenceResource:
    """One durable calendar provider with two exact worker-owned actions."""

    provider: CalendarProvider
    ledger: AsyncPostgresLedger
    workers: Mapping[str, ConnectorWorker]
    principals: Mapping[str, Mapping[str, Scalar]]
    token_principals: Mapping[str, str]
    operator_principals: frozenset[str] = frozenset()
    recovery_interval_seconds: float = 1.0
    _principals: dict[str, dict[str, Scalar]] = field(init=False, repr=False)
    _tokens: dict[str, str] = field(init=False, repr=False)
    _workers: dict[str, ConnectorWorker] = field(init=False, repr=False)
    _runtime: AsyncPolicyRuntime = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if set(self.workers) != {_CREATE, _CANCEL}:
            raise ValueError("calendar reference needs create and cancel workers")
        if type(self.recovery_interval_seconds) not in {int, float} or not (
            0 < self.recovery_interval_seconds <= 60
        ):
            raise ValueError("calendar recovery interval must be between zero and sixty seconds")
        self._workers = dict(self.workers)
        self._principals = {
            principal: dict(attributes) for principal, attributes in self.principals.items()
        }
        if not self._principals:
            raise ValueError("calendar reference needs at least one principal")
        self._tokens = {}
        for token, principal in self.token_principals.items():
            if not token or token.strip() != token or principal not in self._principals:
                raise ValueError("calendar reference token mapping is malformed")
            self._tokens[token] = principal
        if not self.operator_principals.issubset(self._principals):
            raise ValueError("calendar operators must be configured principals")
        self._runtime = _policy_runtime(self.provider)

    @property
    def owner(self) -> dict[str, str]:
        return {
            "provider_id": self.provider.policy.provider_identity.provider_id,
            "position": EffectExecutionPosition.PROTECTED_EXTERNAL.value,
            "connector_id": self.provider.policy.connector_id,
        }

    async def initialize(self) -> None:
        await self.ledger.open()
        await self.provider.initialize()
        await self._initialize_pending_store()
        for worker in self._workers.values():
            await worker.initialize()
        await self.recover()

    async def close(self) -> None:
        await self.ledger.close()

    async def _initialize_pending_store(self) -> None:
        """Create the shared pending lifecycle table inside the policy database."""

        async with self.ledger.open_session(write=True) as session:
            await session.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {_PENDING_TABLE} (
                    pending_id TEXT PRIMARY KEY,
                    request_digest TEXT NOT NULL UNIQUE,
                    operation_id TEXT NOT NULL UNIQUE,
                    request_json TEXT NOT NULL,
                    admission_decision_json TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('pending', 'resolving', 'resolved')),
                    resolution_decision_json TEXT,
                    resolver_id TEXT,
                    resolution_approved BOOLEAN,
                    evidence_json TEXT,
                    execution_id TEXT,
                    claim_token TEXT,
                    claim_expires_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL,
                    resolved_at TIMESTAMPTZ,
                    CHECK (
                        (state = 'resolving') =
                        (claim_token IS NOT NULL AND claim_expires_at IS NOT NULL)
                    )
                )
                """
            )
            await session.execute(
                f"CREATE INDEX IF NOT EXISTS idx_{_PENDING_TABLE}_claim "
                f"ON {_PENDING_TABLE}(state, claim_expires_at)"
            )

    @staticmethod
    def _canonical_json(value: Mapping[str, JsonValue]) -> str:
        return json.dumps(dict(value), ensure_ascii=True, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _decision_payload(decision: PolicyDecision) -> dict[str, JsonValue]:
        return {
            "effect": decision.effect.value,
            "policy_id": decision.policy_id,
            "policy_version": decision.policy_version,
            "rule_id": decision.rule_id,
            "reason": decision.reason,
            "evaluated_policies": [
                {"policy_id": policy_id, "policy_version": policy_version}
                for policy_id, policy_version in decision.evaluated_policies
            ],
        }

    @staticmethod
    def _decision_from_payload(payload: Mapping[str, JsonValue]) -> PolicyDecision:
        try:
            evaluated = tuple(
                (
                    cast(str, item["policy_id"]),
                    cast(str, item["policy_version"]),
                )
                for item in cast(list[dict[str, JsonValue]], payload["evaluated_policies"])
            )
            return PolicyDecision(
                effect=DecisionEffect(cast(str, payload["effect"])),
                policy_id=cast(str, payload["policy_id"]),
                policy_version=cast(str, payload["policy_version"]),
                rule_id=cast(str, payload["rule_id"]),
                reason=cast(str, payload["reason"]),
                evaluated_policies=evaluated,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise CalendarError("calendar pending decision is malformed") from exc

    @staticmethod
    def _request_payload(request: ActionRequest) -> dict[str, JsonValue]:
        return {
            "action": request.action,
            "adapter_invocation_digest": request.adapter_invocation_digest,
            "arguments": dict(request.arguments),
            "idempotency_key": request.idempotency_key,
            "operation_id": request.operation_id,
            "principal": {
                "attributes": dict(request.principal.attributes),
                "id": request.principal.id,
            },
        }

    @staticmethod
    def _request_from_payload(payload: Mapping[str, JsonValue]) -> ActionRequest:
        try:
            principal_payload = cast(dict[str, JsonValue], payload["principal"])
            attributes = cast(dict[str, Scalar], principal_payload["attributes"])
            arguments = cast(dict[str, Scalar], payload["arguments"])
            if any(type(value) not in {bool, int, str} for value in attributes.values()) or any(
                type(value) not in {bool, int, str} for value in arguments.values()
            ):
                raise ValueError("request has non-scalar values")
            return ActionRequest(
                operation_id=cast(str, payload["operation_id"]),
                principal=Principal(cast(str, principal_payload["id"]), attributes),
                action=cast(str, payload["action"]),
                arguments=arguments,
                idempotency_key=cast(str, payload["idempotency_key"]),
                adapter_invocation_digest=cast(str | None, payload["adapter_invocation_digest"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise CalendarError("calendar pending request is malformed") from exc

    @staticmethod
    def _pending_row(row: Mapping[str, object]) -> _CalendarPending:
        def payload(name: str, *, optional: bool = False) -> dict[str, JsonValue] | None:
            raw = row[name]
            if raw is None and optional:
                return None
            if type(raw) is not str:
                raise ValueError(f"{name} is not JSON text")
            decoded = json.loads(raw)
            if not isinstance(decoded, dict):
                raise ValueError(f"{name} is not an object")
            return cast(dict[str, JsonValue], decoded)

        try:
            request_payload = payload("request_json")
            admission = payload("admission_decision_json")
            assert request_payload is not None and admission is not None
            state = row["state"]
            approved = row["resolution_approved"]
            claim_expires_at = row["claim_expires_at"]
            if type(state) is not str or state not in {"pending", "resolving", "resolved"}:
                raise ValueError("unknown pending state")
            if approved is not None and type(approved) is not bool:
                raise ValueError("pending approval is malformed")
            if claim_expires_at is not None and (
                not isinstance(claim_expires_at, datetime) or claim_expires_at.tzinfo is None
            ):
                raise ValueError("pending claim expiry is malformed")
            return _CalendarPending(
                request=CalendarReferenceResource._request_from_payload(request_payload),
                admission=admission,
                state=state,
                resolution=payload("resolution_decision_json", optional=True),
                resolver_id=cast(str | None, row["resolver_id"]),
                approved=approved,
                evidence=payload("evidence_json", optional=True),
                execution_id=cast(str | None, row["execution_id"]),
                claim_token=cast(str | None, row["claim_token"]),
                claim_expires_at=claim_expires_at,
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise CalendarError("calendar pending record is malformed") from exc

    @staticmethod
    def _resolution_replay_matches(
        pending: _CalendarPending,
        *,
        resolver_id: str,
        approved: bool,
        evidence: Mapping[str, JsonValue],
    ) -> bool:
        return (
            pending.resolution is not None
            and pending.resolver_id == resolver_id
            and pending.approved is approved
            and pending.evidence == dict(evidence)
        )

    async def _record_pending(
        self, request: ActionRequest, decision: PolicyDecision
    ) -> tuple[str, _CalendarPending, bool]:
        request_payload = self._request_payload(request)
        encoded_request = self._canonical_json(request_payload)
        request_digest = hashlib.sha256(encoded_request.encode("utf-8")).hexdigest()
        pending_id = str(uuid5(NAMESPACE_URL, "masugate-calendar-pending:" + request_digest))
        encoded_decision = self._canonical_json(self._decision_payload(decision))
        async with self.ledger.open_session(write=True) as session:
            inserted = (
                await session.execute(
                    f"""
                    INSERT INTO {_PENDING_TABLE}(
                        pending_id, request_digest, operation_id, request_json,
                        admission_decision_json, state, created_at, updated_at
                    ) VALUES (%s, %s, %s, %s, %s, 'pending', clock_timestamp(), clock_timestamp())
                    ON CONFLICT DO NOTHING
                    """,
                    (
                        pending_id,
                        request_digest,
                        request.operation_id,
                        encoded_request,
                        encoded_decision,
                    ),
                )
            ).rowcount == 1
            row = await (
                await session.execute(
                    f"SELECT * FROM {_PENDING_TABLE} WHERE pending_id = %s FOR UPDATE",
                    (pending_id,),
                )
            ).fetchone()
            if row is None:
                raise CalendarError("calendar pending identity conflicts with different content")
            pending = self._pending_row(row)
            if (
                row["request_digest"] != request_digest
                or pending.request.operation_id != request.operation_id
            ):
                raise CalendarError("calendar pending operation id collides with different content")
            return pending_id, pending, not inserted

    async def _claim_pending(self, pending_id: str) -> tuple[_CalendarPending, bool]:
        """Atomically acquire a renewable cross-process resolution lease."""

        async with self.ledger.open_session(write=True) as session:
            row = await (
                await session.execute(
                    f"SELECT * FROM {_PENDING_TABLE} WHERE pending_id = %s FOR UPDATE",
                    (pending_id,),
                )
            ).fetchone()
            if row is None:
                raise CalendarError("unknown calendar pending operation")
            pending = self._pending_row(row)
            if pending.state == "resolved":
                return pending, False
            if pending.state == "resolving" and pending.resolution is not None:
                # A durable resolution intent fences every later claimant. Its
                # protected execution can be recovered with the same identity.
                return pending, False
            now_row = await (
                await session.execute("SELECT clock_timestamp() AS current_time")
            ).fetchone()
            now = now_row["current_time"]
            if not isinstance(now, datetime) or now.tzinfo is None:
                raise CalendarError("calendar database clock is malformed")
            if (
                pending.state == "resolving"
                and pending.claim_expires_at is not None
                and pending.claim_expires_at > now
            ):
                return pending, False
            claim_token = str(uuid4())
            expires_at = now + timedelta(seconds=_PENDING_CLAIM_SECONDS)
            await session.execute(
                f"""
                UPDATE {_PENDING_TABLE}
                SET state = 'resolving', claim_token = %s, claim_expires_at = %s,
                    updated_at = %s
                WHERE pending_id = %s
                """,
                (claim_token, expires_at, now, pending_id),
            )
            return replace(
                pending,
                state="resolving",
                claim_token=claim_token,
                claim_expires_at=expires_at,
            ), True

    async def _release_pending_claim(self, pending_id: str, claim_token: str) -> None:
        async with self.ledger.open_session(write=True) as session:
            await session.execute(
                f"""
                UPDATE {_PENDING_TABLE}
                SET state = 'pending', claim_token = NULL, claim_expires_at = NULL,
                    updated_at = clock_timestamp()
                WHERE pending_id = %s AND state = 'resolving' AND claim_token = %s
                  AND resolution_decision_json IS NULL
                """,
                (pending_id, claim_token),
            )

    async def _fence_pending_resolution(
        self,
        pending_id: str,
        *,
        claim_token: str,
        decision: PolicyDecision,
        resolver_id: str,
        approved: bool,
        evidence: Mapping[str, JsonValue],
        execution_id: str | None,
    ) -> None:
        """Persist an immutable resolution before any protected dispatch."""

        encoded_decision = self._canonical_json(self._decision_payload(decision))
        encoded_evidence = self._canonical_json(evidence)
        async with self.ledger.open_session(write=True) as session:
            row = await (
                await session.execute(
                    f"SELECT * FROM {_PENDING_TABLE} WHERE pending_id = %s FOR UPDATE",
                    (pending_id,),
                )
            ).fetchone()
            if row is None:
                raise CalendarError("unknown calendar pending operation")
            pending = self._pending_row(row)
            if pending.state == "resolved":
                if (
                    not self._resolution_replay_matches(
                        pending, resolver_id=resolver_id, approved=approved, evidence=evidence
                    )
                    or pending.resolution != self._decision_payload(decision)
                    or pending.execution_id != execution_id
                ):
                    raise CalendarError("calendar pending resolution evidence is immutable")
                return
            if pending.state != "resolving" or pending.claim_token != claim_token:
                raise CalendarError("calendar pending operation was not claimed")
            if pending.resolution is not None:
                raise CalendarError("calendar pending resolution evidence is immutable")
            await session.execute(
                f"""
                UPDATE {_PENDING_TABLE}
                SET resolution_decision_json = %s, resolver_id = %s,
                    resolution_approved = %s, evidence_json = %s, execution_id = %s,
                    updated_at = clock_timestamp()
                WHERE pending_id = %s AND state = 'resolving' AND claim_token = %s
                  AND resolution_decision_json IS NULL
                """,
                (
                    encoded_decision,
                    resolver_id,
                    approved,
                    encoded_evidence,
                    execution_id,
                    pending_id,
                    claim_token,
                ),
            )

    async def _settle_pending(
        self,
        pending_id: str,
        *,
        claim_token: str,
        decision: PolicyDecision,
        resolver_id: str,
        approved: bool,
        evidence: Mapping[str, JsonValue],
        execution_id: str | None,
    ) -> None:
        encoded_decision = self._canonical_json(self._decision_payload(decision))
        encoded_evidence = self._canonical_json(evidence)
        async with self.ledger.open_session(write=True) as session:
            row = await (
                await session.execute(
                    f"SELECT * FROM {_PENDING_TABLE} WHERE pending_id = %s FOR UPDATE",
                    (pending_id,),
                )
            ).fetchone()
            if row is None:
                raise CalendarError("unknown calendar pending operation")
            pending = self._pending_row(row)
            if pending.state == "resolved":
                if (
                    not self._resolution_replay_matches(
                        pending, resolver_id=resolver_id, approved=approved, evidence=evidence
                    )
                    or pending.resolution != self._decision_payload(decision)
                    or pending.execution_id != execution_id
                ):
                    raise CalendarError("calendar pending resolution evidence is immutable")
                return
            if pending.state != "resolving" or pending.claim_token != claim_token:
                raise CalendarError("calendar pending operation was not claimed")
            if (
                not self._resolution_replay_matches(
                    pending, resolver_id=resolver_id, approved=approved, evidence=evidence
                )
                or pending.resolution != self._decision_payload(decision)
                or pending.execution_id != execution_id
            ):
                raise CalendarError("calendar pending resolution evidence is immutable")
            await session.execute(
                f"""
                UPDATE {_PENDING_TABLE}
                SET state = 'resolved', resolution_decision_json = %s, resolver_id = %s,
                    resolution_approved = %s, evidence_json = %s, execution_id = %s,
                    claim_token = NULL, claim_expires_at = NULL, updated_at = clock_timestamp(),
                    resolved_at = clock_timestamp()
                WHERE pending_id = %s AND claim_token = %s
                """,
                (
                    encoded_decision,
                    resolver_id,
                    approved,
                    encoded_evidence,
                    execution_id,
                    pending_id,
                    claim_token,
                ),
            )

    def authenticate(self, authorization: str | None) -> str:
        if authorization is None or not authorization.startswith("Bearer "):
            raise CalendarReferenceUnauthorized("missing bearer token")
        try:
            return self._tokens[authorization.removeprefix("Bearer ")]
        except KeyError as exc:
            raise CalendarReferenceUnauthorized("invalid bearer token") from exc

    def _operation_id(self, principal_id: str, action: str, idempotency_key: str) -> str:
        return str(
            uuid5(NAMESPACE_URL, f"masugate-calendar:{principal_id}:{action}:{idempotency_key}")
        )

    async def _evaluate_policy(
        self, request: ActionRequest, *, phase: CertificationPhase
    ) -> PolicyDecision:
        """Evaluate the compiled policy after acquiring every declared dependency scope."""

        effect = next(
            (
                binding.contract
                for binding in self.provider.provider_module().effects
                if binding.contract.action == request.action
            ),
            None,
        )
        if effect is None:
            raise CalendarError("calendar action is not deployed")
        effect.footprint_resolver(request)
        async with self.ledger.open_session(write=True) as session:
            await self.ledger.acquire_scoped_locks(
                session, self._runtime.dependency_scopes(request)
            )
            certified_at = await self.ledger.certify_admission(session)
            return await self._runtime.aevaluate(
                request,
                session,
                evaluation_at=certified_at,
                evaluation_phase=phase,
            )

    def _binding(
        self, request: ActionRequest, decision: PolicyDecision
    ) -> ProtectedExecutionBinding:
        decision_payload = self._decision_payload(decision)
        policy_digest = _policy_digest(decision.policy_id)
        authorization_digest = hashlib.sha256(
            self._canonical_json(
                {
                    "action": request.action,
                    "idempotency_key": request.idempotency_key,
                    "policy": decision_payload,
                    "policy_digest": policy_digest,
                }
            ).encode("utf-8")
        ).hexdigest()
        return ProtectedExecutionBinding(
            principal_id=request.principal.id,
            action=request.action,
            arguments=dict(request.arguments),
            idempotency_key=request.idempotency_key,
            policies=(
                PolicyBinding(
                    decision.policy_id,
                    decision.policy_version,
                    policy_digest,
                    "calendar-reference-bundle",
                    "1",
                    _BUNDLE_DIGEST,
                ),
            ),
            provider_identity=self.provider.policy.provider_identity,
            coordination_domain_id=self.provider.domain_id,
            scopes=(self.provider.scope,),
            tool_call_id="calendar:"
            + self._operation_id(request.principal.id, request.action, request.idempotency_key),
            connector_id=self.provider.policy.connector_id,
            entitlement_id="calendar-entitlement:"
            + hashlib.sha256(
                (request.principal.id + ":" + request.idempotency_key).encode("utf-8")
            ).hexdigest(),
            authorization_digest=authorization_digest,
        )

    async def _project_terminal(self, record: ProtectedExecutionRecord) -> None:
        if record.status in {
            ProtectedExecutionStatus.SUCCEEDED,
            ProtectedExecutionStatus.FAILED,
            ProtectedExecutionStatus.OUTCOME_UNKNOWN,
        }:
            await self.provider.record_terminal(record)

    async def _fenced_pending_ids(self) -> tuple[str, ...]:
        """List durable resolution intents that must be resumed, never replaced."""

        async with self.ledger.open_session(write=False) as session:
            rows = await (
                await session.execute(
                    f"SELECT pending_id FROM {_PENDING_TABLE} "
                    "WHERE state = 'resolving' AND resolution_decision_json IS NOT NULL"
                )
            ).fetchall()
        pending_ids: list[str] = []
        for row in rows:
            pending_id = row["pending_id"]
            if type(pending_id) is not str:
                raise CalendarError("calendar pending identity is malformed")
            pending_ids.append(pending_id)
        return tuple(pending_ids)

    async def recover(self) -> None:
        """Recover committed worker handoffs and project every terminal record."""

        failures: list[str] = []
        for worker in self._workers.values():
            report = await worker.recover()
            failures.extend(f"{execution_id}:{error}" for execution_id, error in report.errors)
            for handoff in await worker.handoff_store.committed():
                record = await worker.execution_store.get(handoff.binding.execution_id)
                await self._project_terminal(record)
        for pending_id in await self._fenced_pending_ids():
            try:
                pending, _claimed = await self._claim_pending(pending_id)
                if pending.state == "resolving" and pending.resolution is not None:
                    await self._resume_fenced_resolution(pending_id, pending)
            except Exception as exc:
                failures.append(f"{pending_id}:{exc}")

        if failures:
            raise CalendarError("calendar worker recovery failed: " + ", ".join(failures))

    async def _prepare_commit(
        self, request: ActionRequest, decision: PolicyDecision
    ) -> ProtectedExecutionBinding:
        """Reserve and bind an already fenced allowed request for handoff."""

        if decision.effect is not DecisionEffect.ALLOW:
            raise CalendarError("calendar protected handoff requires an allow decision")
        return await self.provider.bind(request, self._binding(request, decision))

    async def _prepare_fenced_commit(
        self,
        request: ActionRequest,
        decision: PolicyDecision,
        execution_id: str,
    ) -> ProtectedExecutionBinding:
        """Bind an already fenced approval without re-evaluating its clock boundary."""

        if decision.effect is not DecisionEffect.ALLOW:
            raise CalendarError("calendar protected handoff requires an allow decision")
        return await self.provider.bind_fenced(
            request,
            self._binding(request, decision),
            expected_execution_id=execution_id,
        )

    async def _preview_commit(
        self, request: ActionRequest, decision: PolicyDecision
    ) -> ProtectedExecutionBinding:
        """Derive an allowed execution identity without reserving provider state."""

        if decision.effect is not DecisionEffect.ALLOW:
            raise CalendarError("calendar protected handoff requires an allow decision")
        return await self.provider.preview_binding(request, self._binding(request, decision))

    async def _dispatch_commit(
        self, binding: ProtectedExecutionBinding
    ) -> tuple[ProtectedExecutionRecord, bool]:
        """Durably hand off and dispatch an already prepared protected binding."""

        worker = self._workers[binding.action]
        replayed = False
        try:
            await worker.handoff_store.get(binding.execution_id)
        except ContractError:
            await worker.record_committed_handoff(
                ConnectorHandoff(
                    binding=binding,
                    artifacts={},
                    connector_configuration_digest=worker.connector_configuration_digest,
                    created_at=datetime.now(UTC),
                ),
                now=datetime.now(UTC),
            )
        else:
            existing = await worker.execution_store.get(binding.execution_id)
            replayed = existing.status in {
                ProtectedExecutionStatus.SUCCEEDED,
                ProtectedExecutionStatus.FAILED,
                ProtectedExecutionStatus.OUTCOME_UNKNOWN,
            }
        record = await worker.dispatch(binding.execution_id)
        if record.status is ProtectedExecutionStatus.OUTCOME_UNKNOWN:
            record = await worker.reconcile(binding.execution_id)
        await self._project_terminal(record)
        return record, replayed

    async def _commit(
        self, request: ActionRequest, decision: PolicyDecision
    ) -> tuple[ProtectedExecutionRecord, bool]:
        """Prepare and dispatch one already-allowed request."""

        binding = await self._prepare_commit(request, decision)
        return await self._dispatch_commit(binding)

    async def _pending_result(
        self, pending_id: str, pending: _CalendarPending, *, replayed: bool
    ) -> CalendarActionResult:
        if pending.state != "resolved":
            return CalendarActionResult(
                pending.request,
                self._decision_from_payload(pending.admission),
                pending_id=pending_id,
                replayed=replayed,
            )
        decision = self._decision_from_payload(
            pending.resolution if pending.resolution is not None else pending.admission
        )
        if pending.execution_id is None:
            return CalendarActionResult(pending.request, decision, replayed=True)
        record = await self._workers[pending.request.action].execution_store.get(
            pending.execution_id
        )
        return CalendarActionResult(pending.request, decision, record=record, replayed=True)

    async def _resume_fenced_resolution(
        self, pending_id: str, pending: _CalendarPending
    ) -> CalendarActionResult:
        """Finish a persisted resolution without permitting a new decision."""

        if (
            pending.state != "resolving"
            or pending.claim_token is None
            or pending.resolution is None
            or pending.resolver_id is None
            or pending.approved is None
            or pending.evidence is None
        ):
            raise CalendarError("calendar pending resolution fence is malformed")
        decision = self._decision_from_payload(pending.resolution)
        if decision.effect not in {DecisionEffect.ALLOW, DecisionEffect.DENY}:
            raise CalendarError("calendar pending resolution fence is not terminal")
        record: ProtectedExecutionRecord | None = None
        replayed = False
        if decision.effect is DecisionEffect.ALLOW:
            if pending.execution_id is None:
                raise CalendarError("calendar allowed pending resolution has no execution identity")
            binding = await self._prepare_fenced_commit(
                pending.request, decision, pending.execution_id
            )
            if binding.execution_id != pending.execution_id:
                raise CalendarError("calendar pending execution identity drifted")
            record, replayed = await self._dispatch_commit(binding)
        elif pending.execution_id is not None:
            raise CalendarError("calendar denied pending resolution has an execution identity")
        await self._settle_pending(
            pending_id,
            claim_token=pending.claim_token,
            decision=decision,
            resolver_id=pending.resolver_id,
            approved=pending.approved,
            evidence=pending.evidence,
            execution_id=pending.execution_id,
        )
        return CalendarActionResult(pending.request, decision, record=record, replayed=replayed)

    async def submit(
        self,
        *,
        principal_id: str,
        action: str,
        arguments: Mapping[str, Scalar],
        idempotency_key: str,
        adapter_invocation_digest: str | None,
    ) -> CalendarActionResult:
        if principal_id not in self._principals:
            raise CalendarReferenceUnauthorized("principal is not configured")
        if action not in self._workers:
            raise CalendarError("calendar action is not deployed")
        request = ActionRequest(
            operation_id=self._operation_id(principal_id, action, idempotency_key),
            principal=Principal(principal_id, self._principals[principal_id]),
            action=action,
            arguments=dict(arguments),
            idempotency_key=idempotency_key,
            adapter_invocation_digest=adapter_invocation_digest,
        )
        decision = await self._evaluate_policy(request, phase=CertificationPhase.ADMISSION)
        if decision.effect is DecisionEffect.DENY:
            return CalendarActionResult(request, decision)
        if decision.effect is DecisionEffect.ESCALATE:
            pending_id, pending, replayed = await self._record_pending(request, decision)
            if pending.state == "resolved":
                return await self._pending_result(pending_id, pending, replayed=True)
            return CalendarActionResult(
                pending.request,
                self._decision_from_payload(pending.admission),
                pending_id=pending_id,
                replayed=replayed,
            )
        record, replayed = await self._commit(request, decision)
        return CalendarActionResult(request, decision, record=record, replayed=replayed)

    def can_resolve(self, principal_id: str) -> bool:
        return principal_id in self.operator_principals

    async def resolve_pending(
        self,
        pending_id: str,
        *,
        resolver_id: str,
        approved: bool,
        evidence: Mapping[str, JsonValue],
    ) -> CalendarActionResult:
        """Resolve an escalation by re-entering the same policy runtime."""

        if not self.can_resolve(resolver_id):
            raise CalendarError("unknown calendar pending operation")
        pending, claimed = await self._claim_pending(pending_id)
        if pending.state == "resolved":
            if not self._resolution_replay_matches(
                pending, resolver_id=resolver_id, approved=approved, evidence=evidence
            ):
                raise CalendarError("calendar pending resolution evidence is immutable")
            return await self._pending_result(pending_id, pending, replayed=True)
        if pending.resolution is not None:
            if not self._resolution_replay_matches(
                pending, resolver_id=resolver_id, approved=approved, evidence=evidence
            ):
                raise CalendarError("calendar pending resolution evidence is immutable")
            return await self._resume_fenced_resolution(pending_id, pending)
        if not claimed or pending.claim_token is None:
            raise CalendarError("calendar pending resolution is already in progress")
        request = pending.request
        try:
            if approved:
                revalidated = await self._evaluate_policy(
                    request, phase=CertificationPhase.RESOLUTION
                )
                decision = (
                    revalidated
                    if revalidated.effect is DecisionEffect.DENY
                    else replace(
                        revalidated,
                        effect=DecisionEffect.ALLOW,
                        rule_id="resolution.approved",
                        reason="explicit approval followed current calendar policy revalidation",
                    )
                )
            else:
                decision = PolicyDecision(
                    effect=DecisionEffect.DENY,
                    policy_id="calendar.pending-resolution",
                    policy_version="1",
                    rule_id="resolution.denied",
                    reason="the authorized calendar resolver denied the pending operation",
                    evaluated_policies=self._decision_from_payload(
                        pending.admission
                    ).evaluated_policies,
                )
            execution_id: str | None = None
            if decision.effect is DecisionEffect.ALLOW:
                binding = await self._preview_commit(request, decision)
                execution_id = binding.execution_id
            await self._fence_pending_resolution(
                pending_id,
                claim_token=pending.claim_token,
                decision=decision,
                resolver_id=resolver_id,
                approved=approved,
                evidence=evidence,
                execution_id=execution_id,
            )
            fenced = replace(
                pending,
                resolution=self._decision_payload(decision),
                resolver_id=resolver_id,
                approved=approved,
                evidence=dict(evidence),
                execution_id=execution_id,
            )
            return await self._resume_fenced_resolution(pending_id, fenced)
        except BaseException:
            await self._release_pending_claim(pending_id, pending.claim_token)
            raise


def calendar_reference_route_manifest(resource: CalendarReferenceResource) -> dict[str, JsonValue]:
    """Compile the exact closed Calendar pack for one reference deployment."""

    pack = operation_pack()
    provider_implementation, provider_configuration = provider_identity_digests(
        resource.provider.policy.provider_identity
    )
    connector_implementation = hashlib.sha256(
        b"masugate-calendar-reference-connector-implementation-v1"
    ).hexdigest()
    binding = load_deployment_binding(
        {
            "contract_version": "masugate.operation-deployment-binding.v1",
            "pack": {
                "id": pack.pack_id,
                "version": pack.version,
                "digest": hashlib.sha256(
                    canonical_operation_pack(pack).encode("utf-8")
                ).hexdigest(),
            },
            "routes": [
                {
                    "action": _CREATE,
                    "host_tool": "calendar_create",
                    "provider": {
                        "id": resource.provider.policy.provider_identity.provider_id,
                        "implementation_digest": provider_implementation,
                        "configuration_digest": provider_configuration,
                    },
                    "connector": {
                        "id": _CONNECTOR_ID,
                        "version": "1",
                        "implementation_digest": connector_implementation,
                        "configuration_digest": _CONFIGURATION_DIGEST,
                        "credential_refs": [],
                        "allowed_destinations": [],
                    },
                },
                {
                    "action": _CANCEL,
                    "host_tool": "calendar_cancel",
                    "provider": {
                        "id": resource.provider.policy.provider_identity.provider_id,
                        "implementation_digest": provider_implementation,
                        "configuration_digest": provider_configuration,
                    },
                    "connector": {
                        "id": _CONNECTOR_ID,
                        "version": "1",
                        "implementation_digest": connector_implementation,
                        "configuration_digest": _CONFIGURATION_DIGEST,
                        "credential_refs": [],
                        "allowed_destinations": [],
                    },
                },
            ],
        }
    )
    return compile_operation_pack(pack, binding).route_manifest


def build_calendar_reference_resource(
    *,
    dsn: str,
    state_path: Path,
    principals: Mapping[str, Mapping[str, Scalar]],
    token_principals: Mapping[str, str],
    reference_state: ReferenceCalendarState | None = None,
    operator_principals: frozenset[str] = frozenset(),
) -> CalendarReferenceResource:
    """Build the PostgreSQL policy-state and worker-only reference profile."""

    if not isinstance(state_path, Path):
        raise TypeError("calendar reference state_path must be a Path")
    policy = CalendarPolicy("reference-calendar", _CONNECTOR_ID, ("America/New_York",))
    ledger = AsyncPostgresLedger(dsn, min_size=1, max_size=8)
    domain = CoordinationDomain(
        "calendar-reference-domain-v1", policy.digest, "calendar-scope-v1", ledger
    )
    provider = CalendarProvider(policy, domain)
    protected_store = PostgresProtectedExecutionStore(dsn)
    connector = ReferenceCalendarConnector(
        ReferenceCalendarState(state_path / "reference-calendar.sqlite")
        if reference_state is None
        else reference_state
    )
    workers: dict[str, ConnectorWorker] = {}
    for action in (_CREATE, _CANCEL):
        deployment = ConnectorWorkerDeployment(
            action=action,
            connector_id=_CONNECTOR_ID,
            connector_package_id="masugate-operation-calendar",
            connector_package_version="1",
            connector_entry_point="masugate-operation-calendar.reference",
            connector_sdk_contract_version=SDK_CONTRACT_VERSION,
            connector_capabilities=connector.capabilities,
            connector_configuration_digest=_CONFIGURATION_DIGEST,
            artifact_fields=(),
            credential_refs=(),
            allowed_destinations=(),
        )
        workers[action] = ConnectorWorker(
            execution_store=cast(ProtectedExecutionStore, protected_store),
            handoff_store=SqliteConnectorHandoffStore(state_path / f"{action}.handoff.sqlite"),
            artifact_store=SqliteArtifactStore(str(state_path / f"{action}.artifacts.sqlite")),
            secret_resolver=_NoSecrets(),
            authority=ProtectedExecutionAuthority(
                action=action,
                provider_identity=policy.provider_identity,
                coordination_domain_id=domain.domain_id,
                connector_id=_CONNECTOR_ID,
            ),
            deployment=deployment,
            worker_id="calendar-reference-" + action.replace(".", "-"),
            connector=connector,
        )
    return CalendarReferenceResource(
        provider=provider,
        ledger=ledger,
        workers=workers,
        principals=principals,
        operator_principals=operator_principals,
        token_principals=token_principals,
    )


def _error(code: str, message: str) -> dict[str, JsonValue]:
    return {"error": {"code": code, "message": message}}


def _record_payload(record: ProtectedExecutionRecord) -> dict[str, JsonValue]:
    return {
        "binding_digest": record.binding_digest,
        "execution_id": record.execution_id,
        "external_operation_id": record.external_operation_id,
        "status": record.status.value,
        "entitlement_state": record.entitlement_state.value,
        "dispatch_started": record.dispatch_started,
    }


def _public_payload(record: ProtectedExecutionRecord) -> dict[str, JsonValue]:
    event_ref = record.binding.arguments.get("event_ref")
    if type(event_ref) is not str:
        raise ContractError("calendar terminal record lacks an event reference")
    status = {
        ProtectedExecutionStatus.SUCCEEDED: (
            "created" if record.binding.action == _CREATE else "cancelled"
        ),
        ProtectedExecutionStatus.FAILED: "failed",
        ProtectedExecutionStatus.OUTCOME_UNKNOWN: "unknown",
    }.get(record.status)
    if status is None:
        raise ContractError("calendar terminal record has a nonterminal status")
    return {"event_ref": event_ref, "status": status}


def _decision_json(decision: PolicyDecision) -> dict[str, JsonValue]:
    return CalendarReferenceResource._decision_payload(decision)


def _response(result: CalendarActionResult) -> dict[str, JsonValue]:
    request, decision = result.request, result.decision
    base: dict[str, JsonValue] = {
        "audit_ref": "/v1/audit/" + request.operation_id,
        "operation_id": request.operation_id,
        "replayed": result.replayed,
    }
    if result.pending_id is not None:
        return {
            **base,
            "status": "pending",
            "decision": _decision_json(decision),
            "payload": {},
            "pending_id": result.pending_id,
            "resolution_plan": "revalidate",
        }
    if result.record is None:
        if decision.effect is not DecisionEffect.DENY:
            raise CalendarError("calendar terminal result lacks a deny decision")
        return {**base, "status": "denied", "decision": _decision_json(decision), "payload": {}}
    record = result.record
    if record.status is ProtectedExecutionStatus.SUCCEEDED:
        return {
            **base,
            "status": "committed",
            "decision": _decision_json(decision),
            "payload": _public_payload(record),
        }
    if record.status is ProtectedExecutionStatus.FAILED:
        return {
            **base,
            "status": "denied",
            "decision": {
                "effect": "deny",
                "policy_id": decision.policy_id,
                "policy_version": decision.policy_version,
                "rule_id": "connector.failed",
                "reason": "calendar connector returned a terminal failure",
                "evaluated_policies": _decision_json(decision)["evaluated_policies"],
            },
            "payload": _public_payload(record),
        }
    return {
        **base,
        "status": "outcome_unknown",
        "decision": None,
        "payload": _public_payload(record),
    }


def create_calendar_reference_app(resource: CalendarReferenceResource) -> FastAPI:
    """Expose only the governed create/cancel actions to host adapters."""

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        stopped = asyncio.Event()
        recovery: asyncio.Task[None] | None = None
        try:
            await resource.initialize()

            async def recover_forever() -> None:
                while not stopped.is_set():
                    try:
                        await asyncio.wait_for(stopped.wait(), resource.recovery_interval_seconds)
                    except TimeoutError:
                        await resource.recover()

            recovery = asyncio.create_task(recover_forever(), name="masugate-calendar-recovery")
            yield
        finally:
            stopped.set()
            if recovery is not None:
                recovery.cancel()
                with suppress(asyncio.CancelledError):
                    await recovery
            await resource.close()

    app = FastAPI(title="masugate-calendar-reference", version="4.3", lifespan=lifespan)

    @app.exception_handler(CalendarReferenceUnauthorized)
    async def unauthorized(_request: Request, exc: CalendarReferenceUnauthorized) -> JSONResponse:
        return JSONResponse(status_code=401, content=_error("unauthorized", str(exc)))

    @app.exception_handler(ContractError)
    @app.exception_handler(CalendarError)
    async def conflict(_request: Request, exc: ContractError) -> JSONResponse:
        return JSONResponse(status_code=409, content=_error("resource_conflict", str(exc)))

    @app.post("/v1/actions")
    async def action(
        body: ActionBody,
        authorization: Annotated[str | None, Header()] = None,
        masugate_expected_principal: Annotated[str | None, Header()] = None,
        masugate_expected_provider: Annotated[str | None, Header()] = None,
        masugate_expected_position: Annotated[str | None, Header()] = None,
        masugate_expected_connector: Annotated[str | None, Header()] = None,
    ) -> dict[str, JsonValue]:
        principal_id = resource.authenticate(authorization)
        if masugate_expected_principal != principal_id:
            raise CalendarReferenceUnauthorized("expected principal does not match bearer identity")
        if (
            masugate_expected_provider != resource.owner["provider_id"]
            or masugate_expected_position != resource.owner["position"]
            or masugate_expected_connector != resource.owner["connector_id"]
        ):
            raise CalendarError("action execution owner mismatch: calendar")
        if body.adapter_invocation is None:
            raise CalendarReferenceUnauthorized("missing required adapter invocation assertion")
        adapter_digest = _adapter_invocation_digest(
            body.adapter_invocation,
            principal_id=principal_id,
            action=body.action,
            args=body.args,
        )
        result = await resource.submit(
            principal_id=principal_id,
            action=body.action,
            arguments=body.args,
            idempotency_key=body.idempotency_key,
            adapter_invocation_digest=adapter_digest,
        )
        return _response(result)

    @app.post("/v1/pending/{pending_id}/resolve")
    async def resolve_pending(
        pending_id: str,
        body: ResolveBody,
        authorization: Annotated[str | None, Header()] = None,
    ) -> dict[str, JsonValue]:
        resolver_id = resource.authenticate(authorization)
        if not resource.can_resolve(resolver_id):
            raise CalendarError("unknown calendar pending operation")
        return _response(
            await resource.resolve_pending(
                pending_id,
                resolver_id=resolver_id,
                approved=body.approved,
                evidence=body.evidence,
            )
        )

    return app


__all__ = [
    "CalendarReferenceResource",
    "CalendarReferenceUnauthorized",
    "build_calendar_reference_resource",
    "calendar_reference_route_manifest",
    "create_calendar_reference_app",
]
