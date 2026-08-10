"""SDK-owned offline connector lifecycle and fault conformance harness."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from collections.abc import Awaitable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from importlib import metadata
from pathlib import Path
from typing import cast

from . import (
    SDK_CONTRACT_VERSION,
    ArtifactDescriptor,
    ConnectorAmbiguousOutcome,
    ConnectorEvidence,
    ConnectorInvocation,
    ConnectorOutcome,
    ConnectorSDKError,
    JsonValue,
    OperationConnector,
    SecretHandle,
    validate_operation_connector,
)

_ENTRY_POINT_GROUP = "masugate.connector"
_NOW = datetime(2026, 1, 1, tzinfo=UTC)
_CONFORMANCE_ARTIFACT = b"masugate-conformance-artifact"
_LIFECYCLE_EXECUTION_ID = "conformance-lifecycle-1"
_LIFECYCLE_IDEMPOTENCY_KEY = "conformance-lifecycle-1"


class _EffectOracle:
    """Harness-owned assertion that a rejected mutant never consumed an effect input."""

    def __init__(self) -> None:
        self.attempts = 0

    def attempted(self) -> None:
        self.attempts += 1


class _ConformanceArtifactReader:
    """A bounded in-memory reader owned by the harness, never the connector."""

    metadata = ArtifactDescriptor(
        reference="art:conformance",
        content_digest=hashlib.sha256(_CONFORMANCE_ARTIFACT).hexdigest(),
        content_bytes=len(_CONFORMANCE_ARTIFACT),
        media_type="text/plain",
        classification="conformance",
        expires_at=_NOW + timedelta(minutes=5),
    )

    def __init__(self, oracle: _EffectOracle) -> None:
        self._oracle = oracle

    async def read(self, *, maximum_bytes: int | None = None) -> bytes:
        self._oracle.attempted()
        content = _CONFORMANCE_ARTIFACT
        if maximum_bytes is not None and len(content) > maximum_bytes:
            raise ConnectorSDKError("conformance artifact reader limit was not respected")
        return content


@dataclass(frozen=True, slots=True)
class _MutantFacts:
    mutant_id: str
    action: str
    arguments: Mapping[str, JsonValue]
    artifact_fields: tuple[str, ...]
    secret_refs: tuple[str, ...]
    allowed_destinations: tuple[str, ...]


def load_entry_point(name: str) -> OperationConnector:
    """Load one installed authoring entry point for offline conformance only."""

    if not name or name.strip() != name:
        raise ConnectorSDKError("connector conformance entry-point name must be canonical")
    matches = tuple(metadata.entry_points(group=_ENTRY_POINT_GROUP, name=name))
    if len(matches) != 1:
        raise ConnectorSDKError("connector conformance needs exactly one installed entry point")
    return validate_operation_connector(matches[0].load())


def _identifier(value: object, field: str) -> str:
    if type(value) is not str or not value or value.strip() != value:
        raise ConnectorSDKError(f"{field} must be a non-empty identifier")
    return value


def _facts(value: object) -> _MutantFacts:
    if not isinstance(value, dict) or set(value) != {"id", "invocation"}:
        raise ConnectorSDKError("pack mutant must contain only id and invocation")
    mutant_id = _identifier(value["id"], "pack mutant id")
    invocation = value["invocation"]
    if not isinstance(invocation, dict) or set(invocation) != {
        "action",
        "arguments",
        "artifact_fields",
        "secret_refs",
        "allowed_destinations",
    }:
        raise ConnectorSDKError("pack mutant invocation has an invalid shape")
    arguments = invocation["arguments"]
    if not isinstance(arguments, dict) or any(type(name) is not str for name in arguments):
        raise ConnectorSDKError("pack mutant arguments must be an object")
    for key, values in (
        ("artifact_fields", invocation["artifact_fields"]),
        ("secret_refs", invocation["secret_refs"]),
        ("allowed_destinations", invocation["allowed_destinations"]),
    ):
        if (
            not isinstance(values, list)
            or any(type(item) is not str for item in values)
            or len(set(values)) != len(values)
        ):
            raise ConnectorSDKError(f"pack mutant {key} must be a unique string array")
    # ConnectorInvocation applies the full public JSON/identifier validation;
    # keep this loader focused on a closed, executable file shape.
    return _MutantFacts(
        mutant_id=mutant_id,
        action=_identifier(invocation["action"], "pack mutant action"),
        arguments=cast(Mapping[str, JsonValue], arguments),
        artifact_fields=tuple(cast(list[str], invocation["artifact_fields"])),
        secret_refs=tuple(cast(list[str], invocation["secret_refs"])),
        allowed_destinations=tuple(cast(list[str], invocation["allowed_destinations"])),
    )


def _mutants(path: Path | None) -> tuple[_MutantFacts, ...]:
    if path is None:
        return ()
    value = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(value, dict)
        or set(value) != {"mutants"}
        or not isinstance(value["mutants"], list)
    ):
        raise ConnectorSDKError("pack mutant file must contain only mutants")
    parsed = tuple(_facts(item) for item in value["mutants"])
    if len({item.mutant_id for item in parsed}) != len(parsed):
        raise ConnectorSDKError("pack mutant ids must be unique")
    return tuple(sorted(parsed, key=lambda item: item.mutant_id))


def _invocation(
    connector: OperationConnector,
    *,
    action: str = "conformance.action",
    arguments: Mapping[str, JsonValue] | None = None,
    artifact_fields: Sequence[str] = ("content",),
    secret_refs: Sequence[str] = ("conformance_secret",),
    allowed_destinations: Sequence[str] = ("conformance-destination",),
    execution_id: str = _LIFECYCLE_EXECUTION_ID,
    idempotency_key: str = _LIFECYCLE_IDEMPOTENCY_KEY,
    fence_token: int = 1,
    oracle: _EffectOracle,
) -> ConnectorInvocation:
    return ConnectorInvocation(
        action=action,
        arguments={"mode": "execute"} if arguments is None else arguments,
        execution_id=execution_id,
        binding_digest="a" * 64,
        connector_id=connector.connector_id,
        idempotency_key=idempotency_key,
        fence_token=fence_token,
        artifacts={field: _ConformanceArtifactReader(oracle) for field in artifact_fields},
        secrets={reference: SecretHandle(b"conformance-secret") for reference in secret_refs},
        allowed_destinations=tuple(allowed_destinations),
    )


def _require_evidence(
    value: object,
    invocation: ConnectorInvocation,
    *,
    case: str,
    outcomes: frozenset[ConnectorOutcome],
    expected_external_operation_id: str | None = None,
) -> ConnectorEvidence:
    if type(value) is not ConnectorEvidence:
        raise ConnectorSDKError(f"{case} did not return ConnectorEvidence")
    evidence = value
    if (
        evidence.connector_id != invocation.connector_id
        or evidence.idempotency_key != invocation.idempotency_key
        or evidence.outcome not in outcomes
        or evidence.external_operation_id is None
        or (
            expected_external_operation_id is not None
            and evidence.external_operation_id != expected_external_operation_id
        )
    ):
        raise ConnectorSDKError(f"{case} returned evidence inconsistent with its invocation")
    return evidence


async def _require_unsupported(
    call: Awaitable[object],
    *,
    case: str,
) -> None:
    try:
        await call
    except ConnectorSDKError:
        return
    raise ConnectorSDKError(f"{case} must reject unsupported lifecycle work")


async def run_author_conformance(
    connector: OperationConnector,
    *,
    mutants: Sequence[_MutantFacts] = (),
) -> tuple[str, ...]:
    """Execute SDK-owned lifecycle, fault, and pack-mutant cases.

    Pack mutants are executable invocation facts, not connector-recognizable
    labels.  Each receives a fresh harness-owned effect oracle; a mutant only
    passes when the connector rejects those facts *before* reading the payload
    that represents the bounded effect input.
    """

    connector = validate_operation_connector(connector)
    if connector.sdk_contract_version != SDK_CONTRACT_VERSION:
        raise ConnectorSDKError("connector SDK contract version is unsupported")
    if any(type(mutant) is not _MutantFacts for mutant in mutants):
        raise ConnectorSDKError("conformance mutants must come from the closed pack file")
    if len({mutant.mutant_id for mutant in mutants}) != len(mutants):
        raise ConnectorSDKError("conformance mutant ids must be unique")

    lifecycle_oracle = _EffectOracle()
    execute = _invocation(connector, oracle=lifecycle_oracle)
    evidence = _require_evidence(
        await connector.execute(execute),
        execute,
        case="base execute",
        outcomes=frozenset({ConnectorOutcome.SUCCEEDED, ConnectorOutcome.FAILED}),
    )
    if lifecycle_oracle.attempts == 0:
        raise ConnectorSDKError("base execute did not consume its bounded effect input")

    if connector.capabilities.status_query:
        status = _invocation(connector, oracle=_EffectOracle())
        _require_evidence(
            await connector.query_status(
                status, external_operation_id=evidence.external_operation_id
            ),
            status,
            case="base status",
            outcomes=frozenset({ConnectorOutcome.SUCCEEDED, ConnectorOutcome.FAILED}),
            expected_external_operation_id=evidence.external_operation_id,
        )
    else:
        await _require_unsupported(
            connector.query_status(
                _invocation(connector, oracle=_EffectOracle()),
                external_operation_id=evidence.external_operation_id,
            ),
            case="status query",
        )

    if connector.capabilities.cancellation:
        cancellation = _invocation(connector, oracle=_EffectOracle())
        _require_evidence(
            await connector.cancel(
                cancellation, external_operation_id=evidence.external_operation_id
            ),
            cancellation,
            case="base cancel",
            outcomes=frozenset({ConnectorOutcome.FAILED}),
            expected_external_operation_id=evidence.external_operation_id,
        )
    else:
        await _require_unsupported(
            connector.cancel(
                _invocation(connector, oracle=_EffectOracle()),
                external_operation_id=evidence.external_operation_id,
            ),
            case="cancellation",
        )

    response_loss = _invocation(
        connector,
        arguments={"mode": "response-loss"},
        execution_id="conformance-response-loss-1",
        idempotency_key="conformance-response-loss-1",
        oracle=_EffectOracle(),
    )
    try:
        await connector.execute(response_loss)
    except ConnectorAmbiguousOutcome:
        pass
    else:
        raise ConnectorSDKError("fault-response-loss must raise ConnectorAmbiguousOutcome")

    for mutant in sorted(mutants, key=lambda item: item.mutant_id):
        oracle = _EffectOracle()
        try:
            invocation = _invocation(
                connector,
                action=mutant.action,
                arguments=mutant.arguments,
                artifact_fields=mutant.artifact_fields,
                secret_refs=mutant.secret_refs,
                allowed_destinations=mutant.allowed_destinations,
                execution_id=f"conformance-mutant-{mutant.mutant_id}",
                idempotency_key=f"conformance-mutant-{mutant.mutant_id}",
                oracle=oracle,
            )
        except ConnectorSDKError as exc:
            raise ConnectorSDKError(
                f"pack invariant mutant {mutant.mutant_id!r} is not executable"
            ) from exc
        try:
            await connector.execute(invocation)
        except ConnectorSDKError:
            if oracle.attempts != 0:
                raise ConnectorSDKError(
                    f"pack invariant mutant {mutant.mutant_id!r} consumed effect input"
                ) from None
            continue
        raise ConnectorSDKError(
            f"pack invariant mutant {mutant.mutant_id!r} reached connector effect"
        )
    return tuple(
        sorted(("base-lifecycle", "fault-response-loss", *(mutant.mutant_id for mutant in mutants)))
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Run MasuGate connector author conformance")
    parser.add_argument(
        "--entry-point", required=True, help="Installed masugate.connector entry-point name"
    )
    parser.add_argument(
        "--pack-mutants", type=Path, help="Closed JSON file with executable mutants"
    )
    args = parser.parse_args()
    connector = load_entry_point(args.entry_point)
    passed = asyncio.run(run_author_conformance(connector, mutants=_mutants(args.pack_mutants)))
    print(
        json.dumps({"connector_id": connector.connector_id, "passed": list(passed)}, sort_keys=True)
    )


__all__ = ["load_entry_point", "main", "run_author_conformance"]


if __name__ == "__main__":  # pragma: no cover - exercised from the clean wheel subprocess
    main()
