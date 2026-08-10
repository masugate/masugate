"""Command-line bootstrap for one-process ``masugated``.

Example::

    masugated --dsn postgresql://localhost/masugate \
      --governance-profile governance/deployment.json \
      --owner-bundle governance/owner \
      --principals principals.json --tokens tokens.json

``principals.json`` maps authenticated ids to certified scalar attributes;
``tokens.json`` maps bearer-token strings to those ids.  They are deliberately
separate so an HTTP request never carries trusted attributes.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

import uvicorn
from fastapi import FastAPI

from masugate.catalog import (
    TrustedDeploymentProfile,
    compile_trusted_policy_set,
    load_deployment_profile,
    load_trusted_catalog,
)
from masugate.contracts import ContractRegistry
from masugate.coordinator import AsyncGovernedCoordinator
from masugate.language import PolicyCompiler, parse_policy
from masugate.model import MasuGateMode, Scalar, TypeName
from masugate.operations import (
    DEFAULT_OPERATION_PACK_CANONICAL_BYTES,
    CompiledOperationRoutes,
    ConnectorRegistry,
    SqliteArtifactStore,
    compile_operation_pack,
    load_connector_registry,
    load_deployment_binding,
    load_operation_pack,
    validate_compiled_operation_routes,
)
from masugate.policy import AsyncPolicyRuntime, PolicySet
from masugate.principals import PrincipalRegistry
from masugate.masugated.app import ActionOwnerBinding, create_app
from masugate.provider_assembly import ProviderAssembly, assemble_provider_domain
from masugate.resources.postgres import AsyncPostgresLedger

_BOOLEAN_SECURITY_ATTRIBUTES = frozenset(
    {
        "masugate_operator",
        "masugate_require_action_assertions",
        "masugate_require_adapter_invocation",
    }
)


def _object_file(path: str, *, max_bytes: int | None = None) -> dict[str, object]:
    if max_bytes is not None and (type(max_bytes) is not int or max_bytes <= 0):
        raise ValueError("JSON file byte limit must be positive")
    with Path(path).open("rb") as source:
        source.seek(0, 2)
        if max_bytes is not None and source.tell() > max_bytes:
            raise ValueError(f"{path} exceeds configured byte limit")
        source.seek(0)
        raw = json.loads(source.read().decode("utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return cast(dict[str, object], raw)


def _scalar_type(value: Scalar) -> TypeName:
    if isinstance(value, bool):
        return TypeName.BOOL
    if isinstance(value, int):
        return TypeName.INT
    if isinstance(value, str):
        return TypeName.STRING
    raise ValueError(f"principal attribute must be scalar, got {type(value).__name__}")


def _principal_types(principals: Mapping[str, Mapping[str, Scalar]]) -> dict[str, TypeName]:
    types: dict[str, TypeName] = {}
    for attributes in principals.values():
        for name, value in attributes.items():
            value_type = _scalar_type(value)
            existing = types.setdefault(name, value_type)
            if existing is not value_type:
                raise ValueError(f"principal attribute {name!r} has inconsistent types")
    return types


def _validated_principals(principals: Mapping[str, object]) -> dict[str, dict[str, Scalar]]:
    validated: dict[str, dict[str, Scalar]] = {}
    for principal_id, raw_attributes in principals.items():
        if not isinstance(principal_id, str) or not principal_id.strip():
            raise ValueError("principal ids must be non-empty strings")
        if not isinstance(raw_attributes, Mapping):
            raise ValueError(f"principal {principal_id!r} attributes must be a JSON object")
        attributes: dict[str, Scalar] = {}
        for name, raw_value in raw_attributes.items():
            if not isinstance(name, str) or not name.strip():
                raise ValueError(f"principal {principal_id!r} has an empty attribute name")
            if not isinstance(raw_value, bool | int | str):
                raise ValueError(f"principal {principal_id!r} attribute {name!r} must be scalar")
            if name in _BOOLEAN_SECURITY_ATTRIBUTES and type(raw_value) is not bool:
                raise ValueError(
                    f"principal {principal_id!r} security attribute {name!r} must be boolean"
                )
            attributes[name] = raw_value
        if (
            attributes.get("masugate_require_action_assertions") is True
            and attributes.get("masugate_require_adapter_invocation") is True
        ):
            raise ValueError(
                f"principal {principal_id!r} cannot require both header-only and adapter assertions"
            )
        validated[principal_id] = attributes
    return validated


def _action_assertion_principals(
    principals: Mapping[str, Mapping[str, Scalar]],
) -> set[str]:
    """Return principals explicitly configured to require header assertions.

    This preserves the adapter integration setting: a listed principal must assert the
    bearer subject and certified action owner. Adapter-invocation binding is a
    distinct connector SDK deployment choice rather than an implicit behavior
    change for existing trusted bootstraps.
    """

    required: set[str] = set()
    for principal_id, attributes in principals.items():
        if attributes.get("masugate_require_action_assertions") is True:
            required.add(principal_id)
    return required


def _adapter_invocation_principals(
    principals: Mapping[str, Mapping[str, Scalar]],
) -> set[str]:
    """Return principals whose requests must carry a canonical adapter assertion."""

    return {
        principal_id
        for principal_id, attributes in principals.items()
        if attributes.get("masugate_require_adapter_invocation") is True
    }


def _validated_tokens(
    token_principals: Mapping[str, object],
    principal_ids: set[str],
) -> dict[str, str]:
    validated: dict[str, str] = {}
    for token, raw_principal_id in token_principals.items():
        if not isinstance(token, str) or not token or token.strip() != token:
            raise ValueError("bearer tokens must be non-empty strings without surrounding space")
        if not isinstance(raw_principal_id, str) or not raw_principal_id.strip():
            raise ValueError(f"token {token!r} must map to a non-empty principal id")
        if raw_principal_id not in principal_ids:
            raise ValueError(f"token {token!r} maps to unknown principal {raw_principal_id!r}")
        validated[token] = raw_principal_id
    return validated


def _validated_action_modes(action_modes: Mapping[str, object]) -> dict[str, MasuGateMode]:
    validated: dict[str, MasuGateMode] = {}
    for action, raw_mode in action_modes.items():
        if not isinstance(action, str) or not action.strip() or action.strip() != action:
            raise ValueError(
                "action-mode names must be non-empty strings without surrounding space"
            )
        if not isinstance(raw_mode, str):
            raise ValueError(f"action mode for {action!r} must be a string")
        try:
            validated[action] = MasuGateMode(raw_mode)
        except ValueError as exc:
            raise ValueError(f"unknown action mode for {action!r}: {raw_mode!r}") from exc
    return validated


def _action_owner_bindings(assembly: ProviderAssembly) -> dict[str, ActionOwnerBinding]:
    """Project certified deployment-assembly ownership into the HTTP assertion boundary."""

    modules = {module.module_id: module for module in assembly.modules}
    return {
        action: ActionOwnerBinding(
            provider_id=modules[assembled.effect_owner].identity.provider_id,
            position=assembled.position,
            connector_id=assembled.connector_id,
        )
        for action, assembled in assembly.actions.items()
    }


def build_app(
    *,
    dsn: str,
    policy_sources: Sequence[str],
    principals: Mapping[str, Mapping[str, Scalar]],
    token_principals: Mapping[str, str],
    mode: MasuGateMode = MasuGateMode.TRANSACTION,
    action_modes: Mapping[str, MasuGateMode] | None = None,
) -> FastAPI:
    """Build a low-level embedding/test stack from raw policy text.

    This compatibility API does not claim mandatory-policy-layer non-waivability;
    the production CLI and security-sensitive embedders use
    :func:`build_trusted_app`.  A deployment administrator who deliberately
    selects this raw API is outside the trusted profile boundary, just as one
    who disables MasuGate entirely is outside it.
    """

    certified_principals = _validated_principals(cast(Mapping[str, object], principals))
    certified_tokens = _validated_tokens(
        cast(Mapping[str, object], token_principals),
        set(certified_principals),
    )
    ledger = AsyncPostgresLedger(dsn)
    registry = ContractRegistry()
    ledger.install_contracts(registry)
    compiler = PolicyCompiler(registry, _principal_types(certified_principals))
    policies = PolicySet()
    for source in policy_sources:
        policies.add(compiler.compile(parse_policy(source)))
    runtime = AsyncPolicyRuntime(registry, policies)
    coordinator = AsyncGovernedCoordinator(
        registry,
        runtime,
        ledger,
        PrincipalRegistry(certified_principals),
        mode=mode,
        action_modes=action_modes,
    )
    return create_app(
        coordinator,
        ledger,
        certified_tokens,
        operator_principals={
            principal_id
            for principal_id, attributes in certified_principals.items()
            if attributes.get("masugate_operator") is True
        },
        lifespan_resource=ledger,
    )


def build_trusted_app(
    *,
    dsn: str,
    governance_profile: TrustedDeploymentProfile,
    owner_bundle_paths: Sequence[Path],
    disabled_owner_bundle_ids: Sequence[str],
    principals: Mapping[str, Mapping[str, Scalar]],
    token_principals: Mapping[str, str],
    mode: MasuGateMode = MasuGateMode.TRANSACTION,
    action_modes: Mapping[str, MasuGateMode] | None = None,
    compiled_operation_routes: CompiledOperationRoutes | None = None,
    connector_registry: ConnectorRegistry | None = None,
    artifact_store: SqliteArtifactStore | None = None,
) -> FastAPI:
    """Build the production stack through the non-waivable catalog boundary."""

    certified_principals = _validated_principals(cast(Mapping[str, object], principals))
    certified_tokens = _validated_tokens(
        cast(Mapping[str, object], token_principals),
        set(certified_principals),
    )
    assertion_principals = _action_assertion_principals(certified_principals)
    adapter_invocation_principals = _adapter_invocation_principals(certified_principals)
    trusted = load_trusted_catalog(
        governance_profile,
        owner_sources=owner_bundle_paths,
        disabled_bundle_ids=disabled_owner_bundle_ids,
    )
    ledger = AsyncPostgresLedger(dsn)
    assembly = assemble_provider_domain(
        trusted.catalog,
        (ledger.provider_module(),),
    )
    if (compiled_operation_routes is None) is not (connector_registry is None):
        raise ValueError(
            "compiled operation routes and connector registry must be configured together"
        )
    if artifact_store is not None and compiled_operation_routes is None:
        raise ValueError("artifact storage requires compiled operation routes")
    if compiled_operation_routes is not None:
        assert connector_registry is not None
        validate_compiled_operation_routes(compiled_operation_routes, assembly, connector_registry)
    registry = assembly.registry
    policies = compile_trusted_policy_set(
        trusted,
        registry,
        _principal_types(certified_principals),
    )
    runtime = AsyncPolicyRuntime(registry, policies)
    coordinator = AsyncGovernedCoordinator(
        registry,
        runtime,
        ledger,
        PrincipalRegistry(certified_principals),
        mode=mode,
        action_modes=action_modes,
    )
    return create_app(
        coordinator,
        ledger,
        certified_tokens,
        operator_principals={
            principal_id
            for principal_id, attributes in certified_principals.items()
            if attributes.get("masugate_operator") is True
        },
        lifespan_resource=ledger,
        action_owners=_action_owner_bindings(assembly),
        # The established header-only setting retains its public adapter integration
        # semantics. A separately certified adapter setting opts into the
        # stronger invocation envelope requirement.
        action_assertion_principals=assertion_principals,
        adapter_invocation_principals=adapter_invocation_principals,
        artifact_store=artifact_store,
        compiled_operation_routes=compiled_operation_routes,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the MasuGate governed-action daemon")
    parser.add_argument("--dsn", required=True, help="PostgreSQL connection string")
    parser.add_argument(
        "--governance-profile",
        required=True,
        help="Trusted deployment JSON profile pinning every mandatory bundle",
    )
    parser.add_argument(
        "--owner-bundle",
        action="append",
        default=[],
        help="Owner/configurable bundle path (repeatable)",
    )
    parser.add_argument(
        "--disable-owner-bundle",
        action="append",
        default=[],
        help="Owner bundle id to disable (mandatory ids are rejected)",
    )
    parser.add_argument("--principals", required=True, help="JSON id -> certified attributes")
    parser.add_argument("--tokens", required=True, help="JSON bearer token -> principal id")
    parser.add_argument(
        "--mode",
        choices=[str(mode) for mode in MasuGateMode],
        default=str(MasuGateMode.TRANSACTION),
    )
    parser.add_argument(
        "--action-modes",
        help="Optional JSON governed-action -> MasuGateMode overrides",
    )
    parser.add_argument(
        "--operation-pack",
        help="Trusted masugate.operation-pack.v1 JSON path",
    )
    parser.add_argument(
        "--operation-binding",
        help="Server-only masugate.operation-deployment-binding.v1 JSON path",
    )
    parser.add_argument(
        "--connector-registry",
        help="Trusted masugate.connector-registry.v2 JSON path",
    )
    parser.add_argument(
        "--artifact-store",
        help="Worker-owned SQLite path for bounded connector ecosystem staged payloads",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    return parser


def main() -> None:
    args = _parser().parse_args()
    principals_raw = _object_file(args.principals)
    principals = _validated_principals(principals_raw)
    tokens_raw = _object_file(args.tokens)
    tokens = _validated_tokens(tokens_raw, set(principals))
    governance_profile = load_deployment_profile(Path(cast(str, args.governance_profile)))
    action_modes = (
        _validated_action_modes(_object_file(args.action_modes))
        if args.action_modes is not None
        else None
    )
    operation_paths = (args.operation_pack, args.operation_binding, args.connector_registry)
    if any(path is not None for path in operation_paths) and any(
        path is None for path in operation_paths
    ):
        _parser().error(
            "--operation-pack, --operation-binding, and --connector-registry "
            "must be supplied together"
        )
    compiled_operation_routes: CompiledOperationRoutes | None = None
    connector_registry: ConnectorRegistry | None = None
    if args.operation_pack is not None:
        compiled_operation_routes = compile_operation_pack(
            load_operation_pack(
                _object_file(
                    cast(str, args.operation_pack),
                    max_bytes=DEFAULT_OPERATION_PACK_CANONICAL_BYTES,
                )
            ),
            load_deployment_binding(_object_file(cast(str, args.operation_binding))),
        )
        connector_registry = load_connector_registry(
            _object_file(cast(str, args.connector_registry))
        )
    artifact_store = (
        SqliteArtifactStore(cast(str, args.artifact_store))
        if args.artifact_store is not None
        else None
    )
    app = build_trusted_app(
        dsn=cast(str, args.dsn),
        governance_profile=governance_profile,
        owner_bundle_paths=tuple(Path(path) for path in cast(list[str], args.owner_bundle)),
        disabled_owner_bundle_ids=tuple(cast(list[str], args.disable_owner_bundle)),
        principals=principals,
        token_principals=tokens,
        mode=MasuGateMode(cast(str, args.mode)),
        action_modes=action_modes,
        compiled_operation_routes=compiled_operation_routes,
        connector_registry=connector_registry,
        artifact_store=artifact_store,
    )
    uvicorn.run(app, host=cast(str, args.host), port=cast(int, args.port))


if __name__ == "__main__":  # pragma: no cover - console entry point
    main()
