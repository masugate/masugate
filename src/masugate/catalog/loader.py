"""Dependency-free, fail-closed loader for policy-bundle manifests."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import NoReturn, cast

from masugate.catalog.model import (
    BundleMode,
    CertifiedInputRequirement,
    EffectRequirement,
    LoadedPolicy,
    PolicyBundle,
    PolicyCatalog,
    PolicyDriver,
    PolicyEnforcement,
    PolicyEnforcementKind,
    PolicyGovernance,
    PolicyLayer,
    PolicyLimitation,
    RequirementResolution,
    ResolutionKind,
    ViewRequirement,
)
from masugate.contracts import (
    ContractRegistry,
    EffectContract,
    GovernanceViewContract,
    ReservationViewKind,
    ResourceSession,
)
from masugate.errors import PolicySyntaxError, PolicyValidationError
from masugate.language import parse_policy
from masugate.language.ast import (
    BinaryExpr,
    CallExpr,
    Expr,
    LiteralExpr,
    PathExpr,
    PolicyDefinition,
    Rule,
    UnaryExpr,
)
from masugate.language.compiler import PolicyCompiler
from masugate.language.serialize import dumps
from masugate.model import (
    ConsistencyGuarantee,
    Duration,
    PendingResolutionPlan,
    ResourceFootprint,
    Scalar,
    TypeName,
)

_SCHEMA_VERSION = 1
_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$")
_CNAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_ACTION = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
_DOTTED = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CAPABILITY = re.compile(r"^[a-z][a-z0-9-]{0,127}$", re.ASCII)
_LAYER_RANK = {
    PolicyLayer.PLATFORM_SAFETY: 0,
    PolicyLayer.DEPLOYMENT_REGULATORY: 1,
    PolicyLayer.OWNER: 2,
}
_DRIVER_LAYER = {
    PolicyDriver.ADVERSARIAL: PolicyLayer.PLATFORM_SAFETY,
    PolicyDriver.CUSTOMER_INTENT: PolicyLayer.OWNER,
    PolicyDriver.REFERENCE_REGULATORY: PolicyLayer.DEPLOYMENT_REGULATORY,
}


class CatalogValidationError(ValueError):
    """The bundle is malformed, inconsistent, or unsafe to load."""


def _error(context: str, message: str) -> NoReturn:
    raise CatalogValidationError(f"{context}: {message}")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _error("JSON", f"duplicate object key {key!r}")
        result[key] = value
    return result


def _object(
    value: object,
    context: str,
    *,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
) -> dict[str, object]:
    if not isinstance(value, dict):
        _error(context, "must be an object")
    obj = cast(dict[str, object], value)
    keys = frozenset(obj)
    missing = required - keys
    unknown = keys - required - optional
    if missing:
        _error(context, f"missing fields {sorted(missing)}")
    if unknown:
        _error(context, f"unknown fields {sorted(unknown)}")
    return obj


def _list(value: object, context: str, *, nonempty: bool = False) -> list[object]:
    if not isinstance(value, list):
        _error(context, "must be an array")
    items = cast(list[object], value)
    if nonempty and not items:
        _error(context, "must not be empty")
    return items


def _string(value: object, context: str, *, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value:
        _error(context, "must be a non-empty string")
    if pattern is not None and pattern.fullmatch(value) is None:
        _error(context, f"invalid value {value!r}")
    return value


def _enum[T: str](value: object, enum_type: type[T], context: str) -> T:
    if not isinstance(value, str):
        _error(context, "must be a string")
    try:
        return enum_type(value)
    except ValueError:
        _error(context, f"unsupported value {value!r}")


def _strings(value: object, context: str) -> tuple[str, ...]:
    result = tuple(
        _string(item, f"{context}[{index}]") for index, item in enumerate(_list(value, context))
    )
    if len(set(result)) != len(result):
        _error(context, "contains duplicates")
    return result


def _resolution(value: object, context: str) -> RequirementResolution:
    base = _object(
        value,
        context,
        required=frozenset({"kind"}),
        optional=frozenset({"capability", "id", "reason"}),
    )
    kind = _enum(base["kind"], ResolutionKind, f"{context}.kind")
    if kind is ResolutionKind.PROVIDER:
        provider = _object(
            base,
            context,
            required=frozenset({"kind", "capability"}),
        )
        capability = _string(provider["capability"], f"{context}.capability", pattern=_CAPABILITY)
        return RequirementResolution(kind=kind, capability=capability)
    gap = _object(
        base,
        context,
        required=frozenset({"kind", "id", "reason"}),
    )
    gap_id = _string(gap["id"], f"{context}.id", pattern=_ID)
    reason = _string(gap["reason"], f"{context}.reason")
    return RequirementResolution(kind=kind, gap_id=gap_id, reason=reason)


def _type(value: object, context: str) -> TypeName:
    return _enum(value, TypeName, context)


def _effect(value: object, context: str) -> EffectRequirement:
    obj = _object(
        value,
        context,
        required=frozenset(
            {
                "action",
                "argument_types",
                "owner",
                "required_guarantee",
                "consumable_arg",
                "resolution",
            }
        ),
    )
    action = _string(obj["action"], f"{context}.action", pattern=_ACTION)
    raw_args = _object(
        obj["argument_types"],
        f"{context}.argument_types",
        required=frozenset(),
        optional=frozenset(cast(Mapping[str, object], obj["argument_types"]).keys())
        if isinstance(obj["argument_types"], dict)
        else frozenset(),
    )
    argument_types: dict[str, TypeName] = {}
    for name, raw_type in raw_args.items():
        _string(name, f"{context}.argument_types key", pattern=_CNAME)
        argument_types[name] = _type(raw_type, f"{context}.argument_types.{name}")
    consumable_raw = obj["consumable_arg"]
    consumable: str | None
    if consumable_raw is None:
        consumable = None
    else:
        consumable = _string(consumable_raw, f"{context}.consumable_arg", pattern=_CNAME)
        if argument_types.get(consumable) is not TypeName.INT:
            _error(context, "consumable_arg must name an Int argument")
    return EffectRequirement(
        action=action,
        argument_types=MappingProxyType(argument_types),
        owner=_string(obj["owner"], f"{context}.owner", pattern=_ID),
        required_guarantee=_enum(
            obj["required_guarantee"],
            ConsistencyGuarantee,
            f"{context}.required_guarantee",
        ),
        consumable_arg=consumable,
        resolution=_resolution(obj["resolution"], f"{context}.resolution"),
    )


def _view(value: object, context: str) -> ViewRequirement:
    obj = _object(
        value,
        context,
        required=frozenset(
            {
                "name",
                "argument_types",
                "return_type",
                "owner",
                "consistency",
                "max_latency_ms",
                "bounded",
                "reservation_kind",
                "resolution",
            }
        ),
    )
    raw_latency = obj["max_latency_ms"]
    if type(raw_latency) is not int or raw_latency <= 0:
        _error(f"{context}.max_latency_ms", "must be a positive integer")
    if obj["bounded"] is not True:
        _error(f"{context}.bounded", "policy-callable views must be bounded")
    argument_types = tuple(
        _type(item, f"{context}.argument_types[{index}]")
        for index, item in enumerate(_list(obj["argument_types"], f"{context}.argument_types"))
    )
    return ViewRequirement(
        name=_string(obj["name"], f"{context}.name", pattern=_DOTTED),
        argument_types=argument_types,
        return_type=_type(obj["return_type"], f"{context}.return_type"),
        owner=_string(obj["owner"], f"{context}.owner", pattern=_ID),
        consistency=_string(obj["consistency"], f"{context}.consistency", pattern=_ID),
        max_latency_ms=raw_latency,
        bounded=True,
        reservation_kind=_enum(
            obj["reservation_kind"], ReservationViewKind, f"{context}.reservation_kind"
        ),
        resolution=_resolution(obj["resolution"], f"{context}.resolution"),
    )


def _certified_input(value: object, context: str) -> CertifiedInputRequirement:
    obj = _object(
        value,
        context,
        required=frozenset({"name", "type", "resolution"}),
    )
    name = _string(obj["name"], f"{context}.name", pattern=_DOTTED)
    if not name.startswith("certified.") or name.count(".") != 1:
        _error(f"{context}.name", "must be a flat certified.<name> path")
    return CertifiedInputRequirement(
        name=name,
        value_type=_type(obj["type"], f"{context}.type"),
        resolution=_resolution(obj["resolution"], f"{context}.resolution"),
    )


def _governance(
    value: object,
    context: str,
    *,
    effect: EffectRequirement,
    layer: PolicyLayer,
) -> PolicyGovernance:
    obj = _object(
        value,
        context,
        required=frozenset(
            {
                "driver",
                "coordination_domain",
                "provider_owner",
                "connector_id",
                "pending_plan",
                "enforcement",
                "out_of_scope_classes",
            }
        ),
    )
    driver = _enum(obj["driver"], PolicyDriver, f"{context}.driver")
    expected_layer = _DRIVER_LAYER[driver]
    if layer is not expected_layer:
        _error(
            context,
            f"driver {driver.value!r} requires bundle layer {expected_layer.value!r}",
        )
    provider_owner = _string(obj["provider_owner"], f"{context}.provider_owner", pattern=_ID)
    if provider_owner != effect.owner:
        _error(
            context,
            "provider_owner does not match the governed action effect owner",
        )
    raw_connector = obj["connector_id"]
    connector_id = (
        None
        if raw_connector is None
        else _string(raw_connector, f"{context}.connector_id", pattern=_ID)
    )
    raw_out_of_scope = _list(
        obj["out_of_scope_classes"], f"{context}.out_of_scope_classes", nonempty=True
    )
    out_of_scope = tuple(
        _string(item, f"{context}.out_of_scope_classes[{index}]", pattern=_ID)
        for index, item in enumerate(raw_out_of_scope)
    )
    if len(set(out_of_scope)) != len(out_of_scope):
        _error(f"{context}.out_of_scope_classes", "contains duplicates")
    enforcement = _enforcement(obj["enforcement"], f"{context}.enforcement")
    return PolicyGovernance(
        driver=driver,
        coordination_domain=_string(
            obj["coordination_domain"], f"{context}.coordination_domain", pattern=_ID
        ),
        provider_owner=provider_owner,
        connector_id=connector_id,
        pending_plan=_enum(obj["pending_plan"], PendingResolutionPlan, f"{context}.pending_plan"),
        enforcement=enforcement,
        out_of_scope_classes=out_of_scope,
    )


def _enforcement(value: object, context: str) -> PolicyEnforcement:
    base = _object(
        value,
        context,
        required=frozenset({"kind"}),
        optional=frozenset({"id", "reason"}),
    )
    kind = _enum(base["kind"], PolicyEnforcementKind, f"{context}.kind")
    if kind is PolicyEnforcementKind.EXECUTABLE:
        _object(value, context, required=frozenset({"kind"}))
        return PolicyEnforcement(kind=kind)
    gap = _object(value, context, required=frozenset({"kind", "id", "reason"}))
    return PolicyEnforcement(
        kind=kind,
        gap_id=_string(gap["id"], f"{context}.id", pattern=_ID),
        reason=_string(gap["reason"], f"{context}.reason"),
    )


def _walk(
    expression: Expr,
    calls: set[str],
    certified: set[str],
    *,
    inside_view_argument: bool = False,
) -> None:
    if isinstance(expression, CallExpr):
        calls.add(expression.name)
        for argument in expression.arguments:
            _walk(argument, calls, certified, inside_view_argument=True)
    elif isinstance(expression, PathExpr):
        if expression.parts and expression.parts[0] == "certified":
            if len(expression.parts) != 2:
                _error("policy", "certified paths must contain exactly two segments")
            if inside_view_argument:
                _error("policy", "view-call scopes cannot depend on certified inputs")
            certified.add(".".join(expression.parts))
    elif isinstance(expression, UnaryExpr):
        _walk(
            expression.operand,
            calls,
            certified,
            inside_view_argument=inside_view_argument,
        )
    elif isinstance(expression, BinaryExpr):
        _walk(
            expression.left,
            calls,
            certified,
            inside_view_argument=inside_view_argument,
        )
        _walk(
            expression.right,
            calls,
            certified,
            inside_view_argument=inside_view_argument,
        )


def _sample(value_type: TypeName) -> Scalar | Duration:
    if value_type is TypeName.BOOL:
        return False
    if value_type is TypeName.INT:
        return 0
    if value_type is TypeName.STRING:
        return ""
    return Duration(0)


def _replace_certified(
    expression: Expr,
    certified_types: Mapping[str, TypeName],
) -> Expr:
    if isinstance(expression, PathExpr) and expression.parts[0] == "certified":
        name = ".".join(expression.parts)
        try:
            return LiteralExpr(_sample(certified_types[name]))
        except KeyError as exc:  # guarded by requirement-set validation
            raise CatalogValidationError(f"policy: undeclared certified input {name!r}") from exc
    if isinstance(expression, CallExpr):
        return CallExpr(
            expression.name,
            tuple(
                _replace_certified(argument, certified_types) for argument in expression.arguments
            ),
        )
    if isinstance(expression, UnaryExpr):
        return UnaryExpr(
            expression.operator,
            _replace_certified(expression.operand, certified_types),
        )
    if isinstance(expression, BinaryExpr):
        return BinaryExpr(
            expression.operator,
            _replace_certified(expression.left, certified_types),
            _replace_certified(expression.right, certified_types),
        )
    return expression


def _static_scope(arguments: tuple[Scalar | Duration, ...]) -> str:
    return "catalog:static-validation"


def _static_resolver(
    session: ResourceSession,
    arguments: tuple[Scalar | Duration, ...],
    scope: str,
) -> tuple[Scalar, int]:
    return False, 1


def _validate_policy_semantics(
    definition: PolicyDefinition,
    *,
    effects: tuple[EffectRequirement, ...],
    views: tuple[ViewRequirement, ...],
    principal_attributes: Mapping[str, TypeName],
    certified_types: Mapping[str, TypeName],
    context: str,
) -> None:
    registry = ContractRegistry()
    for view in views:
        registry.register_view(
            GovernanceViewContract(
                name=view.name,
                argument_types=view.argument_types,
                return_type=view.return_type,
                owner=view.owner,
                consistency=view.consistency,
                max_latency_ms=view.max_latency_ms,
                bounded=view.bounded,
                scope_resolver=_static_scope,
                resolver=_static_resolver,
                reservation_kind=view.reservation_kind,
            )
        )
    for effect in effects:
        registry.register_effect(
            EffectContract(
                action=effect.action,
                argument_types=dict(effect.argument_types),
                owner=effect.owner,
                required_guarantee=effect.required_guarantee,
                footprint_resolver=lambda request: ResourceFootprint(),
                executor=lambda session, request: {},
                consumable_arg=effect.consumable_arg,
            )
        )
    transformed = PolicyDefinition(
        name=definition.name,
        action=definition.action,
        rules=tuple(
            Rule(
                effect=rule.effect,
                rule_id=rule.rule_id,
                condition=(
                    _replace_certified(rule.condition, certified_types)
                    if rule.condition is not None
                    else None
                ),
            )
            for rule in definition.rules
        ),
    )
    try:
        PolicyCompiler(
            registry,
            principal_attributes=dict(principal_attributes),
        ).compile(transformed)
    except PolicyValidationError as exc:
        raise CatalogValidationError(f"{context}.source: policy/contract mismatch: {exc}") from exc


def _safe_policy_path(root: Path, raw_source: object, context: str) -> tuple[str, Path]:
    source = _string(raw_source, context)
    if "\\" in source:
        _error(context, "must use POSIX separators")
    relative = PurePosixPath(source)
    if relative.is_absolute() or ".." in relative.parts or relative.suffix != ".pvl":
        _error(context, "must be a relative .pvl path without '..'")
    resolved = root.joinpath(*relative.parts).resolve()
    if not resolved.is_relative_to(root) or not resolved.is_file():
        _error(context, "source is missing, not a file, or escapes the bundle root")
    return source, resolved


def _unique[T](items: tuple[T, ...], key: Callable[[T], object], context: str) -> None:
    seen: set[object] = set()
    for item in items:
        value = key(item)
        if value in seen:
            _error(context, f"duplicate {value!r}")
        seen.add(value)


def load_bundle(path: Path) -> PolicyBundle:
    """Load and fully validate one ``bundle.json`` without importing providers."""

    manifest = path / "bundle.json" if path.is_dir() else path
    root = manifest.parent.resolve()
    try:
        raw_text = manifest.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise CatalogValidationError(f"cannot read {manifest}: {exc}") from exc
    try:
        decoded = json.loads(raw_text, object_pairs_hook=_unique_object)
    except json.JSONDecodeError as exc:
        raise CatalogValidationError(f"invalid JSON in {manifest}: {exc}") from exc
    top = _object(
        decoded,
        "bundle manifest",
        required=frozenset({"schema_version", "bundle", "contracts", "policies"}),
    )
    if type(top["schema_version"]) is not int or top["schema_version"] != _SCHEMA_VERSION:
        _error("schema_version", f"must equal {_SCHEMA_VERSION}")
    bundle_raw = _object(
        top["bundle"],
        "bundle",
        required=frozenset({"id", "version", "layer", "mode"}),
    )
    bundle_id = _string(bundle_raw["id"], "bundle.id", pattern=_ID)
    version = _string(bundle_raw["version"], "bundle.version", pattern=_VERSION)
    layer = _enum(bundle_raw["layer"], PolicyLayer, "bundle.layer")
    mode = _enum(bundle_raw["mode"], BundleMode, "bundle.mode")
    expected_mode = BundleMode.CONFIGURABLE if layer is PolicyLayer.OWNER else BundleMode.MANDATORY
    if mode is not expected_mode:
        _error("bundle", f"layer {layer} requires mode {expected_mode}")

    contracts = _object(
        top["contracts"],
        "contracts",
        required=frozenset({"principal_attributes", "effects", "views", "certified_inputs"}),
    )
    raw_principal_attributes = _object(
        contracts["principal_attributes"],
        "contracts.principal_attributes",
        required=frozenset(),
        optional=(
            frozenset(cast(Mapping[str, object], contracts["principal_attributes"]).keys())
            if isinstance(contracts["principal_attributes"], dict)
            else frozenset()
        ),
    )
    principal_attributes: dict[str, TypeName] = {}
    for name, raw_type in raw_principal_attributes.items():
        _string(name, "contracts.principal_attributes key", pattern=_CNAME)
        if name == "id":
            _error("contracts.principal_attributes", "id is built in and cannot be redeclared")
        principal_attributes[name] = _type(raw_type, f"contracts.principal_attributes.{name}")
    effects = tuple(
        _effect(item, f"contracts.effects[{index}]")
        for index, item in enumerate(
            _list(contracts["effects"], "contracts.effects", nonempty=True)
        )
    )
    views = tuple(
        _view(item, f"contracts.views[{index}]")
        for index, item in enumerate(_list(contracts["views"], "contracts.views"))
    )
    certified_requirements = tuple(
        _certified_input(item, f"contracts.certified_inputs[{index}]")
        for index, item in enumerate(
            _list(contracts["certified_inputs"], "contracts.certified_inputs")
        )
    )
    _unique(effects, lambda item: item.action, "contracts.effects")
    _unique(views, lambda item: item.name, "contracts.views")
    _unique(
        certified_requirements,
        lambda item: item.name,
        "contracts.certified_inputs",
    )
    effect_names = {item.action for item in effects}
    view_names = {item.name for item in views}
    certified_names = {item.name for item in certified_requirements}
    certified_types = {item.name: item.value_type for item in certified_requirements}

    loaded: list[LoadedPolicy] = []
    used_sources: set[str] = set()
    for index, raw_policy in enumerate(_list(top["policies"], "policies", nonempty=True)):
        context = f"policies[{index}]"
        obj = _object(
            raw_policy,
            context,
            required=frozenset(
                {
                    "id",
                    "version",
                    "source",
                    "semantic_sha256",
                    "action",
                    "required_views",
                    "certified_inputs",
                    "limitations",
                }
            ),
            optional=frozenset({"governance"}),
        )
        policy_id = _string(obj["id"], f"{context}.id", pattern=_CNAME)
        policy_version = _string(obj["version"], f"{context}.version", pattern=_VERSION)
        source, source_path = _safe_policy_path(root, obj["source"], f"{context}.source")
        if source in used_sources:
            _error("policies", f"duplicate source {source!r}")
        used_sources.add(source)
        try:
            source_text = source_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise CatalogValidationError(f"cannot read policy source {source}: {exc}") from exc
        try:
            definition = parse_policy(source_text)
        except PolicySyntaxError as exc:
            raise CatalogValidationError(f"{context}.source: invalid policy: {exc}") from exc
        action = _string(obj["action"], f"{context}.action", pattern=_ACTION)
        if definition.name != policy_id or definition.action != action:
            _error(context, "source policy name/action does not match manifest")
        if action not in effect_names:
            _error(context, f"action {action!r} has no effect requirement")
        governance = (
            None
            if "governance" not in obj
            else _governance(
                obj["governance"],
                f"{context}.governance",
                effect=next(effect for effect in effects if effect.action == action),
                layer=layer,
            )
        )
        required_views = _strings(obj["required_views"], f"{context}.required_views")
        required_certified = _strings(obj["certified_inputs"], f"{context}.certified_inputs")
        calls: set[str] = set()
        certified_paths: set[str] = set()
        for rule in definition.rules:
            if rule.condition is not None:
                _walk(rule.condition, calls, certified_paths)
        if set(required_views) != calls:
            _error(
                context,
                f"required_views {sorted(required_views)} != source calls {sorted(calls)}",
            )
        if set(required_certified) != certified_paths:
            _error(
                context,
                "certified_inputs "
                f"{sorted(required_certified)} != source paths {sorted(certified_paths)}",
            )
        missing_views = set(required_views) - view_names
        missing_certified = set(required_certified) - certified_names
        if missing_views or missing_certified:
            _error(
                context,
                f"undeclared requirements views={sorted(missing_views)} "
                f"certified={sorted(missing_certified)}",
            )
        _validate_policy_semantics(
            definition,
            effects=effects,
            views=views,
            principal_attributes=principal_attributes,
            certified_types=certified_types,
            context=context,
        )
        digest = _string(obj["semantic_sha256"], f"{context}.semantic_sha256", pattern=_SHA256)
        actual_digest = hashlib.sha256(dumps(definition).encode("utf-8")).hexdigest()
        if digest != actual_digest:
            _error(f"{context}.semantic_sha256", "does not match canonical AST")
        limitations_raw = _list(obj["limitations"], f"{context}.limitations", nonempty=True)
        limitations = tuple(
            PolicyLimitation(
                class_name=_string(
                    limitation["class"], f"{context}.limitations[{limit_index}].class", pattern=_ID
                ),
                statement=_string(
                    limitation["statement"],
                    f"{context}.limitations[{limit_index}].statement",
                ),
            )
            for limit_index, raw_limitation in enumerate(limitations_raw)
            for limitation in [
                _object(
                    raw_limitation,
                    f"{context}.limitations[{limit_index}]",
                    required=frozenset({"class", "statement"}),
                )
            ]
        )
        _unique(limitations, lambda item: item.class_name, f"{context}.limitations")
        loaded.append(
            LoadedPolicy(
                policy_id=policy_id,
                version=policy_version,
                source=source,
                semantic_sha256=digest,
                action=action,
                required_views=tuple(sorted(required_views)),
                certified_inputs=tuple(sorted(required_certified)),
                limitations=limitations,
                governance=governance,
                definition=definition,
                source_text=source_text,
            )
        )
    policies = tuple(sorted(loaded, key=lambda policy: policy.policy_id))
    _unique(policies, lambda item: item.policy_id, "policies")
    canonical_manifest = json.dumps(decoded, sort_keys=True, separators=(",", ":"))
    bundle_digest = hashlib.sha256(canonical_manifest.encode("utf-8")).hexdigest()
    return PolicyBundle(
        schema_version=_SCHEMA_VERSION,
        bundle_id=bundle_id,
        version=version,
        layer=layer,
        mode=mode,
        principal_attributes=MappingProxyType(principal_attributes),
        effects=tuple(sorted(effects, key=lambda item: item.action)),
        views=tuple(sorted(views, key=lambda item: item.name)),
        certified_inputs=tuple(sorted(certified_requirements, key=lambda item: item.name)),
        policies=policies,
        digest=bundle_digest,
        root=root,
    )


def load_catalog(paths: Iterable[Path]) -> PolicyCatalog:
    """Load bundles and deterministically reject cross-bundle ambiguity."""

    bundles = tuple(
        sorted(
            (load_bundle(path) for path in paths),
            key=lambda bundle: (_LAYER_RANK[bundle.layer], bundle.bundle_id),
        )
    )
    if not bundles:
        raise CatalogValidationError("catalog must contain at least one bundle")
    _unique(bundles, lambda item: item.bundle_id, "catalog bundles")
    _unique(
        tuple(policy for bundle in bundles for policy in bundle.policies),
        lambda item: item.policy_id,
        "catalog policies",
    )
    _reject_contract_conflicts(bundles, lambda bundle: bundle.effects, lambda item: item.action)
    _reject_contract_conflicts(bundles, lambda bundle: bundle.views, lambda item: item.name)
    _reject_contract_conflicts(
        bundles,
        lambda bundle: bundle.certified_inputs,
        lambda item: item.name,
    )
    return PolicyCatalog(bundles=bundles)


def _reject_contract_conflicts[T](
    bundles: tuple[PolicyBundle, ...],
    requirements: Callable[[PolicyBundle], tuple[T, ...]],
    key: Callable[[T], str],
) -> None:
    seen: dict[str, T] = {}
    for bundle in bundles:
        for requirement in requirements(bundle):
            name = key(requirement)
            previous = seen.setdefault(name, requirement)
            if previous != requirement:
                _error("catalog contracts", f"conflicting declaration for {name!r}")
