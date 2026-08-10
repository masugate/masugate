"""Trusted mandatory/owner catalog construction.

The trust boundary is deliberately asymmetric.  A deployment-controlled
``TrustedDeploymentProfile`` pins every platform-safety and regulatory bundle
by identity and digest.  Owner configuration is supplied through a separate
argument and may only contain owner/configurable bundles.  File ownership and
the ability to disable MasuGate itself remain deployment concerns; once this
loader is entered, owner input cannot remove or impersonate a mandatory layer.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import NoReturn, cast

from masugate.catalog.loader import CatalogValidationError, load_catalog
from masugate.catalog.model import (
    BundleMode,
    LoadedPolicy,
    PolicyBundle,
    PolicyCatalog,
    PolicyLayer,
)
from masugate.contracts import ContractRegistry
from masugate.language.compiler import PolicyCompiler, compiled_policy_version
from masugate.language.serialize import dumps
from masugate.model import PolicyProvenance, TypeName
from masugate.policy import PolicySet

_IDENTITY = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$", re.ASCII)
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$", re.ASCII)
_SHA256 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_MANDATORY_LAYERS = frozenset({PolicyLayer.PLATFORM_SAFETY, PolicyLayer.DEPLOYMENT_REGULATORY})


def _fail(message: str) -> NoReturn:
    raise CatalogValidationError(f"trusted catalog: {message}")


def _canonical_identity(value: str, field: str, pattern: re.Pattern[str]) -> None:
    if type(value) is not str or pattern.fullmatch(value) is None:
        _fail(f"{field} is not a canonical identity")


@dataclass(frozen=True)
class MandatoryBundlePin:
    """Content pin for one non-waivable bundle in a trusted profile."""

    bundle_id: str
    version: str
    layer: PolicyLayer
    digest: str

    def __post_init__(self) -> None:
        _canonical_identity(self.bundle_id, "mandatory bundle id", _IDENTITY)
        _canonical_identity(self.version, "mandatory bundle version", _VERSION)
        if type(self.layer) is not PolicyLayer or self.layer not in _MANDATORY_LAYERS:
            _fail("mandatory bundle pin must use a mandatory layer")
        _canonical_identity(self.digest, "mandatory bundle digest", _SHA256)


@dataclass(frozen=True)
class TrustedDeploymentProfile:
    """Deployment-owned sources and exact mandatory bundle requirements."""

    profile_id: str
    version: str
    mandatory_sources: tuple[Path, ...]
    required_bundles: tuple[MandatoryBundlePin, ...]

    def __post_init__(self) -> None:
        _canonical_identity(self.profile_id, "profile id", _IDENTITY)
        _canonical_identity(self.version, "profile version", _VERSION)
        if not self.mandatory_sources:
            _fail("deployment profile must name at least one mandatory source")
        if not self.required_bundles:
            _fail("deployment profile must pin at least one mandatory bundle")
        source_roots = tuple(_source_root(path) for path in self.mandatory_sources)
        if len(set(source_roots)) != len(source_roots):
            _fail("deployment profile contains duplicate mandatory sources")
        ids = [pin.bundle_id for pin in self.required_bundles]
        if len(set(ids)) != len(ids):
            _fail("deployment profile contains duplicate mandatory bundle pins")

    @property
    def digest(self) -> str:
        payload = {
            "profile_id": self.profile_id,
            "version": self.version,
            "required_bundles": [
                {
                    "bundle_id": pin.bundle_id,
                    "digest": pin.digest,
                    "layer": pin.layer.value,
                    "version": pin.version,
                }
                for pin in sorted(self.required_bundles, key=lambda item: item.bundle_id)
            ],
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class TrustedPolicyCatalog:
    """Catalog proven to contain the profile's exact mandatory bundle set."""

    catalog: PolicyCatalog
    profile_id: str
    profile_version: str
    profile_digest: str

    @property
    def bundles(self) -> tuple[PolicyBundle, ...]:
        return self.catalog.bundles

    @property
    def policies(self) -> tuple[LoadedPolicy, ...]:
        return self.catalog.policies


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"deployment profile contains duplicate JSON key {key!r}")
        result[key] = value
    return result


def _closed_object(
    value: object,
    context: str,
    required: frozenset[str],
) -> dict[str, object]:
    if not isinstance(value, dict) or any(type(key) is not str for key in value):
        _fail(f"{context} must be an object")
    record = cast(dict[str, object], value)
    missing = required - set(record)
    unknown = set(record) - required
    if missing:
        _fail(f"{context} is missing fields {sorted(missing)}")
    if unknown:
        _fail(f"{context} has unknown fields {sorted(unknown)}")
    return record


def _profile_string(value: object, context: str, pattern: re.Pattern[str]) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        _fail(f"{context} is invalid")
    return value


def _profile_source(root: Path, value: object, context: str) -> Path:
    if type(value) is not str or "\\" in value:
        _fail(f"{context} must be a relative POSIX path")
    relative = PurePosixPath(value)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        _fail(f"{context} must be a relative path without '..'")
    resolved = root.joinpath(*relative.parts).resolve()
    if not resolved.is_relative_to(root):
        _fail(f"{context} escapes the deployment profile root")
    return resolved


def load_deployment_profile(path: Path) -> TrustedDeploymentProfile:
    """Load one strict deployment-owned mandatory-bundle profile."""

    manifest = path.resolve()
    try:
        raw = json.loads(
            manifest.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_json_object,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CatalogValidationError(f"cannot load trusted deployment profile: {exc}") from exc
    top = _closed_object(
        raw,
        "deployment profile",
        frozenset({"schema_version", "profile", "mandatory_bundles"}),
    )
    if type(top["schema_version"]) is not int or top["schema_version"] != 1:
        _fail("deployment profile schema_version must equal 1")
    profile = _closed_object(
        top["profile"],
        "deployment profile identity",
        frozenset({"id", "version"}),
    )
    entries = top["mandatory_bundles"]
    if not isinstance(entries, list) or not entries:
        _fail("deployment profile mandatory_bundles must be a non-empty array")
    sources: list[Path] = []
    pins: list[MandatoryBundlePin] = []
    for index, value in enumerate(cast(list[object], entries)):
        context = f"deployment profile mandatory_bundles[{index}]"
        entry = _closed_object(
            value,
            context,
            frozenset({"id", "version", "layer", "digest", "source"}),
        )
        try:
            layer = PolicyLayer(_profile_string(entry["layer"], f"{context}.layer", _IDENTITY))
        except ValueError as exc:
            raise CatalogValidationError(f"trusted catalog: {context}.layer is invalid") from exc
        pins.append(
            MandatoryBundlePin(
                bundle_id=_profile_string(entry["id"], f"{context}.id", _IDENTITY),
                version=_profile_string(entry["version"], f"{context}.version", _VERSION),
                layer=layer,
                digest=_profile_string(entry["digest"], f"{context}.digest", _SHA256),
            )
        )
        sources.append(_profile_source(manifest.parent, entry["source"], f"{context}.source"))
    return TrustedDeploymentProfile(
        profile_id=_profile_string(profile["id"], "deployment profile id", _IDENTITY),
        version=_profile_string(profile["version"], "deployment profile version", _VERSION),
        mandatory_sources=tuple(sources),
        required_bundles=tuple(pins),
    )


def _source_root(path: Path) -> Path:
    resolved = path.resolve()
    return resolved if resolved.is_dir() else resolved.parent


def _validate_mandatory_bundle(
    bundle: PolicyBundle,
    pin: MandatoryBundlePin,
) -> None:
    if bundle.mode is not BundleMode.MANDATORY or bundle.layer not in _MANDATORY_LAYERS:
        _fail(f"mandatory source {bundle.root} declared a configurable/owner bundle")
    actual = (bundle.bundle_id, bundle.version, bundle.layer, bundle.digest)
    expected = (pin.bundle_id, pin.version, pin.layer, pin.digest)
    if actual != expected:
        _fail(f"mandatory bundle {pin.bundle_id!r} does not match its trusted pin")


def load_trusted_catalog(
    profile: TrustedDeploymentProfile,
    *,
    owner_sources: Iterable[Path] = (),
    disabled_bundle_ids: Iterable[str] = (),
) -> TrustedPolicyCatalog:
    """Load mandatory and owner channels without granting owner substitution.

    Mandatory sources come exclusively from ``profile``.  Owner input can add
    configurable bundles and can disable only those owner bundles; attempting
    to disable, replace, relabel, or shadow a mandatory identity fails startup.
    """

    owner_paths = tuple(owner_sources)
    mandatory_roots = {_source_root(path) for path in profile.mandatory_sources}
    owner_roots = {_source_root(path) for path in owner_paths}
    if mandatory_roots & owner_roots:
        _fail("one source cannot occupy both mandatory and owner channels")
    if len(owner_roots) != len(owner_paths):
        _fail("owner configuration contains duplicate sources")

    catalog = load_catalog((*profile.mandatory_sources, *owner_paths))
    by_root = {bundle.root: bundle for bundle in catalog.bundles}
    mandatory = tuple(by_root[root] for root in mandatory_roots if root in by_root)
    if len(mandatory) != len(mandatory_roots):
        _fail("a mandatory source did not produce exactly one bundle")

    pins = {pin.bundle_id: pin for pin in profile.required_bundles}
    loaded_ids = {bundle.bundle_id for bundle in mandatory}
    missing = set(pins) - loaded_ids
    unpinned = loaded_ids - set(pins)
    if missing:
        _fail(f"deployment profile is missing required mandatory bundles {sorted(missing)}")
    if unpinned:
        _fail(f"deployment profile contains unpinned mandatory bundles {sorted(unpinned)}")
    for bundle in mandatory:
        _validate_mandatory_bundle(bundle, pins[bundle.bundle_id])

    owners = tuple(bundle for bundle in catalog.bundles if bundle.root in owner_roots)
    if len(owners) != len(owner_roots):
        _fail("an owner source did not produce exactly one bundle")
    for bundle in owners:
        if bundle.layer is not PolicyLayer.OWNER or bundle.mode is not BundleMode.CONFIGURABLE:
            _fail(f"owner source {bundle.root} attempted to declare a mandatory layer")
        if bundle.bundle_id in pins:
            _fail(f"owner bundle shadows mandatory id {bundle.bundle_id!r}")

    disabled = tuple(disabled_bundle_ids)
    for bundle_id in disabled:
        _canonical_identity(bundle_id, "disabled bundle id", _IDENTITY)
    if len(set(disabled)) != len(disabled):
        _fail("owner configuration contains duplicate disable entries")
    mandatory_disabled = set(disabled) & set(pins)
    if mandatory_disabled:
        _fail(f"owner configuration cannot disable mandatory bundles {sorted(mandatory_disabled)}")
    owner_ids = {bundle.bundle_id for bundle in owners}
    unknown_disabled = set(disabled) - owner_ids
    if unknown_disabled:
        _fail(f"owner configuration disables unknown bundles {sorted(unknown_disabled)}")

    active = tuple(
        bundle
        for bundle in catalog.bundles
        if bundle.layer is not PolicyLayer.OWNER or bundle.bundle_id not in set(disabled)
    )
    return TrustedPolicyCatalog(
        catalog=PolicyCatalog(bundles=active),
        profile_id=profile.profile_id,
        profile_version=profile.version,
        profile_digest=profile.digest,
    )


def compile_trusted_policy_set(
    trusted: TrustedPolicyCatalog,
    registry: ContractRegistry,
    principal_attributes: Mapping[str, TypeName],
) -> PolicySet:
    """Compile a trusted catalog and attach complete layer provenance."""

    required_attributes: dict[str, TypeName] = {}
    for bundle in trusted.bundles:
        for name, value_type in bundle.principal_attributes.items():
            previous = required_attributes.setdefault(name, value_type)
            if previous is not value_type:
                _fail(f"principal attribute {name!r} has conflicting bundle declarations")
    for name, value_type in required_attributes.items():
        if principal_attributes.get(name) is not value_type:
            _fail(f"deployment principal schema does not satisfy {name!r}")

    compiler = PolicyCompiler(registry, dict(principal_attributes))
    policies = PolicySet()
    for bundle in trusted.bundles:
        for loaded in bundle.policies:
            compiled = compiler.compile(loaded.definition)
            full_digest = hashlib.sha256(dumps(compiled.definition).encode("utf-8")).hexdigest()
            if full_digest != loaded.semantic_sha256:
                _fail(f"compiled policy {loaded.policy_id!r} changed after catalog validation")
            provenance = PolicyProvenance(
                policy_id=loaded.policy_id,
                policy_declared_version=loaded.version,
                policy_runtime_version=compiled_policy_version(compiled),
                policy_digest=loaded.semantic_sha256,
                bundle_id=bundle.bundle_id,
                bundle_version=bundle.version,
                bundle_digest=bundle.digest,
                layer=bundle.layer.value,
                mode=bundle.mode.value,
            )
            policies.add(compiled, provenance=provenance)
    return policies
