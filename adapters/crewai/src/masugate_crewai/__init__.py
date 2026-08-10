"""Exact-artifact CrewAI ``BaseTool`` replacements over ``masugate-adapter-core``."""

from .runtime import (
    CREWAI_CORE_VERSION,
    CREWAI_VERSION,
    CREWAI_WHEEL_SHA256,
    CrewAIAdapterError,
    CrewAIGovernedToolset,
    CrewAIProfileViolationError,
    CrewAITrustedContext,
    MissingCrewTaskIdentityError,
    UnsupportedCrewAIRuntimeError,
    create_crewai_governed_toolset,
    reattach_restored_crewai_tools,
    verify_pinned_crewai_runtime,
)

__all__ = [
    "CREWAI_CORE_VERSION",
    "CREWAI_VERSION",
    "CREWAI_WHEEL_SHA256",
    "CrewAIAdapterError",
    "CrewAIGovernedToolset",
    "CrewAIProfileViolationError",
    "CrewAITrustedContext",
    "MissingCrewTaskIdentityError",
    "UnsupportedCrewAIRuntimeError",
    "create_crewai_governed_toolset",
    "reattach_restored_crewai_tools",
    "verify_pinned_crewai_runtime",
]
