"""MasuGate exception hierarchy."""


class MasuGateError(Exception):
    """Base class for framework errors."""


class PolicySyntaxError(MasuGateError):
    pass


class PolicyValidationError(MasuGateError):
    pass


class PolicyEvaluationError(MasuGateError):
    pass


class ContractError(MasuGateError):
    pass


class CertificationError(MasuGateError):
    """Certified policy input is missing, stale, or fails provenance checks."""


class ResourceError(MasuGateError):
    pass


class RetryableResourceError(ResourceError):
    """A resource operation failed in a way the coordinator may safely retry."""
