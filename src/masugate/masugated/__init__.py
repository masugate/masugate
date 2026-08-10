"""The ``masugated`` governed-action HTTP service.

``create_app`` wraps one coordinator and one governed resource with the
Governed Action Protocol.  The caller owns policy/provider construction; the
CLI in :mod:`masugate.masugated.cli` supplies the production PostgreSQL bootstrap.
"""

from masugate.masugated.app import ActionOwnerBinding, PendingEventBroker, create_app

__all__ = ["ActionOwnerBinding", "PendingEventBroker", "create_app"]
