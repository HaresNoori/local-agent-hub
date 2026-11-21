"""Local agent hub broker core.

The Store class in :mod:`hub.store` is the public persistence interface for a
future adapter or worker. It deliberately does not start subprocesses.
"""

from .store import Store, HubError

__all__ = ["Store", "HubError"]
