# agent_mash/coo/__init__.py
from __future__ import annotations

"""
agent_mash.coo

COO layer (Chief Operations Officer): orchestration-facing utilities, policies and
coordination helpers for workforce execution.

This package-level module is intentionally lightweight:
- Provides a stable public API surface via __all__
- Avoids heavy imports at import-time (lazy imports via PEP 562)
- Plays well with type-checkers (TYPE_CHECKING)
- Minimizes cyclic import risk across agent_mash layers

If you add new symbols in agent_mash/coo/*.py, expose them here through:
- _EXPORTS mapping (name -> "module:attr")
- __all__ list update
"""

from typing import TYPE_CHECKING, Any

__all__ = [
    "__version__",
    "__api__",
    "__package_name__",
]

__package_name__ = "agent_mash.coo"
__api__ = "coo"
__version__ = "0.1.0"

# Public exports registry.
# Populate this mapping as you add real modules and symbols.
# Example:
# _EXPORTS = {
#     "COORouter": "agent_mash.coo.router:COORouter",
#     "COOPolicy": "agent_mash.coo.policy:COOPolicy",
# }
_EXPORTS: dict[str, str] = {}


if TYPE_CHECKING:
    # For static analyzers: re-exported symbols can be imported here.
    # Keep it safe: only import optional symbols behind TYPE_CHECKING.
    #
    # Example:
    # from .router import COORouter as COORouter
    # from .policy import COOPolicy as COOPolicy
    pass


def __getattr__(name: str) -> Any:
    """
    Lazy attribute resolution (PEP 562).

    Benefits:
    - Avoids importing submodules until actually used
    - Reduces startup time and mitigates cyclic imports
    """
    target = _EXPORTS.get(name)
    if not target:
        raise AttributeError(f"module {__package_name__!r} has no attribute {name!r}")

    mod_path, _, attr = target.partition(":")
    if not mod_path or not attr:
        raise AttributeError(
            f"invalid export mapping for {name!r}: {target!r} "
            f"(expected 'module.path:Attribute')"
        )

    try:
        from importlib import import_module

        module = import_module(mod_path)
        value = getattr(module, attr)
    except Exception as e:
        # Do not mask the original error type; wrap with clear message.
        raise ImportError(
            f"failed to resolve export {name!r} -> {target!r} in {__package_name__}"
        ) from e

    # Cache on module namespace for subsequent access.
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """
    Improve developer UX: include lazily-exported symbols in dir().
    """
    base = set(globals().keys())
    base.update(_EXPORTS.keys())
    return sorted(base)
