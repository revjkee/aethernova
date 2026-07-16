# agent_mash/cfo/__init__.py
from __future__ import annotations

"""
agent_mash.cfo

CFO layer (Chief Financial Officer): finance, pricing, billing, unit-economics,
and accounting-facing helpers for workforce execution.

Design goals:
- Stable public API via __all__
- Lightweight import-time behavior (lazy imports via PEP 562)
- Type-checker friendly exports (TYPE_CHECKING)
- Reduced cyclic import probability across agent_mash layers

When you add new symbols under agent_mash/cfo/*.py, expose them here using:
- _EXPORTS mapping: name -> "module.path:Attribute"
- __all__ list update
"""

from typing import TYPE_CHECKING, Any

__all__ = [
    "__version__",
    "__api__",
    "__package_name__",
]

__package_name__ = "agent_mash.cfo"
__api__ = "cfo"
__version__ = "0.1.0"

# Public exports registry.
# Populate as your CFO submodules appear.
# Example:
# _EXPORTS = {
#     "BillingPolicy": "agent_mash.cfo.billing:BillingPolicy",
#     "PricingEngine": "agent_mash.cfo.pricing:PricingEngine",
#     "LedgerAdapter": "agent_mash.cfo.ledger:LedgerAdapter",
# }
_EXPORTS: dict[str, str] = {}


if TYPE_CHECKING:
    # For static analysis only; keep runtime import minimal and safe.
    #
    # Example:
    # from .billing import BillingPolicy as BillingPolicy
    # from .pricing import PricingEngine as PricingEngine
    # from .ledger import LedgerAdapter as LedgerAdapter
    pass


def __getattr__(name: str) -> Any:
    """
    Lazy attribute resolution (PEP 562).

    - Avoids importing submodules until symbol is accessed
    - Mitigates cyclic imports in large architectures
    - Caches resolved symbol in module globals for performance
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
        raise ImportError(
            f"failed to resolve export {name!r} -> {target!r} in {__package_name__}"
        ) from e

    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """
    Developer UX: include lazy exports in dir().
    """
    base = set(globals().keys())
    base.update(_EXPORTS.keys())
    return sorted(base)
