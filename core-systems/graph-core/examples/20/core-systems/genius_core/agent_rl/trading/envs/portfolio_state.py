import numpy as np
from dataclasses import dataclass, asdict
from typing import Optional, Dict

@dataclass
class Position:
    symbol: str
    size: float = 0.0
    entry_price: float = 0.0
    leverage: float = 1.0
    direction: str = "flat"  # "long", "short", "flat"
    unrealized_pnl: float = 0.0
    realized_pnl: float = 0.0
    liquidation_price: Optional[float] = None

@dataclass
class Portfolio:
    balance: float
    equity: float
    positions: Dict[str, Position]
    margin_used: float
    margin_available: float
    leverage_limit: float = 10.0

    def update_position(self, symbol: str, price: float, size_delta: float, direction: str):
        pos = self.positions.get(symbol, Position(symbol=symbol))

        if pos.size == 0.0:
            pos.entry_price = price
            pos.direction = direction
            pos.size = size_delta
        else:
            total_size = pos.size + size_delta
            if total_size == 0.0:
                self._close_position(symbol, price)
                return
            new_entry_price = (
                (pos.entry_price * pos.size + price * size_delta) / total_size
            )
            pos.entry_price = new_entry_price
            pos.size = total_size

        pos.leverage = self._calculate_leverage(symbol)
        pos.liquidation_price = self._calc_liquidation_price(pos)
        self.positions[symbol] = pos
        self._recalculate_margins()

    def mark_to_market(self, symbol: str, current_price: float):
        if symbol in self.positions:
            pos = self.positions[symbol]
            pnl = self._compute_unrealized_pnl(pos, current_price)
            pos.unrealized_pnl = pnl
            self.positions[symbol] = pos
            self.equity = self.balance + pnl

    def _compute_unrealized_pnl(self, pos: Position, current_price: float) -> float:
        if pos.direction == "long":
            return (current_price - pos.entry_price) * pos.size
        elif pos.direction == "short":
            return (pos.entry_price - current_price) * pos.size
        return 0.0

    def _calc_liquidation_price(self, pos: Position) -> float:
        maintenance_margin = 0.005  # 0.5%
        if pos.direction == "long":
            return pos.entry_price * (1 - (1 / pos.leverage) + maintenance_margin)
        elif pos.direction == "short":
            return pos.entry_price * (1 + (1 / pos.leverage) - maintenance_margin)
        return 0.0

    def _calculate_leverage(self, symbol: str) -> float:
        pos = self.positions[symbol]
        notional = pos.size * pos.entry_price
        if notional == 0:
            return 1.0
        return min(self.leverage_limit, notional / self.balance)

    def _close_position(self, symbol: str, exit_price: float):
        pos = self.positions[symbol]
        pnl = self._compute_unrealized_pnl(pos, exit_price)
        self.balance += pnl
        pos.realized_pnl += pnl
        pos.size = 0.0
        pos.unrealized_pnl = 0.0
        pos.direction = "flat"
        pos.liquidation_price = None
        self.positions[symbol] = pos
        self._recalculate_margins()

    def _recalculate_margins(self):
        self.margin_used = sum(
            pos.entry_price * pos.size / pos.leverage for pos in self.positions.values()
            if pos.size > 0
        )
        self.margin_available = self.balance - self.margin_used
        self.equity = self.balance + sum(p.unrealized_pnl for p in self.positions.values())

    def as_dict(self) -> dict:
        return {
            "balance": self.balance,
            "equity": self.equity,
            "margin_used": self.margin_used,
            "margin_available": self.margin_available,
            "positions": {s: asdict(p) for s, p in self.positions.items()},
        }
