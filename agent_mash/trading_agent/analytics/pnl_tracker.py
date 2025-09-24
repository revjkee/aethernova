# pnl_tracker.py

import logging
from typing import List, Dict, Optional
from datetime import datetime
from decimal import Decimal, ROUND_HALF_UP
from dataclasses import dataclass, field

logger = logging.getLogger("pnl_tracker")
logger.setLevel(logging.INFO)

@dataclass
class Trade:
    trade_id: str
    symbol: str
    side: str  # 'buy' or 'sell'
    amount: float
    price: float
    fee: float
    timestamp: datetime

@dataclass
class Position:
    symbol: str
    open_trades: List[Trade] = field(default_factory=list)
    closed_trades: List[Trade] = field(default_factory=list)
    realized_pnl: float = 0.0
    unrealized_pnl: float = 0.0
    fees_total: float = 0.0

class PnLTracker:
    """
    Трекер доходности: считает валовую/чистую прибыль, удержания, комиссии и обеспечивает отчётность.
    """

    def __init__(self):
        self.positions: Dict[str, Position] = {}
        self.closed_pnl_log: List[Dict[str, float]] = []

    def _round(self, value: float, precision: int = 6) -> float:
        return float(Decimal(value).quantize(Decimal(f"1e-{precision}"), rounding=ROUND_HALF_UP))

    def record_trade(self, trade: Trade):
        pos = self.positions.setdefault(trade.symbol, Position(symbol=trade.symbol))
        pos.fees_total += trade.fee

        if trade.side == "buy":
            pos.open_trades.append(trade)
        elif trade.side == "sell":
            self._close_position(pos, trade)
        else:
            logger.warning(f"[PNL] Неизвестное направление сделки: {trade.side}")

        logger.debug(f"[PNL] Записана сделка: {trade}")

    def _close_position(self, position: Position, sell_trade: Trade):
        if not position.open_trades:
            logger.warning(f"[PNL] Нет открытых позиций для закрытия по {sell_trade.symbol}")
            return

        buy_trade = position.open_trades.pop(0)
        pnl = (sell_trade.price - buy_trade.price) * sell_trade.amount
        position.realized_pnl += pnl
        position.closed_trades.extend([buy_trade, sell_trade])

        logger.info(f"[PNL] Закрыта позиция по {sell_trade.symbol} | PnL: {self._round(pnl)}")
        self.closed_pnl_log.append({
            "symbol": sell_trade.symbol,
            "pnl": self._round(pnl),
            "timestamp": sell_trade.timestamp.isoformat()
        })

    def get_summary(self) -> Dict[str, Dict[str, float]]:
        summary = {}
        for symbol, pos in self.positions.items():
            summary[symbol] = {
                "realized_pnl": self._round(pos.realized_pnl),
                "fees": self._round(pos.fees_total),
                "net_pnl": self._round(pos.realized_pnl - pos.fees_total),
                "open_trades": len(pos.open_trades),
                "closed_trades": len(pos.closed_trades)
            }
        return summary

    def export_closed_pnl_log(self) -> List[Dict[str, float]]:
        return self.closed_pnl_log.copy()

    def reset(self):
        self.positions.clear()
        self.closed_pnl_log.clear()
        logger.info("[PNL] Все позиции и лог доходности сброшены")
