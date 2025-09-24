# order_formatter.py

import logging
from typing import Dict, Any, Optional, Literal, Union

logger = logging.getLogger("order_formatter")
logger.setLevel(logging.INFO)

OrderType = Literal["market", "limit", "stop", "stop_limit"]
SideType = Literal["buy", "sell"]

SUPPORTED_BROKERS = ["binance", "bybit", "mock"]


class OrderFormatter:
    """
    Универсальный форматтер ордеров для адаптации к API разных брокеров.
    """

    def __init__(self, broker: str = "mock"):
        if broker not in SUPPORTED_BROKERS:
            raise ValueError(f"Брокер {broker} не поддерживается.")
        self.broker = broker

    def format_order(
        self,
        side: SideType,
        quantity: Union[int, float],
        price: Optional[float] = None,
        order_type: OrderType = "market",
        symbol: str = "BTCUSDT",
        reduce_only: bool = False,
        time_in_force: Optional[str] = "GTC"
    ) -> Dict[str, Any]:
        """
        Возвращает ордер, отформатированный под API брокера.
        """
        self._validate_input(side, quantity, price, order_type)

        if self.broker == "binance":
            return self._format_binance_order(side, quantity, price, order_type, symbol, time_in_force)
        elif self.broker == "bybit":
            return self._format_bybit_order(side, quantity, price, order_type, symbol, reduce_only)
        elif self.broker == "mock":
            return self._format_mock_order(side, quantity, price, order_type, symbol)
        else:
            raise NotImplementedError(f"Форматтер для {self.broker} не реализован.")

    def _validate_input(self, side: str, quantity: float, price: Optional[float], order_type: str):
        if side not in {"buy", "sell"}:
            raise ValueError("side должен быть 'buy' или 'sell'")
        if quantity <= 0:
            raise ValueError("quantity должен быть положительным")
        if order_type in {"limit", "stop", "stop_limit"} and price is None:
            raise ValueError("price обязателен для limit/stop ордеров")

    def _format_binance_order(
        self, side: str, quantity: float, price: Optional[float], order_type: str,
        symbol: str, time_in_force: str
    ) -> Dict[str, Any]:
        order = {
            "symbol": symbol,
            "side": side.upper(),
            "type": order_type.upper(),
            "quantity": quantity,
        }
        if order_type != "market":
            order["price"] = price
            order["timeInForce"] = time_in_force
        return order

    def _format_bybit_order(
        self, side: str, qty: float, price: Optional[float], order_type: str,
        symbol: str, reduce_only: bool
    ) -> Dict[str, Any]:
        order = {
            "symbol": symbol,
            "side": side.capitalize(),
            "order_type": order_type.upper(),
            "qty": qty,
            "reduce_only": reduce_only,
        }
        if order_type != "market":
            order["price"] = price
        return order

    def _format_mock_order(
        self, side: str, quantity: float, price: Optional[float], order_type: str,
        symbol: str
    ) -> Dict[str, Any]:
        return {
            "symbol": symbol,
            "side": side,
            "type": order_type,
            "quantity": quantity,
            "price": price or 0.0,
            "simulated": True
        }

    def describe_format(self) -> Dict[str, Any]:
        """
        Возвращает информацию о текущем брокере и поддерживаемых полях.
        """
        return {
            "broker": self.broker,
            "supported_order_types": ["market", "limit", "stop", "stop_limit"],
            "fields": ["side", "quantity", "price", "symbol", "reduce_only", "time_in_force"]
        }
