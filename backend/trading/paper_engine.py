"""Paper trading engine with risk-based sizing and performance metrics."""
from __future__ import annotations

from datetime import datetime

from backend.models.schemas import PerformanceMetrics, Position, Signal, TradeRecord


class PaperTradingEngine:
    """In-memory paper trading simulation engine."""

    def __init__(self, capital: float, risk_per_trade: float) -> None:
        self.initial_capital = capital
        self.cash = capital
        self.risk_per_trade = risk_per_trade
        self.open_position: Position | None = None
        self.trades: list[TradeRecord] = []
        self.equity_curve: list[float] = [capital]

    def on_signal(self, signal: Signal, price: float, now: datetime, atr_value: float | None = None) -> TradeRecord | None:
        trade_update = None
        direction = 1 if signal.label in {"Strong Buy", "Buy"} else -1 if signal.label in {"Strong Sell", "Sell"} else 0

        if self.open_position is None and direction != 0 and signal.strength >= 45:
            stop_distance = (atr_value or price * 0.006)
            risk_amount = self.cash * self.risk_per_trade
            quantity = max(0.0, risk_amount / stop_distance)
            if quantity > 0:
                stop_price = price - stop_distance if direction == 1 else price + stop_distance
                self.open_position = Position(
                    side="long" if direction == 1 else "short",
                    quantity=quantity,
                    entry_price=price,
                    entry_time=now,
                    stop_price=stop_price,
                )
        elif self.open_position is not None:
            should_close = (
                (self.open_position.side == "long" and direction <= 0)
                or (self.open_position.side == "short" and direction >= 0)
                or (self.open_position.side == "long" and price <= self.open_position.stop_price)
                or (self.open_position.side == "short" and price >= self.open_position.stop_price)
            )
            if should_close:
                trade_update = self._close_trade(price, now)

        self.equity_curve.append(self.current_equity(price))
        return trade_update

    def _close_trade(self, price: float, now: datetime) -> TradeRecord:
        assert self.open_position is not None
        pos = self.open_position
        pnl = (price - pos.entry_price) * pos.quantity if pos.side == "long" else (pos.entry_price - price) * pos.quantity
        self.cash += pnl
        pnl_pct = (pnl / self.initial_capital) * 100
        trade = TradeRecord(
            side=pos.side,
            quantity=pos.quantity,
            entry_price=pos.entry_price,
            exit_price=price,
            entry_time=pos.entry_time,
            exit_time=now,
            pnl=pnl,
            pnl_pct=pnl_pct,
        )
        self.trades.append(trade)
        self.open_position = None
        return trade

    def current_equity(self, price: float) -> float:
        if self.open_position is None:
            return self.cash
        pos = self.open_position
        unrealized = (price - pos.entry_price) * pos.quantity if pos.side == "long" else (pos.entry_price - price) * pos.quantity
        return self.cash + unrealized

    def metrics(self, mark_price: float, rolling_accuracy: float, sample_size: int) -> PerformanceMetrics:
        pnl_values = [t.pnl for t in self.trades]
        wins = [p for p in pnl_values if p > 0]
        losses = [abs(p) for p in pnl_values if p < 0]
        win_rate = (len(wins) / len(self.trades) * 100) if self.trades else 0.0
        profit_factor = (sum(wins) / sum(losses)) if losses else (float("inf") if wins else 0.0)

        peak = self.equity_curve[0]
        max_dd = 0.0
        for eq in self.equity_curve:
            peak = max(peak, eq)
            dd = (peak - eq) / peak * 100 if peak else 0.0
            max_dd = max(max_dd, dd)

        return PerformanceMetrics(
            capital=self.initial_capital,
            equity=self.current_equity(mark_price),
            open_position=self.open_position,
            total_trades=len(self.trades),
            win_rate=win_rate,
            max_drawdown=max_dd,
            profit_factor=profit_factor,
            rolling_accuracy=rolling_accuracy,
            signal_accuracy_samples=sample_size,
            equity_curve=self.equity_curve[-300:],
        )
