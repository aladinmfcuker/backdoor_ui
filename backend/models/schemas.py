"""Pydantic schemas used across data, engine, and API layers."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class Candle(BaseModel):
    """OHLCV candle structure."""

    timeframe: str
    open_time: datetime
    close_time: datetime
    open: float
    high: float
    low: float
    close: float
    volume: float


class Signal(BaseModel):
    """Signal emitted by strategy engine."""

    label: Literal["Strong Buy", "Buy", "Neutral", "Sell", "Strong Sell"]
    score: float
    strength: float
    indicator_breakdown: dict[str, float]


class Position(BaseModel):
    """Current paper trade position."""

    side: Literal["long", "short"]
    quantity: float
    entry_price: float
    entry_time: datetime
    stop_price: float


class TradeRecord(BaseModel):
    """Closed trade record."""

    side: Literal["long", "short"]
    quantity: float
    entry_price: float
    exit_price: float
    entry_time: datetime
    exit_time: datetime
    pnl: float
    pnl_pct: float


class PerformanceMetrics(BaseModel):
    """Aggregated paper trading and accuracy metrics."""

    capital: float
    equity: float
    open_position: Position | None
    total_trades: int
    win_rate: float
    max_drawdown: float
    profit_factor: float
    rolling_accuracy: float
    signal_accuracy_samples: int
    equity_curve: list[float]


class PredictionSample(BaseModel):
    """Signal prediction to evaluate after horizon candles."""

    created_at: datetime
    candle_index: int
    direction: int
    entry_price: float
