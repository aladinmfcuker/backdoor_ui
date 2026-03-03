"""Signal prediction accuracy tracker."""
from __future__ import annotations

from collections import deque
from datetime import datetime

from backend.models.schemas import PredictionSample


class SignalPerformanceTracker:
    """Tracks prediction direction correctness after a configurable candle horizon."""

    def __init__(self, horizon_candles: int) -> None:
        self.horizon = horizon_candles
        self.pending: deque[PredictionSample] = deque()
        self.results: deque[int] = deque(maxlen=500)

    def add_prediction(self, candle_index: int, direction: int, entry_price: float, created_at: datetime) -> None:
        if direction == 0:
            return
        self.pending.append(
            PredictionSample(
                created_at=created_at,
                candle_index=candle_index,
                direction=direction,
                entry_price=entry_price,
            )
        )

    def evaluate(self, current_candle_index: int, current_price: float) -> None:
        while self.pending and current_candle_index - self.pending[0].candle_index >= self.horizon:
            sample = self.pending.popleft()
            actual_dir = 1 if current_price > sample.entry_price else -1 if current_price < sample.entry_price else 0
            self.results.append(1 if actual_dir == sample.direction else 0)

    @property
    def rolling_accuracy(self) -> float:
        if not self.results:
            return 0.0
        return (sum(self.results) / len(self.results)) * 100

    @property
    def sample_size(self) -> int:
        return len(self.results)
