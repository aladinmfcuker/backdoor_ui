"""Strategy scoring engine built from technical indicators."""
from __future__ import annotations

from dataclasses import dataclass

from backend.config import settings
from backend.engine.indicators import adx, atr, bullish_bearish_engulfing, ema, macd, rsi
from backend.models.schemas import Candle, Signal


@dataclass
class StrategyContext:
    candles: list[Candle]


class StrategyEngine:
    """Computes weighted directional score and mapped signal labels."""

    def evaluate(self, ctx: StrategyContext) -> Signal:
        candles = ctx.candles
        closes = [c.close for c in candles]
        opens = [c.open for c in candles]
        highs = [c.high for c in candles]
        lows = [c.low for c in candles]
        volumes = [c.volume for c in candles]

        breakdown: dict[str, float] = {}
        weights = settings.indicator_weights

        rsi_val = rsi(closes)
        rsi_score = 0.0 if rsi_val is None else (1.0 if rsi_val < 35 else -1.0 if rsi_val > 65 else (50 - rsi_val) / 15)
        breakdown["rsi"] = rsi_score

        macd_line, macd_signal, _ = macd(closes)
        macd_score = 0.0 if macd_line is None or macd_signal is None else 1.0 if macd_line > macd_signal else -1.0
        breakdown["macd"] = macd_score

        ema20 = ema(closes, 20)
        ema50 = ema(closes, 50)
        ema200 = ema(closes, 200)
        ema_score = 0.0
        if ema20 and ema50 and ema200:
            if closes[-1] > ema20 > ema50 > ema200:
                ema_score = 1.0
            elif closes[-1] < ema20 < ema50 < ema200:
                ema_score = -1.0
        breakdown["ema_stack"] = ema_score

        vol_score = 0.0
        if len(volumes) >= 21:
            avg_vol = sum(volumes[-21:-1]) / 20
            ratio = volumes[-1] / avg_vol if avg_vol else 1.0
            if ratio > 1.8:
                vol_score = 1.0 if closes[-1] > opens[-1] else -1.0
            elif ratio > 1.2:
                vol_score = 0.5 if closes[-1] > opens[-1] else -0.5
        breakdown["volume_spike"] = vol_score

        engulfing_score = float(bullish_bearish_engulfing(opens, closes))
        breakdown["engulfing"] = engulfing_score

        adx_val = adx(highs, lows, closes)
        adx_score = 0.0
        if adx_val is not None:
            trend_dir = 1.0 if closes[-1] > closes[-5] else -1.0
            adx_score = trend_dir if adx_val >= 22 else trend_dir * 0.4
        breakdown["adx_regime"] = adx_score

        atr_val = atr(highs, lows, closes)
        atr_score = 0.0
        if atr_val and closes[-1] > 0:
            atr_ratio = atr_val / closes[-1]
            atr_score = 0.6 if atr_ratio > 0.012 else 0.2
            atr_score = atr_score if closes[-1] > opens[-1] else -atr_score
        breakdown["atr_volatility"] = atr_score

        weighted_sum = sum(breakdown[k] * weights[k] for k in breakdown)
        total_weight = sum(weights.values())
        normalized = weighted_sum / total_weight if total_weight else 0.0
        strength = min(100.0, abs(normalized) * 100)

        if normalized >= 0.6:
            label = "Strong Buy"
        elif normalized >= 0.2:
            label = "Buy"
        elif normalized <= -0.6:
            label = "Strong Sell"
        elif normalized <= -0.2:
            label = "Sell"
        else:
            label = "Neutral"

        return Signal(label=label, score=normalized, strength=strength, indicator_breakdown=breakdown)
