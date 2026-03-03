"""Indicator computation utilities for strategy engine."""
from __future__ import annotations

from statistics import fmean


def ema(values: list[float], period: int) -> float | None:
    if len(values) < period:
        return None
    multiplier = 2 / (period + 1)
    ema_val = fmean(values[:period])
    for value in values[period:]:
        ema_val = (value - ema_val) * multiplier + ema_val
    return ema_val


def rsi(closes: list[float], period: int = 14) -> float | None:
    if len(closes) <= period:
        return None
    gains: list[float] = []
    losses: list[float] = []
    for i in range(1, period + 1):
        delta = closes[i] - closes[i - 1]
        gains.append(max(delta, 0))
        losses.append(abs(min(delta, 0)))

    avg_gain = fmean(gains)
    avg_loss = fmean(losses)

    for i in range(period + 1, len(closes)):
        delta = closes[i] - closes[i - 1]
        gain = max(delta, 0)
        loss = abs(min(delta, 0))
        avg_gain = ((avg_gain * (period - 1)) + gain) / period
        avg_loss = ((avg_loss * (period - 1)) + loss) / period

    if avg_loss == 0:
        return 100.0
    rs = avg_gain / avg_loss
    return 100 - (100 / (1 + rs))


def macd(closes: list[float]) -> tuple[float | None, float | None, float | None]:
    if len(closes) < 35:
        return None, None, None
    ema12_series = _ema_series(closes, 12)
    ema26_series = _ema_series(closes, 26)
    macd_line_series = [a - b for a, b in zip(ema12_series, ema26_series) if a is not None and b is not None]
    if len(macd_line_series) < 9:
        return None, None, None
    signal = ema(macd_line_series, 9)
    if signal is None:
        return None, None, None
    macd_line = macd_line_series[-1]
    hist = macd_line - signal
    return macd_line, signal, hist


def atr(highs: list[float], lows: list[float], closes: list[float], period: int = 14) -> float | None:
    if len(closes) <= period:
        return None
    true_ranges: list[float] = []
    for i in range(1, len(closes)):
        tr = max(
            highs[i] - lows[i],
            abs(highs[i] - closes[i - 1]),
            abs(lows[i] - closes[i - 1]),
        )
        true_ranges.append(tr)
    if len(true_ranges) < period:
        return None
    atr_val = fmean(true_ranges[:period])
    for tr in true_ranges[period:]:
        atr_val = ((atr_val * (period - 1)) + tr) / period
    return atr_val


def adx(highs: list[float], lows: list[float], closes: list[float], period: int = 14) -> float | None:
    if len(closes) <= period * 2:
        return None

    plus_dm, minus_dm, true_ranges = [], [], []
    for i in range(1, len(closes)):
        up_move = highs[i] - highs[i - 1]
        down_move = lows[i - 1] - lows[i]
        plus_dm.append(up_move if up_move > down_move and up_move > 0 else 0.0)
        minus_dm.append(down_move if down_move > up_move and down_move > 0 else 0.0)
        true_ranges.append(max(highs[i] - lows[i], abs(highs[i] - closes[i - 1]), abs(lows[i] - closes[i - 1])))

    tr14 = sum(true_ranges[:period])
    plus14 = sum(plus_dm[:period])
    minus14 = sum(minus_dm[:period])

    dx_values: list[float] = []
    for i in range(period, len(true_ranges)):
        tr14 = tr14 - (tr14 / period) + true_ranges[i]
        plus14 = plus14 - (plus14 / period) + plus_dm[i]
        minus14 = minus14 - (minus14 / period) + minus_dm[i]

        plus_di = 100 * (plus14 / tr14) if tr14 else 0
        minus_di = 100 * (minus14 / tr14) if tr14 else 0
        denom = plus_di + minus_di
        dx = 100 * abs(plus_di - minus_di) / denom if denom else 0
        dx_values.append(dx)

    if len(dx_values) < period:
        return None
    adx_val = fmean(dx_values[:period])
    for dx in dx_values[period:]:
        adx_val = ((adx_val * (period - 1)) + dx) / period
    return adx_val


def bullish_bearish_engulfing(opens: list[float], closes: list[float]) -> int:
    if len(opens) < 2 or len(closes) < 2:
        return 0
    prev_open, prev_close = opens[-2], closes[-2]
    last_open, last_close = opens[-1], closes[-1]

    bullish = prev_close < prev_open and last_close > last_open and last_open <= prev_close and last_close >= prev_open
    bearish = prev_close > prev_open and last_close < last_open and last_open >= prev_close and last_close <= prev_open

    if bullish:
        return 1
    if bearish:
        return -1
    return 0


def _ema_series(values: list[float], period: int) -> list[float | None]:
    series: list[float | None] = [None] * len(values)
    if len(values) < period:
        return series
    multiplier = 2 / (period + 1)
    ema_val = fmean(values[:period])
    series[period - 1] = ema_val
    for i in range(period, len(values)):
        ema_val = (values[i] - ema_val) * multiplier + ema_val
        series[i] = ema_val
    return series
