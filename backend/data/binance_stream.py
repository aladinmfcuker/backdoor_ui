"""Async Binance public websocket stream client with auto-reconnect."""
from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone

import websockets

from backend.models.schemas import Candle

logger = logging.getLogger(__name__)


CandleCallback = Callable[[Candle], Awaitable[None]]


class BinanceStreamClient:
    """Consumes Binance kline streams for multiple timeframes."""

    BASE_WS_URL = "wss://stream.binance.com:9443/ws"

    def __init__(self, symbol: str, intervals: list[str], on_candle: CandleCallback) -> None:
        self.symbol = symbol.lower()
        self.intervals = intervals
        self.on_candle = on_candle
        self._tasks: list[asyncio.Task] = []
        self._stop = asyncio.Event()

    async def start(self) -> None:
        self._stop.clear()
        for interval in self.intervals:
            self._tasks.append(asyncio.create_task(self._run_interval_stream(interval)))

    async def stop(self) -> None:
        self._stop.set()
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

    async def _run_interval_stream(self, interval: str) -> None:
        stream_url = f"{self.BASE_WS_URL}/{self.symbol}@kline_{interval}"
        backoff = 1
        while not self._stop.is_set():
            try:
                async with websockets.connect(stream_url, ping_interval=20, ping_timeout=20) as ws:
                    logger.info("Connected to Binance stream for %s", interval)
                    backoff = 1
                    async for raw in ws:
                        payload = json.loads(raw)
                        kline = payload.get("k", {})
                        if not kline.get("x"):
                            continue
                        candle = Candle(
                            timeframe=interval,
                            open_time=datetime.fromtimestamp(kline["t"] / 1000, tz=timezone.utc),
                            close_time=datetime.fromtimestamp(kline["T"] / 1000, tz=timezone.utc),
                            open=float(kline["o"]),
                            high=float(kline["h"]),
                            low=float(kline["l"]),
                            close=float(kline["c"]),
                            volume=float(kline["v"]),
                        )
                        await self.on_candle(candle)
                        if self._stop.is_set():
                            break
            except asyncio.CancelledError:
                break
            except Exception as exc:  # noqa: BLE001
                logger.warning("Binance stream error (%s): %s", interval, exc)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 30)
