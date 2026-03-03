"""FastAPI app entrypoint for realtime crypto analysis and paper trading."""
from __future__ import annotations

import asyncio
import json
import logging
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.config import settings
from backend.data.binance_stream import BinanceStreamClient
from backend.engine.performance import SignalPerformanceTracker
from backend.engine.strategy import StrategyContext, StrategyEngine
from backend.models.schemas import Candle
from backend.trading.paper_engine import PaperTradingEngine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title=settings.app_name)
app.mount("/assets", StaticFiles(directory="frontend"), name="assets")

clients: set[WebSocket] = set()
candle_store: dict[str, deque[Candle]] = defaultdict(lambda: deque(maxlen=settings.max_candles))
strategy = StrategyEngine()
paper = PaperTradingEngine(capital=settings.default_capital, risk_per_trade=settings.risk_per_trade)
perf_tracker = SignalPerformanceTracker(horizon_candles=settings.prediction_horizon_candles)
stream_client: BinanceStreamClient | None = None
candle_index = 0
state_lock = asyncio.Lock()


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(Path("frontend/index.html"))


@app.websocket("/ws/frontend")
async def frontend_ws(websocket: WebSocket) -> None:
    await websocket.accept()
    clients.add(websocket)
    try:
        await websocket.send_json({"type": "hello", "symbol": settings.symbol.upper(), "timeframes": settings.timeframes})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        clients.discard(websocket)


async def broadcast(payload: dict) -> None:
    if not clients:
        return
    encoded = json.dumps(payload, default=str)
    stale: list[WebSocket] = []
    for ws in clients:
        try:
            await ws.send_text(encoded)
        except Exception:  # noqa: BLE001
            stale.append(ws)
    for ws in stale:
        clients.discard(ws)


async def handle_candle(candle: Candle) -> None:
    global candle_index
    async with state_lock:
        candle_store[candle.timeframe].append(candle)

        await broadcast({"type": "new_candle", "timeframe": candle.timeframe, "data": candle.model_dump(mode="json")})

        if candle.timeframe != settings.base_timeframe:
            return

        base_candles = list(candle_store[settings.base_timeframe])
        if len(base_candles) < 220:
            return

        signal = strategy.evaluate(StrategyContext(candles=base_candles))
        direction = 1 if signal.label in {"Strong Buy", "Buy"} else -1 if signal.label in {"Strong Sell", "Sell"} else 0

        trade = paper.on_signal(signal=signal, price=candle.close, now=datetime.now(timezone.utc))
        if direction:
            perf_tracker.add_prediction(candle_index, direction, candle.close, datetime.now(timezone.utc))
        perf_tracker.evaluate(candle_index, candle.close)
        candle_index += 1

        metrics = paper.metrics(candle.close, perf_tracker.rolling_accuracy, perf_tracker.sample_size)

        await broadcast({"type": "signal", "data": signal.model_dump(mode="json")})
        if trade is not None:
            await broadcast({"type": "trade_update", "data": trade.model_dump(mode="json")})
        await broadcast({"type": "metrics", "data": metrics.model_dump(mode="json")})


@app.on_event("startup")
async def startup() -> None:
    global stream_client
    stream_client = BinanceStreamClient(settings.symbol, settings.timeframes, handle_candle)
    await stream_client.start()
    logger.info("Started Binance stream client")


@app.on_event("shutdown")
async def shutdown() -> None:
    if stream_client:
        await stream_client.stop()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.main:app", host=settings.host, port=settings.port, reload=False)
