# Crypto Trading Intelligence Platform

Production-style real-time crypto analysis and paper trading terminal using a **FastAPI async backend** and a **modern dark-mode web dashboard**.

## Features

- Real-time Binance public WebSocket streaming (no private keys)
- Multi-timeframe OHLCV ingestion (`1m`, `5m`, `15m`, `1h`) with auto-reconnect
- Strategy engine indicators:
  - RSI
  - MACD
  - ATR
  - EMA (20/50/200)
  - Volume spike vs rolling average
  - Bullish/bearish engulfing
  - ADX regime filter
- Weighted signal scoring:
  - `Strong Buy`, `Buy`, `Neutral`, `Sell`, `Strong Sell`
  - Signal strength percentage (0–100)
- Paper trading engine:
  - Virtual wallet and configurable starting capital
  - Risk-based position sizing (default 1% risk)
  - Trade log, PnL, win rate, max drawdown, profit factor, equity curve
- Performance tracking:
  - Rolling signal accuracy vs realized move after configurable candle horizon
- Real-time frontend updates via FastAPI WebSocket endpoint:
  - Live candlestick chart + buy/sell markers
  - Signal gauge + indicator breakdown
  - Trade history table
  - Performance metrics panel
  - Equity curve chart

## Project Structure

```text
/backend
  /data
    binance_stream.py
  /engine
    indicators.py
    strategy.py
    performance.py
  /trading
    paper_engine.py
  /models
    schemas.py
  config.py
  main.py
/frontend
  index.html
requirements.txt
```

## Setup

1. Create and activate a virtual environment.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the backend:

```bash
python -m backend.main
```

4. Open the terminal UI:

```text
http://localhost:8000
```

## Configuration

Edit `backend/config.py`:

- `symbol` (default `btcusdt`)
- `timeframes`
- `base_timeframe`
- `default_capital`
- `risk_per_trade`
- `prediction_horizon_candles`
- indicator weights

## Notes

- Uses only Binance **public** streams.
- All trading is simulated in-memory (paper trading only).
- The frontend is fully web-based and works with the backend WebSocket broadcast stream.
