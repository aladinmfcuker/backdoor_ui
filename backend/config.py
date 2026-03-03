"""Application configuration for the crypto trading intelligence platform."""
from pydantic import BaseModel, Field


class Settings(BaseModel):
    """Runtime settings for backend and strategy components."""

    app_name: str = "Crypto Trading Intelligence Platform"
    host: str = "0.0.0.0"
    port: int = 8000

    symbol: str = "btcusdt"
    timeframes: list[str] = Field(default_factory=lambda: ["1m", "5m", "15m", "1h"])
    base_timeframe: str = "1m"

    max_candles: int = 600
    prediction_horizon_candles: int = 3

    default_capital: float = 10000.0
    risk_per_trade: float = 0.01

    indicator_weights: dict[str, float] = Field(
        default_factory=lambda: {
            "rsi": 1.2,
            "macd": 1.3,
            "ema_stack": 1.4,
            "volume_spike": 0.7,
            "engulfing": 0.8,
            "adx_regime": 1.0,
            "atr_volatility": 0.6,
        }
    )


settings = Settings()
