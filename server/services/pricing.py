import json
import time
import requests
from decimal import Decimal, ROUND_DOWN

from server.utils.config import EXCHANGE_RATE_API, EXCHANGE_CACHE_TTL, FALLBACK_RATE
from server.utils.logger import get_logger

_cache: dict = {"rate": FALLBACK_RATE, "ts": 0}
logger = get_logger()


def get_eth_cny_rate() -> Decimal:
    global _cache
    now = time.time()
    if now - _cache["ts"] < EXCHANGE_CACHE_TTL and _cache["rate"] > 0:
        return _cache["rate"]
    try:
        resp = requests.get(EXCHANGE_RATE_API, timeout=10)
        rate = Decimal(resp.text.strip())
        _cache = {"rate": rate, "ts": now}
        logger.info("汇率更新: 1 ETH = %s CNY", rate)
        return rate
    except Exception as e:
        logger.warning("获取汇率失败: %s，使用兜底汇率 %s", e, FALLBACK_RATE)
        return _cache["rate"] if _cache["rate"] > 0 else FALLBACK_RATE


def quantize(amount: Decimal) -> Decimal:
    return amount.quantize(Decimal("0.01"), rounding=ROUND_DOWN)
