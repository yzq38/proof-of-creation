from decimal import Decimal, ROUND_DOWN
from server.utils.config import FIXED_FEE, FEE_RATE, PRICE_MULTIPLIER, MIN_GAS_MULTIPLIER
from server.services.pricing import get_eth_cny_rate, quantize


def calc_order_price(gas_limit: int, gas_price: int, user_multiplier: float) -> dict:
    rate = get_eth_cny_rate()
    multiplier = max(user_multiplier, MIN_GAS_MULTIPLIER)

    gas_limit_adjusted = int(gas_limit * multiplier)
    estimated_gas_cost_wei = gas_limit_adjusted * gas_price
    estimated_gas_cost_eth = Decimal(estimated_gas_cost_wei) / Decimal(10 ** 18)
    estimated_gas_cost_cny = quantize(estimated_gas_cost_eth * rate)
    payment_price = quantize(estimated_gas_cost_cny * PRICE_MULTIPLIER + FIXED_FEE)

    return {
        "gas_limit": gas_limit_adjusted,
        "gas_price_wei": gas_price,
        "multiplier": multiplier,
        "rate": float(rate),
        "estimated_gas_cost_cny": float(estimated_gas_cost_cny),
        "payment_price": float(payment_price),
    }


def calc_actual_cost(
    gas_used: int,
    effective_gas_price: int,
    exchange_rate: Decimal,
) -> dict:
    gas_cost_eth = Decimal(gas_used * effective_gas_price) / Decimal(10 ** 18)
    gas_cost_cny = quantize(gas_cost_eth * exchange_rate)
    fee = quantize(gas_cost_cny * FEE_RATE) + FIXED_FEE
    final_cost = quantize(gas_cost_cny + fee)
    return {
        "gas_cost_cny": float(gas_cost_cny),
        "fee": float(fee),
        "final_cost": float(final_cost),
    }


def calc_refund(paid_amount: Decimal, final_cost: Decimal) -> Decimal:
    refund = paid_amount - final_cost
    return quantize(refund) if refund > 0 else Decimal("0")
