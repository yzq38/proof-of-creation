import time
from decimal import Decimal

from flask import Blueprint, request, jsonify, g, send_file
from io import BytesIO

from server.routes.auth import token_required
from server.utils.db import get_db
from server.utils.logger import get_logger
from server.utils.config import ORDER_EXPIRY, FEE_RATE, FIXED_FEE
from server.services.blockchain import estimate_gas, get_current_gas_price, send_transaction, wait_for_receipt
from server.services.payment import calc_order_price, calc_actual_cost, calc_refund
from server.services.pricing import get_eth_cny_rate, quantize

order_bp = Blueprint("orders", __name__, url_prefix="/api/orders")
logger = get_logger()


def _validate_encryption_mode(mode: str) -> bool:
    return mode in ("sha3-256+ed25519", "advanced")


def _validate_file_name(name: str) -> str:
    if not name or not name.strip():
        return "untitled"
    return name.strip()[:32]


def _calc_final_cost(o) -> tuple:
    if o["status"] != "success" or not o["gas_used"]:
        return None, None
    gas_cost_eth = Decimal(o["gas_used"] * o["gas_price"]) / Decimal(10 ** 18)
    gas_cost_cny = quantize(gas_cost_eth * Decimal(str(o["exchange_rate"])))
    fee = quantize(gas_cost_cny * FEE_RATE) + FIXED_FEE
    final_cost = float(quantize(gas_cost_cny + fee))
    paid = Decimal(str(o["paid_amount"]))
    refund = float(max(Decimal("0"), paid - Decimal(str(final_cost))))
    return final_cost, refund


@order_bp.route("/create", methods=["POST"])
@token_required
def create():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "请求数据为空"}), 400

    file_name = _validate_file_name(data.get("file_name", "untitled"))
    encryption_mode = (data.get("encryption_mode") or "").strip()
    if not _validate_encryption_mode(encryption_mode):
        return jsonify({"error": "无效的加密模式"}), 400

    user_multiplier = max(float(data.get("gas_multiplier", 1.2)), 1.2)

    hash_len = int(data.get("hash_len", 0))
    sig_len = int(data.get("sig_len", 0))
    gas_limit = estimate_gas(encryption_mode, hash_len, sig_len)
    gas_price_info = get_current_gas_price()
    gas_price = gas_price_info["last_base_fee"]
    pricing = calc_order_price(gas_limit, gas_price, user_multiplier)

    db = get_db()
    cursor = db.execute(
        "INSERT INTO orders (user_id, file_name, created_at, encryption_mode, status, paid_amount) "
        "VALUES (?, ?, ?, ?, 'pending', 0.00)",
        (g.user_id, file_name, time.time(), encryption_mode),
    )
    db.commit()
    order_id = cursor.lastrowid

    logger.info(
        "订单创建: order_id=%d, user_id=%d, mode=%s, price=%.2f CNY",
        order_id, g.user_id, encryption_mode, pricing["payment_price"],
    )

    return jsonify({
        "order_id": order_id,
        "file_name": file_name,
        "encryption_mode": encryption_mode,
        "created_at": time.time(),
        "gas_limit_original": gas_limit,
        "gas_limit_adjusted": pricing["gas_limit"],
        "gas_price_wei": pricing["gas_price_wei"],
        "multiplier": pricing["multiplier"],
        "exchange_rate": pricing["rate"],
        "estimated_gas_cost_cny": pricing["estimated_gas_cost_cny"],
        "payment_price": pricing["payment_price"],
        "order_expiry": ORDER_EXPIRY,
    }), 201


@order_bp.route("/<int:order_id>/pay", methods=["POST"])
@token_required
def pay(order_id: int):
    data = request.get_json(silent=True) or {}
    db = get_db()
    order = db.execute(
        "SELECT * FROM orders WHERE order_id = ? AND user_id = ?",
        (order_id, g.user_id),
    ).fetchone()
    if not order:
        return jsonify({"error": "订单不存在"}), 404
    if order["status"] != "pending":
        return jsonify({"error": "订单状态异常: %s" % order["status"]}), 400

    elapsed = time.time() - order["created_at"]
    if elapsed > ORDER_EXPIRY:
        db.execute("UPDATE orders SET status = 'cancelled' WHERE order_id = ?", (order_id,))
        db.commit()
        logger.info("订单超时取消: order_id=%d", order_id)
        return jsonify({"error": "订单已超过有效期(60秒)，已自动取消"}), 400

    gas_price_info = get_current_gas_price()
    current_gas_price = gas_price_info["last_base_fee"]
    rate = get_eth_cny_rate()

    chain_data = data.get("chain_data", {})
    gas_limit_user = int(data.get("gas_limit", 100000))

    current_cost_eth = Decimal(gas_limit_user * current_gas_price) / Decimal(10 ** 18)
    current_cost = quantize(current_cost_eth * rate)
    payment_price = Decimal(str(chain_data.get("payment_price", data.get("payment_price", "0"))))

    if payment_price == 0:
        gas_limit_est = estimate_gas(order["encryption_mode"])
        pricing = calc_order_price(gas_limit_est, current_gas_price, 1.2)
        payment_price = Decimal(str(pricing["payment_price"]))

    if current_cost > payment_price:
        db.execute("UPDATE orders SET status = 'refunded', paid_amount = 0 WHERE order_id = ?", (order_id,))
        db.commit()
        logger.info("二次校验失败退款: order_id=%d, cost=%.2f > price=%.2f", order_id, current_cost, payment_price)
        return jsonify({"error": "当前Gas费用超出支付价格，订单已退款"}), 400

    user = db.execute("SELECT storage_balance FROM users WHERE user_id = ?", (g.user_id,)).fetchone()
    balance = Decimal(str(user["storage_balance"]))
    balance_deduct = min(balance, payment_price)
    online_pay = payment_price - balance_deduct

    if balance_deduct > 0:
        db.execute("UPDATE users SET storage_balance = storage_balance - ? WHERE user_id = ?",
                   (float(balance_deduct), g.user_id))
        logger.info("储值扣款: order_id=%d, amount=%.2f CNY", order_id, balance_deduct)
    if online_pay > 0:
        logger.info("模拟在线支付: order_id=%d, amount=%.2f CNY", order_id, online_pay)

    db.execute(
        "UPDATE orders SET status = 'paid', paid_amount = ?, exchange_rate = ? WHERE order_id = ?",
        (float(payment_price), float(rate), order_id),
    )
    db.commit()
    logger.info("订单已支付: order_id=%d, amount=%.2f CNY (储值%.2f + 在线%.2f)",
                order_id, payment_price, balance_deduct, online_pay)

    db.execute("UPDATE orders SET status = 'onchain' WHERE order_id = ?", (order_id,))
    db.commit()

    max_fee_per_gas = int(current_gas_price * float(data.get("gas_multiplier", 1.2)))
    max_priority_fee = min(gas_price_info.get("max_priority_fee", 1_500_000_000), max_fee_per_gas)

    tx_data = {
        "hash": bytes.fromhex(chain_data.get("hash", "").replace("0x", "")),
        "user_id": bytes.fromhex(chain_data.get("user_id", "").replace("0x", "")),
    }
    if order["encryption_mode"] == "sha3-256+ed25519":
        tx_data["signature1"] = bytes.fromhex(chain_data.get("signature1", "").replace("0x", ""))
        tx_data["signature2"] = bytes.fromhex(chain_data.get("signature2", "").replace("0x", ""))
    else:
        tx_data["signature"] = bytes.fromhex(chain_data.get("signature", "").replace("0x", ""))

    try:
        tx_hash = send_transaction(
            order["encryption_mode"], tx_data, gas_limit_user,
            max_fee_per_gas, max_priority_fee,
        )
        receipt = wait_for_receipt(tx_hash)

        onchain_rate = get_eth_cny_rate()
        cost = calc_actual_cost(
            receipt["gas_used"], receipt["effective_gas_price"],
            onchain_rate,
        )
        refund = calc_refund(payment_price, Decimal(str(cost["final_cost"])))

        db.execute(
            """UPDATE orders SET status = 'success',
               gas_used = ?, gas_price = ?, exchange_rate = ?,
               onchain_at = ?, block_number = ?, tx_hash = ?
               WHERE order_id = ?""",
            (
                receipt["gas_used"],
                receipt["effective_gas_price"],
                float(onchain_rate),
                time.time(),
                receipt["block_number"],
                bytes.fromhex(tx_hash.replace("0x", "")),
                order_id,
            ),
        )
        db.commit()

        if refund > 0:
            db.execute(
                "UPDATE users SET storage_balance = storage_balance + ? WHERE user_id = ?",
                (float(refund), g.user_id),
            )
            db.commit()
            logger.info("退款存入余额: order_id=%d, refund=%.2f CNY", order_id, refund)

        logger.info(
            "上链成功: order_id=%d, tx=%s, block=%d, gas=%d, cost=%.2f, refund=%.2f",
            order_id, tx_hash, receipt["block_number"],
            receipt["gas_used"], cost["final_cost"], refund,
        )

        return jsonify({
            "order_id": order_id,
            "status": "success",
            "tx_hash": tx_hash,
            "block_number": receipt["block_number"],
            "gas_used": receipt["gas_used"],
            "gas_price": receipt["effective_gas_price"],
            "final_cost": cost["final_cost"],
            "refund": float(refund),
        })

    except Exception as e:
        logger.error("上链失败: order_id=%d, error=%s", order_id, str(e))
        db.execute("UPDATE orders SET status = 'refunded', paid_amount = 0 WHERE order_id = ?", (order_id,))
        db.execute(
            "UPDATE users SET storage_balance = storage_balance + ? WHERE user_id = ?",
            (order["paid_amount"], g.user_id),
        )
        db.commit()
        return jsonify({"error": "上链失败，已全额退款: " + str(e)}), 500


@order_bp.route("", methods=["GET"])
@token_required
def list_orders():
    db = get_db()
    orders = db.execute(
        "SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC",
        (g.user_id,),
    ).fetchall()
    result = []
    for o in orders:
        fc, rf = _calc_final_cost(o)
        result.append({
            "order_id": o["order_id"],
            "file_name": o["file_name"],
            "created_at": o["created_at"],
            "encryption_mode": o["encryption_mode"],
            "status": o["status"],
            "paid_amount": o["paid_amount"],
            "gas_used": o["gas_used"],
            "gas_price": o["gas_price"],
            "exchange_rate": o["exchange_rate"],
            "onchain_at": o["onchain_at"],
            "block_number": o["block_number"],
            "tx_hash": o["tx_hash"].hex() if o["tx_hash"] else None,
            "final_cost": fc,
            "refund_amount": rf,
        })
    return jsonify(result)


@order_bp.route("/<int:order_id>", methods=["GET"])
@token_required
def get_order(order_id: int):
    db = get_db()
    o = db.execute(
        "SELECT * FROM orders WHERE order_id = ? AND user_id = ?",
        (order_id, g.user_id),
    ).fetchone()
    if not o:
        return jsonify({"error": "订单不存在"}), 404
    fc, rf = _calc_final_cost(o)
    return jsonify({
        "order_id": o["order_id"],
        "file_name": o["file_name"],
        "created_at": o["created_at"],
        "encryption_mode": o["encryption_mode"],
        "status": o["status"],
        "paid_amount": o["paid_amount"],
        "gas_used": o["gas_used"],
        "gas_price": o["gas_price"],
        "exchange_rate": o["exchange_rate"],
        "onchain_at": o["onchain_at"],
        "block_number": o["block_number"],
        "tx_hash": o["tx_hash"].hex() if o["tx_hash"] else None,
        "final_cost": fc,
        "refund_amount": rf,
    })


@order_bp.route("/<int:order_id>/report", methods=["GET"])
@token_required
def download_report(order_id: int):
    db = get_db()
    o = db.execute(
        "SELECT * FROM orders WHERE order_id = ? AND user_id = ?",
        (order_id, g.user_id),
    ).fetchone()
    if not o:
        return jsonify({"error": "订单不存在"}), 404
    if o["status"] != "success":
        return jsonify({"error": "订单尚未上链成功，无法生成报告"}), 400

    from server.services.report import generate_report
    pdf_data, file_date, tx_short = generate_report(o)

    filename = f"{file_date}-{tx_short}.pdf"
    return send_file(
        BytesIO(pdf_data),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )
