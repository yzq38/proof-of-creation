from decimal import Decimal

from flask import Blueprint, request, jsonify, g

from server.routes.auth import token_required
from server.utils.db import get_db
from server.utils.logger import get_logger
from server.services.pricing import quantize

user_bp = Blueprint("user", __name__, url_prefix="/api/user")
logger = get_logger()


@user_bp.route("/balance", methods=["GET"])
@token_required
def get_balance():
    db = get_db()
    row = db.execute("SELECT storage_balance FROM users WHERE user_id = ?", (g.user_id,)).fetchone()
    return jsonify({"balance": row["storage_balance"]})


@user_bp.route("/deposit", methods=["POST"])
@token_required
def deposit():
    data = request.get_json(silent=True) or {}
    amount = Decimal(str(data.get("amount", "0")))
    if amount <= 0:
        return jsonify({"error": "储值金额必须大于0"}), 400

    db = get_db()
    db.execute(
        "UPDATE users SET storage_balance = storage_balance + ? WHERE user_id = ?",
        (float(amount), g.user_id),
    )
    db.commit()
    row = db.execute("SELECT storage_balance FROM users WHERE user_id = ?", (g.user_id,)).fetchone()
    logger.info("储值: user_id=%d, amount=%.2f, balance=%.2f", g.user_id, amount, row["storage_balance"])
    return jsonify({"message": "储值成功", "amount": float(amount), "balance": row["storage_balance"]})


@user_bp.route("/withdraw", methods=["POST"])
@token_required
def withdraw():
    data = request.get_json(silent=True) or {}
    amount = Decimal(str(data.get("amount", "0")))
    if amount <= 0:
        return jsonify({"error": "提现金额必须大于0"}), 400

    db = get_db()
    row = db.execute("SELECT storage_balance FROM users WHERE user_id = ?", (g.user_id,)).fetchone()
    balance = Decimal(str(row["storage_balance"]))
    if amount > balance:
        return jsonify({"error": "余额不足，当前余额: %.2f" % balance}), 400

    db.execute(
        "UPDATE users SET storage_balance = storage_balance - ? WHERE user_id = ?",
        (float(amount), g.user_id),
    )
    db.commit()
    new_balance = balance - amount
    logger.info("提现: user_id=%d, amount=%.2f, balance=%.2f", g.user_id, amount, new_balance)
    return jsonify({"message": "提现成功", "amount": float(amount), "balance": float(new_balance)})
