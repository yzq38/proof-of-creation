import hashlib
import os
import uuid
from datetime import datetime, timedelta

import jwt
from flask import Blueprint, request, jsonify, g

from server.utils.config import JWT_SECRET, JWT_EXPIRY
from server.utils.db import get_db
from server.utils.logger import get_logger

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")
logger = get_logger()


def hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.sha3_256(password.encode("utf-8") + salt).digest()


def generate_token(user_id: int, jti: str) -> str:
    payload = {
        "user_id": user_id,
        "jti": jti,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(seconds=JWT_EXPIRY),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def token_required(f):
    from functools import wraps

    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            return jsonify({"error": "未提供认证令牌"}), 401
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            user_id = payload["user_id"]
            jti = payload["jti"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "令牌已过期，请重新登录"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "无效的认证令牌"}), 401

        db = get_db()
        row = db.execute("SELECT active_jti FROM users WHERE user_id = ?", (user_id,)).fetchone()
        if not row or row["active_jti"] != jti:
            return jsonify({"error": "令牌已被覆盖，请在当前设备重新登录"}), 401

        g.user_id = user_id
        return f(*args, **kwargs)

    return decorated


@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "请求数据为空"}), 400

    user_name = (data.get("user_name") or "").strip()
    password = (data.get("password") or "").strip()

    if not user_name or len(user_name) > 32:
        return jsonify({"error": "用户名长度为1-32个字符"}), 400
    if len(password) < 6:
        return jsonify({"error": "密码长度至少6个字符"}), 400

    db = get_db()
    existing = db.execute("SELECT user_id FROM users WHERE user_name = ?", (user_name,)).fetchone()
    if existing:
        return jsonify({"error": "用户名已被注册"}), 409

    salt = os.urandom(16)
    phash = hash_password(password, salt)
    jti = uuid.uuid4().hex

    cursor = db.execute(
        "INSERT INTO users (user_name, password_hash, salt, active_jti) VALUES (?, ?, ?, ?)",
        (user_name, phash, salt, jti),
    )
    db.commit()
    user_id = cursor.lastrowid

    token = generate_token(user_id, jti)
    logger.info(f"用户注册: {user_name} (user_id={user_id})")
    return jsonify({"token": token, "user_id": user_id, "user_name": user_name}), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "请求数据为空"}), 400

    user_name = (data.get("user_name") or "").strip()
    password = (data.get("password") or "").strip()

    if not user_name or not password:
        return jsonify({"error": "用户名和密码不能为空"}), 400

    db = get_db()
    row = db.execute(
        "SELECT user_id, password_hash, salt FROM users WHERE user_name = ?",
        (user_name,),
    ).fetchone()
    if not row:
        return jsonify({"error": "用户名或密码错误"}), 401

    phash = hash_password(password, bytes(row["salt"]))
    if phash != bytes(row["password_hash"]):
        return jsonify({"error": "用户名或密码错误"}), 401

    jti = uuid.uuid4().hex
    db.execute("UPDATE users SET active_jti = ? WHERE user_id = ?", (jti, row["user_id"]))
    db.commit()

    token = generate_token(row["user_id"], jti)
    logger.info(f"用户登录: {user_name} (user_id={row['user_id']})")
    return jsonify({"token": token, "user_id": row["user_id"], "user_name": user_name})


@auth_bp.route("/logout", methods=["POST"])
@token_required
def logout():
    db = get_db()
    db.execute("UPDATE users SET active_jti = NULL WHERE user_id = ?", (g.user_id,))
    db.commit()
    logger.info(f"用户登出: user_id={g.user_id}")
    return jsonify({"message": "已登出"})
