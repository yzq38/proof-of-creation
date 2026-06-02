import sqlite3
import os
from threading import Lock

_conn = None
_lock = Lock()


def get_db_path():
    from server.utils.config import DATABASE_PATH
    return DATABASE_PATH


def get_db():
    global _conn
    if _conn is None:
        db_path = get_db_path()
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        _conn = sqlite3.connect(db_path, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA foreign_keys=ON")
        init_db(_conn)
    return _conn


def init_db(conn: sqlite3.Connection):
    with _lock:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                user_id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_name        TEXT    UNIQUE NOT NULL,
                password_hash    BLOB    NOT NULL,
                salt             BLOB    NOT NULL,
                storage_balance  REAL    NOT NULL DEFAULT 0.00,
                active_jti       TEXT
            );

            CREATE TABLE IF NOT EXISTS orders (
                order_id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id          INTEGER NOT NULL,
                file_name        TEXT    NOT NULL,
                created_at       REAL    NOT NULL,
                encryption_mode  TEXT    NOT NULL,
                gas_used         REAL,
                gas_price        REAL,
                exchange_rate    REAL,
                status           TEXT    NOT NULL DEFAULT 'pending',
                paid_amount      REAL    NOT NULL DEFAULT 0.00,
                onchain_at       REAL,
                block_number     INTEGER,
                tx_hash          BLOB,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            );

            CREATE INDEX IF NOT EXISTS idx_orders_user_id ON orders(user_id);
            CREATE INDEX IF NOT EXISTS idx_orders_status  ON orders(status);
        """)
        conn.commit()


def close_db():
    global _conn
    if _conn:
        _conn.close()
        _conn = None
