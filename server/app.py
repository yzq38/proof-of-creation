import os
import sys
import threading
import time

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from flask import Flask

from server.utils.config import HOST, PORT, LOG_DIR, LOG_LEVEL, ORDER_EXPIRY, SSL_CERT, SSL_KEY, check_config
from server.utils.logger import setup_logger, get_logger
from server.routes.auth import auth_bp
from server.routes.orders import order_bp
from server.routes.user import user_bp


def create_app():
    app = Flask(__name__, template_folder="../web/templates", static_folder="../web/static")

    app.register_blueprint(auth_bp)
    app.register_blueprint(order_bp)
    app.register_blueprint(user_bp)

    @app.route("/")
    def index():
        from flask import render_template
        return render_template("index.html")

    @app.route("/api/health")
    def health():
        from server.utils.db import get_db
        get_db()
        return {"status": "ok"}

    @app.after_request
    def _no_cache(response):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    return app


def _expire_orders_worker():
    from server.utils.db import get_db
    logger = get_logger()
    while True:
        try:
            db = get_db()
            db.execute(
                "UPDATE orders SET status = 'cancelled' "
                "WHERE status = 'pending' AND (? - created_at) > ?",
                (time.time(), ORDER_EXPIRY),
            )
            db.commit()
        except Exception:
            pass
        time.sleep(30)


def main():
    logger = setup_logger(LOG_DIR, LOG_LEVEL)
    logger.info("Proof Of Creation 服务器正在启动...")

    try:
        check_config()
    except RuntimeError as e:
        logger.warning(str(e))
        logger.info("如需运行完整功能，请先完成配置。开发模式下继续启动...")

    threading.Thread(target=_expire_orders_worker, daemon=True).start()

    app = create_app()

    ssl_context = None
    if SSL_CERT and SSL_KEY and os.path.exists(SSL_CERT) and os.path.exists(SSL_KEY):
        ssl_context = (SSL_CERT, SSL_KEY)
        logger.info("已启用 HTTPS: %s / %s", SSL_CERT, SSL_KEY)
    else:
        logger.info("未找到证书，使用 HTTP 模式")

    proto = "https" if ssl_context else "http"
    logger.info("服务器启动于 %s://%s:%d", proto, HOST, PORT)
    app.run(host=HOST, port=PORT, ssl_context=ssl_context, debug=True)


if __name__ == "__main__":
    main()
