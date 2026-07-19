import os
import secrets
from datetime import timedelta

from flask import Flask, render_template, request, redirect, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash


app = Flask(__name__)

# 生产环境应通过 SECRET_KEY 环境变量提供固定密钥。
# 未配置时生成随机密钥，避免在源代码中硬编码。
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE") == "1",
    MAX_CONTENT_LENGTH=16 * 1024,
)

csrf = CSRFProtect(app)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri="memory://",
    headers_enabled=True,
)

ADMIN_HASH = (
    "scrypt:32768:8:1$SkjGyPCyi3hxg59f$"
    "abb7590859d75b896c01f9941dc875beb77c3125912ea4001b58ecf4da0c70ce"
    "7c258635df796a855c2687793be3f546120d79e1494083851f4a1b9983499325"
)

ALICE_HASH = (
    "scrypt:32768:8:1$zuyiLj6SRczN6i0Q$"
    "3e8234157a3f093ce6ca47ea95bf27bce021ff467fe844d1f43a116bfd022562f"
    "e132acab552c9361296bc0c3155ed40dc6f1311705cae0e20244a2e037f110a"
)

USERS = {
    "admin": {
        "username": "admin",
        "password_hash": ADMIN_HASH,
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "username": "alice",
        "password_hash": ALICE_HASH,
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}

# 用于不存在用户的密码校验，降低通过响应耗时枚举用户名的可能性。
DUMMY_PASSWORD_HASH = ADMIN_HASH


def safe_user_info(user):
    """只向页面传递允许公开的字段，不包含密码哈希。"""
    return {
        "username": user["username"],
        "role": user["role"],
        "email": user["email"],
        "phone": user["phone"],
        "balance": user["balance"],
    }


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'"
    )
    return response


@app.route("/")
def index():
    username = session.get("username")
    user = USERS.get(username)
    public_user = safe_user_info(user) if user else None
    return render_template("index.html", user=public_user)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        if (
            not username
            or not password
            or len(username) > 50
            or len(password) > 128
        ):
            return render_template(
                "login.html", error="用户名或密码格式不正确"
            ), 400

        user = USERS.get(username)
        stored_hash = (
            user["password_hash"] if user else DUMMY_PASSWORD_HASH
        )
        password_is_valid = check_password_hash(stored_hash, password)

        if user and password_is_valid:
            session.clear()
            session["username"] = username
            session.permanent = True
            return redirect(url_for("index"))

        return render_template(
            "login.html", error="用户名或密码错误"
        ), 401

    return render_template("login.html")


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.errorhandler(429)
def rate_limit_exceeded(_error):
    return render_template(
        "login.html", error="登录尝试次数过多，请一分钟后再试"
    ), 429


if __name__ == "__main__":
    debug_enabled = os.environ.get("FLASK_DEBUG") == "1"
    app.run(debug=debug_enabled, host="0.0.0.0", port=5000)
