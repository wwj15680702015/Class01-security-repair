import os
import secrets
import sqlite3
from datetime import timedelta

from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash


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


def init_db():
    """初始化 SQLite 数据库（Day3 教学漏洞数据库）。"""
    db_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    os.makedirs(db_dir, exist_ok=True)
    db_path = os.path.join(db_dir, "users.db")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            phone TEXT
        )
    """)
    # 默认用户密码以哈希形式存储
    admin_pw = generate_password_hash("admin123")
    alice_pw = generate_password_hash("alice2025")
    cursor.execute(
        "INSERT OR IGNORE INTO users (username, password, email, phone) "
        "VALUES ('admin', ?, 'admin@example.com', '13800138000')",
        (admin_pw,)
    )
    cursor.execute(
        "INSERT OR IGNORE INTO users (username, password, email, phone) "
        "VALUES ('alice', ?, 'alice@example.com', '13900139001')",
        (alice_pw,)
    )
    conn.commit()
    conn.close()
    print("[SQLite] 数据库初始化完成")


def get_db():
    """获取 SQLite 数据库连接。"""
    db_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    db_path = os.path.join(db_dir, "users.db")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


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
    return render_template(
        "index.html",
        user=public_user,
        search_results=None,
        search_keyword="",
        search_error=None,
    )


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


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        email = (request.form.get("email") or "").strip()
        phone = (request.form.get("phone") or "").strip()

        # 输入验证
        if (
            not username or len(username) > 50
            or not password or len(password) < 6 or len(password) > 128
            or not email or len(email) > 100
            or not phone or len(phone) > 20
        ):
            return render_template(
                "register.html", error="输入格式不正确（用户名1-50，密码6-128，邮箱1-100，手机1-20）"
            ), 400

        # 使用参数化查询和密码哈希
        pw_hash = generate_password_hash(password)
        sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"

        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(sql, (username, pw_hash, email, phone))
            conn.commit()
            conn.close()
            flash("注册成功，请登录")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            return render_template("register.html", error="用户名已存在"), 409
        except sqlite3.Error as e:
            return render_template("register.html", error=f"数据库错误"), 400

    return render_template("register.html")


@app.route("/search", methods=["GET"])
def search():
    if "username" not in session:
        return redirect(url_for("login"))

    keyword = request.args.get("keyword", "").strip()
    search_results = None
    search_error = None

    if keyword:
        if len(keyword) > 100:
            search_error = "搜索关键词过长"
        else:
            # 使用参数化查询修复 SQL 注入
            sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
            print(f"[SQL] 执行搜索: keyword='{keyword}'")

            try:
                conn = get_db()
                cursor = conn.cursor()
                cursor.execute(sql, (f"%{keyword}%", f"%{keyword}%"))
                rows = cursor.fetchall()
                search_results = []
                for row in rows:
                    search_results.append({
                        "id": row["id"],
                        "username": row["username"],
                        "email": row["email"],
                        "phone": row["phone"],
                    })
                conn.close()
            except sqlite3.Error as e:
                print(f"[SQL] 搜索错误: {e}")
                search_error = "搜索查询出错"

    username = session.get("username")
    user = USERS.get(username)
    public_user = safe_user_info(user) if user else None

    return render_template(
        "index.html",
        user=public_user,
        search_results=search_results,
        search_keyword=keyword,
        search_error=search_error,
    )


@app.errorhandler(429)
def rate_limit_exceeded(_error):
    return render_template(
        "login.html", error="登录尝试次数过多，请一分钟后再试"
    ), 429


if __name__ == "__main__":
    init_db()
    debug_enabled = os.environ.get("FLASK_DEBUG") == "1"
    app.run(debug=debug_enabled, host="0.0.0.0", port=5000)
