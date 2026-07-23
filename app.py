import os
import secrets
import sqlite3
import logging
import uuid
from datetime import timedelta
from pathlib import Path

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
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
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

# 商品数据（用于价格篡改漏洞实验）
PRODUCTS = {
    1: {"name": "iPhone 15 Pro Max", "price": 9999.00},
    2: {"name": "MacBook Pro 16", "price": 19999.00},
    3: {"name": "AirPods Pro", "price": 1999.00},
    4: {"name": "iPad Air", "price": 4999.00},
}

# 上传目录
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "uploads")


def deploy_htaccess():
    """在上传目录部署 .htaccess 以禁止 PHP 执行。"""
    htaccess_path = os.path.join(UPLOAD_DIR, ".htaccess")
    if not os.path.exists(htaccess_path):
        try:
            os.makedirs(UPLOAD_DIR, exist_ok=True)
            with open(htaccess_path, "w") as f:
                f.write('<FilesMatch "\\.(php|phtml|php3|php4|php5)$">\n')
                f.write("    Require all denied\n")
                f.write("</FilesMatch>\n")
            print(f"[安全] .htaccess 已部署到 {htaccess_path}")
        except Exception as e:
            print(f"[警告] .htaccess 部署失败: {e}")


# 审计日志配置
audit_logger = logging.getLogger("upload_audit")
audit_logger.setLevel(logging.INFO)
os.makedirs(os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs"), exist_ok=True)
audit_handler = logging.FileHandler(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "upload.log"),
    encoding="utf-8"
)
audit_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
audit_logger.addHandler(audit_handler)


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
        "img-src 'self' data:; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "script-src 'self'; "
        "object-src 'none'"
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


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        if "file" not in request.files:
            return render_template("upload.html", error="未选择文件"), 400

        file = request.files["file"]
        if file.filename == "":
            return render_template("upload.html", error="未选择文件"), 400

        # 校验文件扩展名
        allowed_extensions = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".ico"}
        original_ext = os.path.splitext(file.filename)[1].lower()
        if original_ext not in allowed_extensions:
            return render_template("upload.html", error="仅允许上传图片文件（jpg, jpeg, png, gif, webp, bmp, ico）"), 400

        # 校验文件内容（魔数检查）
        file.seek(0)
        magic_bytes = file.read(12)
        file.seek(0)

        is_valid_image = False
        if magic_bytes[:8] == b"\x89PNG\r\n\x1a\n":
            is_valid_image = True  # PNG
        elif magic_bytes[:2] in (b"\xff\xd8",):
            is_valid_image = True  # JPEG
        elif magic_bytes[:6] in (b"GIF87a", b"GIF89a"):
            is_valid_image = True  # GIF
        elif magic_bytes[:4] == b"RIFF" and magic_bytes[8:12] == b"WEBP":
            is_valid_image = True  # WebP
        elif magic_bytes[:2] in (b"BM",):
            is_valid_image = True  # BMP
        elif magic_bytes[:4] in (b"\x00\x00\x01\x00",):
            is_valid_image = True  # ICO

        if not is_valid_image:
            return render_template("upload.html", error="文件内容不是有效的图片格式"), 400

        # UUID 重命名 + Path.resolve() 路径安全校验
        safe_filename = uuid.uuid4().hex + original_ext
        safe_path = Path(UPLOAD_DIR).resolve()
        os.makedirs(str(safe_path), exist_ok=True)
        final_path = (safe_path / safe_filename).resolve()

        if not str(final_path).startswith(str(safe_path)):
            return render_template("upload.html", error="文件名不合法"), 400

        file.save(str(final_path))

        file_url = url_for("static", filename=f"uploads/{safe_filename}")

        # 审计日志
        audit_logger.info(
            f"用户={session['username']} "
            f"IP={request.remote_addr} "
            f"原始文件={file.filename} "
            f"保存为={safe_filename} "
            f"扩展名={original_ext} "
            f"魔数校验={'通过' if is_valid_image else '失败'}"
        )

        return render_template(
            "upload.html", success=True, file_url=file_url, filename=safe_filename
        )

    return render_template("upload.html")


@app.route("/profile", methods=["GET"])
def profile():
    if "username" not in session:
        return redirect(url_for("login"))

    user_id = request.args.get("user_id", "").strip()

    if not user_id or not user_id.isdigit():
        return render_template("profile.html", error="无效的用户ID"), 400

    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, email, phone FROM users WHERE id = ?",
            (int(user_id),)
        )
        row = cursor.fetchone()
        conn.close()
    except sqlite3.Error:
        return render_template("profile.html", error="查询用户信息失败"), 400

    if not row:
        return render_template("profile.html", error="用户不存在"), 404

    user_info = {
        "id": row["id"],
        "username": row["username"],
        "email": row["email"],
        "phone": row["phone"],
        "balance": USERS.get(row["username"], {}).get("balance", 0),
    }
    return render_template("profile.html", user=user_info)


@app.route("/recharge", methods=["POST"])
def recharge():
    if "username" not in session:
        return redirect(url_for("login"))

    user_id = request.form.get("user_id", "").strip()
    amount = request.form.get("amount", "").strip()

    if not user_id or not user_id.isdigit():
        return render_template("profile.html", error="无效的用户ID"), 400

    if not amount:
        try:
            amount_float = 0.0
        except ValueError:
            return render_template("profile.html", error="金额格式错误"), 400
    else:
        try:
            amount_float = float(amount)
        except ValueError:
            return render_template("profile.html", error="金额格式错误"), 400

    # 直接修改用户数据中的余额字段：balance = balance + amount
    # 不检查 amount 是否为负数
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username FROM users WHERE id = ?",
            (int(user_id),)
        )
        row = cursor.fetchone()
        conn.close()
    except sqlite3.Error:
        return render_template("profile.html", error="查询用户信息失败"), 400

    if not row:
        return render_template("profile.html", error="用户不存在"), 404

    username = row["username"]
    if username in USERS:
        USERS[username]["balance"] = USERS[username]["balance"] + amount_float
        print(f"[充值] 用户={username} 充值={amount_float} 新余额={USERS[username]['balance']}")

    return redirect(url_for("profile", user_id=user_id))


@app.route("/admin", methods=["GET"])
def admin_panel():
    if "username" not in session:
        return redirect(url_for("login"))
    # 垂直越权漏洞：仅检查了登录，未检查是否为管理员
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, phone FROM users ORDER BY id")
        rows = cursor.fetchall()
        all_users = []
        for row in rows:
            user_data = dict(row)
            user_data["balance"] = USERS.get(row["username"], {}).get("balance", 0)
            all_users.append(user_data)
        conn.close()
    except sqlite3.Error:
        return render_template("admin.html", users=None, error="查询用户列表失败"), 400

    return render_template("admin.html", users=all_users, error=None)


@app.route("/admin/delete-user", methods=["POST"])
def admin_delete_user():
    if "username" not in session:
        return redirect(url_for("login"))
    # 垂直越权漏洞：任何登录用户都可以删除任意用户
    user_id = request.form.get("user_id", "").strip()
    if not user_id or not user_id.isdigit():
        return render_template("admin.html", users=None, error="无效的用户ID"), 400

    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE id = ?", (int(user_id),))
        row = cursor.fetchone()
        if row and row["username"] in USERS:
            del USERS[row["username"]]
        cursor.execute("DELETE FROM users WHERE id = ?", (int(user_id),))
        conn.commit()
        conn.close()
        print(f"[删除] 用户ID={user_id} 已被删除")
    except sqlite3.Error as e:
        return render_template("admin.html", users=None, error="删除用户失败"), 400

    return redirect(url_for("admin_panel"))


@app.route("/shop", methods=["GET"])
def shop():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("shop.html", products=PRODUCTS)


@app.route("/cart", methods=["POST"])
def cart():
    if "username" not in session:
        return redirect(url_for("login"))
    # 业务逻辑漏洞：价格由客户端提交，服务器不信任
    product_id = request.form.get("product_id", "").strip()
    product_name = request.form.get("product_name", "未知商品")
    price = request.form.get("price", "0")
    quantity = request.form.get("quantity", "1")

    try:
        total = float(price) * int(quantity)
    except ValueError:
        return render_template("shop.html", products=PRODUCTS, cart_error="参数格式错误"), 400

    print(f"[购物车] 商品={product_name} 单价={price} 数量={quantity} 总价={total}")
    return render_template(
        "shop.html",
        products=PRODUCTS,
        cart_success=True,
        cart_product=product_name,
        cart_price=price,
        cart_quantity=quantity,
        cart_total=total,
    )


@app.route("/page", methods=["GET"])
def dynamic_page():
    name = request.args.get("name", "").strip()
    if not name:
        return render_template("index.html", user=None, page_error="未指定页面名称"), 400

    page_content = None
    page_error = None

    # 修复：使用 Path.resolve() 校验最终路径是否在 pages 目录内
    pages_dir = Path(os.path.join(os.path.dirname(os.path.abspath(__file__)), "pages")).resolve()
    os.makedirs(str(pages_dir), exist_ok=True)

    # 尝试 name 原样
    candidate = (pages_dir / name).resolve()
    if not str(candidate).startswith(str(pages_dir)):
        page_error = "非法的页面路径"
    elif candidate.is_file():
        try:
            with open(str(candidate), "r", encoding="utf-8") as f:
                page_content = f.read()
        except Exception:
            page_error = "读取页面失败"
    else:
        # 尝试加 .html 后缀
        candidate_html = (pages_dir / (name + ".html")).resolve()
        if str(candidate_html).startswith(str(pages_dir)) and candidate_html.is_file():
            try:
                with open(str(candidate_html), "r", encoding="utf-8") as f:
                    page_content = f.read()
            except Exception:
                page_error = "读取页面失败"
        else:
            page_error = "页面不存在"

    username = session.get("username")
    user = USERS.get(username)
    public_user = safe_user_info(user) if user else None
    return render_template(
        "index.html", user=public_user,
        page_content=page_content, page_name=name, page_error=page_error
    )


@app.errorhandler(429)
def rate_limit_exceeded(_error):
    return render_template(
        "login.html", error="登录尝试次数过多，请一分钟后再试"
    ), 429


if __name__ == "__main__":
    init_db()
    deploy_htaccess()
    debug_enabled = os.environ.get("FLASK_DEBUG") == "1"
    app.run(debug=debug_enabled, host="0.0.0.0", port=5000)
