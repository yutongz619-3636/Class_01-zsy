import hmac
import ipaddress
import logging
import os
import platform
import re
import secrets
import shutil
import sqlite3
import subprocess
import time
import uuid
import warnings
from collections import defaultdict, deque
from contextlib import contextmanager
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from PIL import Image, ImageOps, UnidentifiedImageError
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
PRIVATE_UPLOAD_DIR = BASE_DIR / "uploads"

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32),
    DATABASE_PATH=str(DATA_DIR / "users.db"),
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_COOKIE_SECURE", "0") == "1",
    # 留空时仅允许公网地址；部署者可显式配置 CIDR 白名单以允许内网诊断。
    PING_ALLOWED_NETWORKS=os.environ.get("PING_ALLOWED_NETWORKS", ""),
    # 可选的绝对路径；未配置时仅从受控部署环境的 PATH 查找 ping。
    PING_EXECUTABLE=os.environ.get("PING_EXECUTABLE", ""),
)

ALLOWED_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"}
MAX_IMAGE_PIXELS = 20_000_000
PING_TIMEOUT_SECONDS = 30
PING_RATE_LIMIT = 5
PING_RATE_WINDOW_SECONDS = 60
UPLOAD_MIN_INTERVAL_SECONDS = 3
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 60
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,32}$")

# 这些内存限流适用于单进程课堂演示；生产环境应替换为 Redis 等共享存储。
LOGIN_ATTEMPTS = {}
PING_ATTEMPTS = defaultdict(deque)
UPLOAD_LAST_ACTION = {}
DUMMY_PASSWORD_HASH = generate_password_hash(secrets.token_urlsafe(32))

PRIVATE_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS


def get_db_connection():
    db_path = Path(app.config["DATABASE_PATH"])
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def db_session(immediate=False):
    """提供会自动提交/回滚并关闭连接的 SQLite 会话。"""
    connection = get_db_connection()
    try:
        if immediate:
            # 获取写锁后再读取，避免“先读后写”出现竞态条件。
            connection.execute("BEGIN IMMEDIATE")
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def table_columns(connection, table_name):
    return {row["name"] for row in connection.execute(f"PRAGMA table_info({table_name})")}


def init_db():
    """创建安全的用户表，并将旧版明文密码数据库迁移为哈希。"""
    with db_session() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                phone TEXT,
                balance INTEGER NOT NULL DEFAULT 0,
                role TEXT NOT NULL DEFAULT 'user',
                avatar_filename TEXT
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS recharge_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                amount INTEGER NOT NULL CHECK (amount > 0),
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'approved', 'rejected')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            """
        )
        # 每名用户只能有一条待审核申请；数据库约束可抵御并发重复提交。
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_recharge_one_pending "
            "ON recharge_requests(user_id) WHERE status = 'pending'"
        )
        columns = table_columns(connection, "users")
        role_was_missing = "role" not in columns
        for column, definition in (
            ("password_hash", "TEXT"),
            ("balance", "INTEGER NOT NULL DEFAULT 0"),
            ("role", "TEXT NOT NULL DEFAULT 'user'"),
            ("avatar_filename", "TEXT"),
        ):
            if column not in columns:
                connection.execute(f"ALTER TABLE users ADD COLUMN {column} {definition}")
        columns = table_columns(connection, "users")
        if role_was_missing:
            # 兼容课程旧版本中已有的管理员账户；新部署不会自动创建该账户。
            connection.execute("UPDATE users SET role = 'admin' WHERE username = 'admin'")

        # 兼容旧版 password 列：一旦迁移，原列只保留不可用于登录的标记值。
        if "password" in columns:
            old_rows = connection.execute(
                "SELECT id, password, password_hash FROM users"
            ).fetchall()
            for row in old_rows:
                if not row["password_hash"]:
                    connection.execute(
                        "UPDATE users SET password_hash = ?, password = ? WHERE id = ?",
                        (generate_password_hash(row["password"]), "!migrated!", row["id"]),
                    )

        # 仅在部署者明确提供环境变量时创建演示管理员，避免源码中出现默认凭据。
        bootstrap_username = os.environ.get("BOOTSTRAP_ADMIN_USERNAME")
        bootstrap_password = os.environ.get("BOOTSTRAP_ADMIN_PASSWORD")
        if bootstrap_username and bootstrap_password and USERNAME_PATTERN.fullmatch(bootstrap_username):
            create_user(
                connection,
                bootstrap_username,
                bootstrap_password,
                role="admin",
                ignore_existing=True,
            )


def create_user(connection, username, password, email="", phone="", role="user", ignore_existing=False):
    password_hash = generate_password_hash(password)
    columns = table_columns(connection, "users")
    if "password" in columns:
        sql = (
            "INSERT OR IGNORE INTO users "
            "(username, password, password_hash, email, phone, role) VALUES (?, ?, ?, ?, ?, ?)"
        )
        params = (username, "!migrated!", password_hash, email, phone, role)
    else:
        sql = "INSERT OR IGNORE INTO users (username, password_hash, email, phone, role) VALUES (?, ?, ?, ?, ?)"
        params = (username, password_hash, email, phone, role)
    cursor = connection.execute(sql, params)
    if cursor.rowcount == 0 and not ignore_existing:
        raise sqlite3.IntegrityError("username already exists")
    return cursor.rowcount == 1


def get_current_user():
    if hasattr(g, "current_user"):
        return g.current_user

    user_id = session.get("user_id")
    if not isinstance(user_id, int):
        g.current_user = None
        return None

    with db_session() as connection:
        row = connection.execute(
            "SELECT id, username, email, phone, balance, role, avatar_filename "
            "FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    g.current_user = dict(row) if row else None
    if row is None:
        session.clear()
    return g.current_user


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if get_current_user() is None:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


def validate_csrf():
    token = request.form.get("csrf_token", "")
    stored = session.get("_csrf_token", "")
    return bool(token and stored and hmac.compare_digest(token, stored))


def generate_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_urlsafe(32)
    return session["_csrf_token"]


def csrf_error(template_name=None):
    if template_name:
        return render_template(template_name, error="请求校验失败，请刷新页面后重试"), 400
    abort(400, "请求校验失败，请刷新页面后重试")


def validate_username(username):
    return bool(USERNAME_PATTERN.fullmatch(username or ""))


def validate_password(password):
    if not isinstance(password, str) or not 8 <= len(password) <= 128:
        return False
    return any(char.isalpha() for char in password) and any(char.isdigit() for char in password)


def login_key(username):
    return (request.remote_addr or "unknown", (username or "").strip().lower()[:32])


def seconds_until_login_allowed(key):
    record = LOGIN_ATTEMPTS.get(key)
    if not record:
        return 0
    remaining = int(record.get("locked_until", 0) - time.time())
    if remaining <= 0 and record.get("locked_until"):
        LOGIN_ATTEMPTS.pop(key, None)
        return 0
    return max(0, remaining)


def record_login_failure(key):
    record = LOGIN_ATTEMPTS.setdefault(key, {"failures": 0, "locked_until": 0})
    record["failures"] += 1
    if record["failures"] >= LOGIN_MAX_ATTEMPTS:
        record["locked_until"] = time.time() + LOGIN_LOCKOUT_SECONDS
        return True
    return False


def rate_limit(store, key, limit, window_seconds):
    now = time.monotonic()
    attempts = store[key]
    while attempts and now - attempts[0] >= window_seconds:
        attempts.popleft()
    if len(attempts) >= limit:
        return False
    attempts.append(now)
    return True


def parse_allowed_networks():
    raw_networks = app.config.get("PING_ALLOWED_NETWORKS", "")
    if not raw_networks:
        return []
    networks = []
    for value in raw_networks.split(","):
        value = value.strip()
        if not value:
            continue
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            app.logger.warning("忽略无效的 PING_ALLOWED_NETWORKS 配置项")
    return networks


def is_ping_target_allowed(address):
    allowed_networks = parse_allowed_networks()
    if allowed_networks:
        return any(address.version == network.version and address in network for network in allowed_networks)
    return address.is_global


def get_ping_executable():
    configured_path = (app.config.get("PING_EXECUTABLE") or "").strip()
    if configured_path:
        candidate = Path(configured_path)
        if candidate.is_absolute() and candidate.is_file():
            return str(candidate)
        app.logger.error("PING_EXECUTABLE 必须是存在的绝对路径")
        return None
    return shutil.which("ping")


def avatar_path(filename):
    if not filename or not re.fullmatch(r"[a-f0-9]{32}\.png", filename):
        return None
    candidate = (PRIVATE_UPLOAD_DIR / filename).resolve()
    try:
        candidate.relative_to(PRIVATE_UPLOAD_DIR.resolve())
    except ValueError:
        return None
    return candidate


def normalize_and_save_image(file_storage):
    safe_name = secure_filename(file_storage.filename or "")
    extension = Path(safe_name).suffix.lower()
    if not safe_name or extension not in ALLOWED_IMAGE_EXTENSIONS:
        raise ValueError("仅支持 JPG、PNG、GIF、WebP 或 BMP 图片")

    temporary = None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            file_storage.stream.seek(0)
            with Image.open(file_storage.stream) as image:
                image.verify()

            file_storage.stream.seek(0)
            with Image.open(file_storage.stream) as image:
                width, height = image.size
                if width < 1 or height < 1 or width * height > MAX_IMAGE_PIXELS:
                    raise ValueError("图片尺寸不符合要求")
                normalized = ImageOps.exif_transpose(image)
                normalized.load()
                # 统一重新编码为 PNG，去除原始文件尾随内容、脚本片段和元数据。
                if normalized.mode in {"RGBA", "LA", "P"}:
                    normalized = normalized.convert("RGBA")
                else:
                    normalized = normalized.convert("RGB")
                filename = f"{uuid.uuid4().hex}.png"
                destination = avatar_path(filename)
                temporary = destination.with_suffix(".tmp")
                normalized.save(temporary, format="PNG", optimize=True)
                os.replace(temporary, destination)
                return filename
    except (
        UnidentifiedImageError,
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
        OSError,
        ValueError,
    ) as error:
        if temporary and temporary.exists():
            temporary.unlink(missing_ok=True)
        raise ValueError("文件内容不是有效且安全的图片") from error


@app.context_processor
def inject_template_vars():
    user = get_current_user()
    return {
        "current_user_id": user["id"] if user else None,
        "current_user_role": user["role"] if user else None,
        "csrf_token": generate_csrf_token(),
    }


@app.after_request
def apply_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
    )
    if app.config["SESSION_COOKIE_SECURE"]:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if request.endpoint in {"profile", "avatar"}:
        response.headers.setdefault("Cache-Control", "no-store, private")
    return response


@app.errorhandler(413)
def request_entity_too_large(_error):
    return render_template("upload.html", error="文件不能超过 5 MB"), 413


@app.route("/")
def index():
    return render_template("index.html", user=get_current_user())


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if not validate_csrf():
            return csrf_error("login.html")

        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        key = login_key(username)
        remaining = seconds_until_login_allowed(key)
        if remaining:
            return render_template("login.html", error=f"账号已锁定，请在 {remaining} 秒后重试"), 429

        with db_session() as connection:
            row = connection.execute(
                "SELECT id, username, password_hash FROM users WHERE username = ?", (username,)
            ).fetchone()

        password_hash = row["password_hash"] if row else DUMMY_PASSWORD_HASH
        password_is_valid = check_password_hash(password_hash, password)
        if row and password_is_valid:
            LOGIN_ATTEMPTS.pop(key, None)
            session.clear()
            session["user_id"] = row["id"]
            generate_csrf_token()
            return redirect(url_for("index"))

        locked = record_login_failure(key)
        if locked:
            return render_template("login.html", error=f"账号已锁定 {LOGIN_LOCKOUT_SECONDS} 秒，请稍后重试"), 429
        attempts_left = LOGIN_MAX_ATTEMPTS - LOGIN_ATTEMPTS[key]["failures"]
        return render_template("login.html", error=f"用户名或密码错误，还可尝试 {attempts_left} 次"), 401

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    if not validate_csrf():
        return csrf_error()
    session.clear()
    return redirect(url_for("index"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if not validate_csrf():
            return csrf_error("register.html")

        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        email = (request.form.get("email") or "").strip()[:254]
        phone = (request.form.get("phone") or "").strip()[:32]
        if not validate_username(username):
            return render_template("register.html", error="用户名须为 3–32 位字母、数字或下划线"), 400
        if not validate_password(password):
            return render_template("register.html", error="密码须至少 8 位，并同时包含字母和数字"), 400

        try:
            with db_session() as connection:
                create_user(connection, username, password, email, phone)
        except sqlite3.IntegrityError:
            return render_template("register.html", error="注册信息无法使用，请更换后重试"), 400
        return render_template("login.html", error="注册成功，请登录"), 201

    return render_template("register.html")


@app.route("/search")
@login_required
def search():
    keyword = (request.args.get("keyword") or "").strip()[:50]
    results = []
    if keyword:
        # 转义 LIKE 的通配符，避免 % / _ 被用于批量枚举用户资料。
        escaped_keyword = keyword.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        with db_session() as connection:
            rows = connection.execute(
                "SELECT id, username FROM users WHERE username LIKE ? ESCAPE '\\' ORDER BY id LIMIT 20",
                (f"%{escaped_keyword}%",),
            ).fetchall()
        results = [dict(row) for row in rows]
    return render_template(
        "index.html", user=get_current_user(), search_results=results, keyword=keyword
    )


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    user = get_current_user()
    if request.method == "POST":
        if not validate_csrf():
            return csrf_error("upload.html")
        last_action = UPLOAD_LAST_ACTION.get(user["id"], 0)
        if time.monotonic() - last_action < UPLOAD_MIN_INTERVAL_SECONDS:
            return render_template("upload.html", error="上传过于频繁，请稍后再试"), 429

        file_storage = request.files.get("file")
        if not file_storage or not file_storage.filename:
            return render_template("upload.html", error="请选择一个图片文件"), 400

        try:
            filename = normalize_and_save_image(file_storage)
        except ValueError as error:
            return render_template("upload.html", error=str(error)), 400

        old_path = avatar_path(user.get("avatar_filename"))
        with db_session() as connection:
            connection.execute("UPDATE users SET avatar_filename = ? WHERE id = ?", (filename, user["id"]))
        UPLOAD_LAST_ACTION[user["id"]] = time.monotonic()
        if old_path and old_path.exists():
            old_path.unlink(missing_ok=True)
        g.current_user = None
        return render_template("upload.html", file_url=url_for("avatar"))

    return render_template("upload.html")


@app.route("/avatar")
@login_required
def avatar():
    user = get_current_user()
    path = avatar_path(user.get("avatar_filename"))
    if path is None or not path.is_file():
        abort(404)
    return send_file(path, mimetype="image/png", conditional=True, max_age=0)


@app.route("/ping", methods=["GET", "POST"])
@login_required
def ping():
    ip = ""
    output = None
    if request.method == "POST":
        if not validate_csrf():
            return render_template("ping.html", ip=ip, output="请求校验失败，请刷新页面后重试"), 400

        ip = (request.form.get("ip") or "").strip()
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return render_template("ping.html", ip=ip, output="IP 地址格式无效，请输入合法的 IPv4 或 IPv6 地址")

        if not is_ping_target_allowed(address):
            return render_template(
                "ping.html",
                ip=str(address),
                output="该目标不在允许的网络范围内，仅支持公网地址或管理员配置的白名单",
            ), 403

        user = get_current_user()
        if not rate_limit(PING_ATTEMPTS, user["id"], PING_RATE_LIMIT, PING_RATE_WINDOW_SECONDS):
            return render_template("ping.html", ip=str(address), output="Ping 请求过于频繁，请稍后再试"), 429

        executable = get_ping_executable()
        if not executable:
            app.logger.error("系统未找到 ping 可执行文件")
            return render_template("ping.html", ip=str(address), output="网络诊断服务暂不可用"), 503
        count_flag = "-n" if platform.system() == "Windows" else "-c"
        command = [executable, count_flag, "3", str(address)]
        try:
            output = subprocess.check_output(
                command,
                shell=False,
                stderr=subprocess.STDOUT,
                timeout=PING_TIMEOUT_SECONDS,
            ).decode("utf-8", errors="replace")
        except subprocess.CalledProcessError:
            output = "Ping 未成功完成，目标可能不可达"
        except subprocess.TimeoutExpired:
            output = "Ping 命令执行超时"
        except OSError:
            app.logger.exception("Ping 执行失败")
            output = "网络诊断服务暂不可用"

    return render_template("ping.html", ip=ip, output=output)


@app.route("/profile")
@login_required
def profile():
    user = get_current_user()
    with db_session() as connection:
        requests = connection.execute(
            "SELECT id, amount, status, created_at FROM recharge_requests "
            "WHERE user_id = ? ORDER BY id DESC LIMIT 10",
            (user["id"],),
        ).fetchall()
    return render_template("profile.html", user_info=user, recharge_requests=[dict(row) for row in requests])


@app.route("/recharge", methods=["POST"])
@login_required
def recharge():
    if not validate_csrf():
        return csrf_error()
    user = get_current_user()
    try:
        amount = int(request.form.get("amount", "0"))
    except (TypeError, ValueError):
        amount = 0
    if amount <= 0 or amount > 9_999_999:
        flash("充值金额必须是 1 到 9,999,999 之间的整数", "error")
        return redirect(url_for("profile"))

    try:
        with db_session(immediate=True) as connection:
            connection.execute(
                "INSERT INTO recharge_requests (user_id, amount, status) VALUES (?, ?, 'pending')",
                (user["id"], amount),
            )
    except sqlite3.IntegrityError:
        flash("已有待审核的充值申请，请勿重复提交", "error")
        return redirect(url_for("profile"))
    flash("充值申请已提交，余额将在管理员审核后更新", "success")
    return redirect(url_for("profile"))


@app.route("/admin/recharge/<int:request_id>/approve", methods=["POST"])
@login_required
def approve_recharge(request_id):
    if not validate_csrf():
        return csrf_error()
    admin = get_current_user()
    if admin["role"] != "admin":
        abort(403)
    with db_session(immediate=True) as connection:
        approved = connection.execute(
            "UPDATE recharge_requests SET status = 'approved' WHERE id = ? AND status = 'pending'",
            (request_id,),
        )
        if approved.rowcount != 1:
            abort(404)
        request_row = connection.execute(
            "SELECT user_id, amount FROM recharge_requests WHERE id = ?", (request_id,)
        ).fetchone()
        connection.execute(
            "UPDATE users SET balance = balance + ? WHERE id = ?",
            (request_row["amount"], request_row["user_id"]),
        )
    flash("充值申请已审核", "success")
    return redirect(url_for("admin_recharge_requests"))


@app.route("/admin/recharge-requests")
@login_required
def admin_recharge_requests():
    admin = get_current_user()
    if admin["role"] != "admin":
        abort(403)
    with db_session() as connection:
        rows = connection.execute(
            "SELECT recharge_requests.id, recharge_requests.amount, recharge_requests.status, "
            "recharge_requests.created_at, users.username "
            "FROM recharge_requests JOIN users ON users.id = recharge_requests.user_id "
            "ORDER BY recharge_requests.id DESC LIMIT 100"
        ).fetchall()
    return render_template("admin_recharge_requests.html", recharge_requests=[dict(row) for row in rows])


@app.route("/change-password", methods=["POST"])
@login_required
def change_password():
    if not validate_csrf():
        return csrf_error()
    user = get_current_user()
    current_password = request.form.get("current_password") or ""
    new_password = request.form.get("new_password") or ""
    confirm_password = request.form.get("confirm_password") or ""
    if new_password != confirm_password:
        flash("两次输入的新密码不一致", "error")
        return redirect(url_for("profile"))
    if not validate_password(new_password):
        flash("新密码须至少 8 位，并同时包含字母和数字", "error")
        return redirect(url_for("profile"))

    with db_session() as connection:
        row = connection.execute("SELECT password_hash FROM users WHERE id = ?", (user["id"],)).fetchone()
        if row is None or not check_password_hash(row["password_hash"], current_password):
            flash("当前密码不正确", "error")
            return redirect(url_for("profile"))
        connection.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password), user["id"]),
        )
    session.clear()
    flash("密码已修改，请使用新密码重新登录", "success")
    return redirect(url_for("login"))


@app.route("/page")
def page():
    # 固定模板白名单替代“参数 → 文件路径”映射，消除路径遍历与本地文件包含风险。
    page_name = request.args.get("name", "")
    allowed_pages = {"help": "help.html"}
    template_name = allowed_pages.get(page_name)
    if not template_name:
        abort(404)
    return render_template(template_name)


@app.route("/welcome")
def welcome():
    name = (request.args.get("name") or "")[:80]
    welcome_text = "亲爱的用户，欢迎你！" if not name else f"欢迎你，{name}！"
    return render_template("welcome.html", welcome_text=welcome_text, name=name)


@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    if request.method == "POST":
        if not validate_csrf():
            return csrf_error("feedback.html")
        name = (request.form.get("name") or "")[:80]
        message = (request.form.get("message") or "")[:2000]
        if not name or not message:
            return render_template("feedback.html", error="姓名和反馈内容不能为空"), 400
        return render_template("feedback.html", name=name, message=message)
    return render_template("feedback.html")


init_db()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.run(debug=False, host="127.0.0.1", port=5000)
