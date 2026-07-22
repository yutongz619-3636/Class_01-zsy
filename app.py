import sqlite3
import os
import uuid
import imghdr
import mimetypes
from flask import Flask, render_template, request, redirect, session, url_for, abort

app = Flask(__name__)
app.secret_key = "dev-key-2025"
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

# 上传配置
UPLOAD_DIR = "static/uploads"
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"}
ALLOWED_MIME_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp", "image/bmp"}
DANGEROUS_KEYWORDS = {".php", ".php3", ".php4", ".php5", ".phtml", ".py", ".pyc", ".jsp",
                      ".jspx", ".asp", ".aspx", ".asa", ".cer", ".cgi", ".pl", ".sh",
                      ".bash", ".exe", ".msi", ".bat", ".cmd", ".vbs", ".js", ".jar",
                      ".war", ".htaccess", ".user.ini"}

# 确保上传目录存在
os.makedirs(UPLOAD_DIR, exist_ok=True)

# 用户数据库（明文密码）
USERS = {
    "admin": {
        "username": "admin",
        "password": "admin123",
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "username": "alice",
        "password": "alice2025",
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}


# ── SQLite 数据库初始化 ─────────────────────────────
def init_db():
    os.makedirs("data", exist_ok=True)
    db_path = os.path.join("data", "users.db")
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    # 创建表（不含 balance，兼容旧数据库）
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT
        )
    ''')
    # 尝试添加 balance 列（如果已存在会静默忽略）
    try:
        c.execute("ALTER TABLE users ADD COLUMN balance INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass  # 列已存在，忽略
    # 插入默认用户（INSERT OR IGNORE 防止重复）
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES ('admin', 'admin123', 'admin@example.com', '13800138000', 99999)")
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES ('alice', 'alice2025', 'alice@example.com', '13900139001', 100)")
    # 确保已有用户有余额
    c.execute("UPDATE users SET balance = 99999 WHERE username = 'admin' AND (balance IS NULL OR balance = 0)")
    c.execute("UPDATE users SET balance = 100 WHERE username = 'alice' AND (balance IS NULL OR balance = 0)")
    conn.commit()
    conn.close()


@app.context_processor
def inject_current_user_id():
    """在全局模板中注入当前登录用户的 user_id"""
    username = session.get("username")
    user_id = None
    if username:
        try:
            db_path = os.path.join("data", "users.db")
            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            c.execute(f"SELECT id FROM users WHERE username = '{username}'")
            row = c.fetchone()
            if row:
                user_id = row[0]
            conn.close()
        except Exception:
            pass
    return dict(current_user_id=user_id)


@app.route("/")
def index():
    username = session.get("username")
    user = USERS.get(username) if username else None
    return render_template("index.html", user=user)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = USERS.get(username)
        if user and user["password"] == password:
            session["username"] = username
            return render_template("index.html", user=user)
        else:
            return render_template("login.html", error="用户名或密码错误")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")
        phone = request.form.get("phone")

        db_path = os.path.join("data", "users.db")
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
        print(f"[SQL] {sql}")
        try:
            c.execute(sql)
            conn.commit()
            return render_template("login.html", error="注册成功，请登录")
        except sqlite3.IntegrityError:
            return render_template("register.html", error="用户名已存在")
        finally:
            conn.close()

    return render_template("register.html")


@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")
    results = []

    if keyword:
        db_path = os.path.join("data", "users.db")
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
        print(f"[SQL] {sql}")
        try:
            c.execute(sql)
            rows = c.fetchall()
            for row in rows:
                results.append({"id": row[0], "username": row[1], "email": row[2], "phone": row[3]})
        except Exception as e:
            print(f"[SQL ERROR] {e}")
        finally:
            conn.close()

    username = session.get("username")
    user = USERS.get(username) if username else None
    return render_template("index.html", user=user, search_results=results, keyword=keyword)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    # 需要登录才能访问
    username = session.get("username")
    if not username:
        return redirect("/login")

    file_url = None
    error = None

    if request.method == "POST":
        file = request.files.get("file")
        if not file or not file.filename:
            error = "请选择一个文件"
        else:
            # 1. 净化文件名，去除路径穿越字符
            safe_filename = os.path.basename(file.filename)

            if not safe_filename or safe_filename == "":
                error = "文件名无效"
            else:
                # 2. 检查文件名中是否含危险关键词（防双扩展名绕过）
                filename_lower = safe_filename.lower()
                has_dangerous = any(kw in filename_lower for kw in DANGEROUS_KEYWORDS)
                if has_dangerous:
                    error = "文件名包含不允许的关键词"
                else:
                    # 3. 检查文件扩展名
                    ext = os.path.splitext(safe_filename)[1].lower()
                    if ext not in ALLOWED_EXTENSIONS:
                        error = f"不允许的文件类型: {ext}，仅支持图片格式 (jpg/png/gif/webp/bmp)"
                    else:
                        # 4. 检查 MIME 类型
                        mime_type = file.content_type
                        if mime_type not in ALLOWED_MIME_TYPES:
                            error = f"不允许的文件 MIME 类型: {mime_type}"
                        else:
                            # 5. 用 UUID 重命名文件，防止覆盖和原始文件名泄露
                            new_filename = f"{uuid.uuid4().hex}{ext}"
                            save_path = os.path.join(UPLOAD_DIR, new_filename)
                            file.save(save_path)

                            # 6. 二次校验：读取文件头确认是真实图片
                            if imghdr.what(save_path) is None:
                                os.remove(save_path)
                                error = "文件内容不是有效图片"
                            else:
                                file_url = url_for("static", filename=f"uploads/{new_filename}")

    return render_template("upload.html", file_url=file_url, error=error)


@app.route("/profile")
def profile():
    # 从 URL 参数获取 user_id，不验证权限
    user_id = request.args.get("user_id", type=int)
    user_info = None

    if user_id:
        db_path = os.path.join("data", "users.db")
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        try:
            c.execute(f"SELECT id, username, email, phone, balance FROM users WHERE id = {user_id}")
            row = c.fetchone()
            if row:
                user_info = {
                    "id": row[0],
                    "username": row[1],
                    "email": row[2],
                    "phone": row[3],
                    "balance": row[4],
                }
        except Exception as e:
            print(f"[SQL ERROR] {e}")
        finally:
            conn.close()

    return render_template("profile.html", user_info=user_info)


@app.route("/recharge", methods=["POST"])
def recharge():
    user_id = request.form.get("user_id", type=int)
    amount = request.form.get("amount", type=int, default=0)

    if user_id is not None:
        db_path = os.path.join("data", "users.db")
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        try:
            # 直接修改余额，不做正负校验
            c.execute(f"UPDATE users SET balance = balance + {amount} WHERE id = {user_id}")
            conn.commit()
            print(f"[RECHARGE] user_id={user_id}, amount={amount}")
        except Exception as e:
            print(f"[SQL ERROR] {e}")
        finally:
            conn.close()

    return redirect(f"/profile?user_id={user_id}")


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
