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
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT
        )
    ''')
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES ('admin', 'admin123', 'admin@example.com', '13800138000')")
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES ('alice', 'alice2025', 'alice@example.com', '13900139001')")
    conn.commit()
    conn.close()


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


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
