import sqlite3
import os
from flask import Flask, render_template, request, redirect, session, url_for

app = Flask(__name__)
app.secret_key = "dev-key-2025"
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

# 确保上传目录存在
os.makedirs("static/uploads", exist_ok=True)

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
    # 插入默认用户（INSERT OR IGNORE 防止重复）
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
        # 使用 f-string 字符串拼接（不安全的写法，用于演示）
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
        # 使用 f-string 字符串拼接（不安全的写法，用于演示）
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
        if file and file.filename:
            # 使用用户上传的原始文件名保存，不做任何检查
            save_path = os.path.join("static/uploads", file.filename)
            file.save(save_path)
            file_url = url_for("static", filename=f"uploads/{file.filename}")
        else:
            error = "请选择一个文件"

    return render_template("upload.html", file_url=file_url, error=error)


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
