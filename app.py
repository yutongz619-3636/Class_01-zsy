import math
import os
import secrets
import time

from flask import Flask, redirect, render_template, request, session
from werkzeug.security import check_password_hash


app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# 课程演示配置：同一 IP 对同一用户名连续失败 5 次，锁定 60 秒。
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 60
LOGIN_ATTEMPTS = {}

# 仅保存密码哈希，不在源码中保存或展示明文密码。
USERS = {
    "admin": {
        "username": "admin",
        "password_hash": "scrypt:32768:8:1$ed7HWds2HYRrHEpk$b1e57752ee17eb614bb40f4cafdaddbc8097a09bc275e95f9bcc0fbb9d7aa368119ec29072ddee70b5c9c226534e9d132c4bea5b63bb8c183b713d01b0aec424",
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "username": "alice",
        "password_hash": "scrypt:32768:8:1$scHm8L325GPZ5iMR$031a92587b5161d7cc0952ef67e9e60fec60ce8e682e6fd7b8b3d546242c68759e62cb5543bd7ed802d19a7b8f67afa6c68c41f2c5b654946d67b475565b1150",
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}

PUBLIC_USER_FIELDS = ("username", "role", "email", "phone", "balance")


def get_attempt_key(username):
    """使用客户端 IP 和用户名共同标识一次登录来源。"""
    return (request.remote_addr or "unknown", username)


def get_public_user(user):
    """只返回允许展示的字段，避免把密码哈希传入模板。"""
    return {field: user[field] for field in PUBLIC_USER_FIELDS}


@app.route("/")
def index():
    username = session.get("username")
    user = USERS.get(username) if username else None
    public_user = get_public_user(user) if user else None
    return render_template("index.html", user=public_user)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = (request.form.get("username") or "").strip().lower()
    password = request.form.get("password") or ""
    attempt_key = get_attempt_key(username)
    now = time.time()
    state = LOGIN_ATTEMPTS.get(attempt_key)

    if state and state["locked_until"] > now:
        wait_seconds = math.ceil(state["locked_until"] - now)
        return (
            render_template(
                "login.html",
                error=f"登录失败次数过多，请在 {wait_seconds} 秒后重试",
            ),
            429,
        )

    # 锁定时间已经结束，重新开始统计。
    if state and state["locked_until"]:
        LOGIN_ATTEMPTS.pop(attempt_key, None)
        state = None

    user = USERS.get(username)
    if user and check_password_hash(user["password_hash"], password):
        LOGIN_ATTEMPTS.pop(attempt_key, None)
        session.clear()
        session["username"] = username
        return redirect("/")

    state = state or {"failures": 0, "locked_until": 0}
    state["failures"] += 1
    LOGIN_ATTEMPTS[attempt_key] = state

    if state["failures"] >= MAX_FAILED_ATTEMPTS:
        state["locked_until"] = now + LOCKOUT_SECONDS
        return (
            render_template(
                "login.html",
                error=f"登录失败次数过多，账号已锁定 {LOCKOUT_SECONDS} 秒",
            ),
            429,
        )

    remaining = MAX_FAILED_ATTEMPTS - state["failures"]
    return (
        render_template(
            "login.html",
            error=f"用户名或密码错误，还可尝试 {remaining} 次",
        ),
        401,
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG") == "1"
    app.run(debug=debug_mode, host="0.0.0.0", port=5000)
