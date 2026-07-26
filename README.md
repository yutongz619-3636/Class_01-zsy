# Class_01 用户管理系统（安全加固版）

这是一个用于网络与应用安全课程演示的 Flask 项目。项目保留注册、登录、个人中心、头像上传、充值申请、页面帮助、反馈和 Ping 网络诊断等功能，并针对课程涉及的常见漏洞完成了防护与回归测试。

## 已覆盖的安全措施

- 密码仅以 Werkzeug 哈希形式存储；源码、页面和日志中不保留默认密码或明文密码。
- 登录按「客户端 IP + 用户名」限速：连续失败 5 次后锁定 60 秒。
- 所有敏感状态变更均使用 CSRF Token；会话采用 `HttpOnly` 与 `SameSite=Lax` Cookie。
- SQL 查询均使用参数化绑定；搜索转义 `LIKE` 通配符并最小化返回字段。
- 个人中心仅访问当前会话用户；改密必须校验当前密码和确认密码。
- 充值改为待审核申请，普通用户不能直接修改余额。
- 上传文件使用真实图像解码、像素限制、重新编码和私有下载路由。
- 帮助页面使用固定模板白名单，不接受用户输入作为文件路径或 HTML 模板。
- Ping 使用参数列表和 `shell=False`，限制到公网 IP 或管理员配置的 CIDR 白名单，并设置频率限制。
- 统一返回 CSP、`nosniff`、防嵌入等安全响应头。

## 安装与启动

```bash
cd Class_01-zsy
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 生产/演示环境均应显式配置稳定的随机密钥
export FLASK_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
python3 app.py
```

浏览器访问 `http://127.0.0.1:5000`，首次使用请自行注册账户。

### 可选部署配置

| 变量 | 用途 |
|---|---|
| `FLASK_SECRET_KEY` | 必填建议项；使用至少 32 字节的随机值，避免重启后会话失效。 |
| `FLASK_COOKIE_SECURE=1` | HTTPS 部署时启用 Secure Cookie。 |
| `PING_ALLOWED_NETWORKS` | 逗号分隔 CIDR 白名单，例如 `203.0.113.0/24`；未设置时仅允许公网地址。 |
| `BOOTSTRAP_ADMIN_USERNAME` / `BOOTSTRAP_ADMIN_PASSWORD` | 仅在受控演示环境创建首个管理员；不要将值提交到 Git。 |

## 运行测试

```bash
python3 -m unittest discover -s tests -v
```

测试覆盖密码哈希与暴力破解防护、越权访问、充值审批、上传验证、文件包含、SSTI/XSS、Ping 命令注入和内网探测限制。

## 生产提示

本项目适合课程与原型演示。生产环境还应使用 HTTPS、生产级 WSGI 服务器、集中式限流存储、审计日志、独立对象存储及真实支付回调校验。
