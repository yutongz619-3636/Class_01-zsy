# Class01 用户管理系统（安全修复版）

这是一个用于课程演示的 Flask 登录项目。修复版增加了失败次数统计和临时锁定，并移除了页面与源码中的明文密码泄露。

## 防暴力破解规则

- 按“客户端 IP + 用户名”统计失败次数。
- 连续失败 5 次后锁定 60 秒。
- 锁定期间即使密码正确也不能登录。
- 登录成功后清空该来源的失败记录。
- 普通登录失败返回 HTTP 401，触发锁定返回 HTTP 429。

## Linux 启动方式

```bash
cd /opt/Class01
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
python3 app.py
```

浏览器访问 `http://127.0.0.1:5000`。从同一局域网的其他电脑访问时，使用服务器实际 IP，例如 `http://192.168.73.128:5000`。

## 运行测试

```bash
cd /opt/Class01
source .venv/bin/activate
python3 -m unittest discover -s tests -v
```

## 说明

当前失败记录保存在内存字典中，适合单进程课堂演示。服务器重启后记录会清空；正式项目应将记录保存到 Redis 或数据库，并使用 HTTPS 和生产级 WSGI 服务器。
