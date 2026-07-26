# 项目安全加固说明

## 1. 项目目标

本项目是一个 Flask 用户管理系统课程作业。功能包括注册与登录、个人资料、私有头像上传、充值申请、帮助页面、意见反馈与 Ping 网络诊断。本版本以“可运行功能 + 可验证安全控制”为目标，不在源码、页面或文档中保留可直接使用的默认账号密码。

## 2. 数据模型

### 用户表 `users`

| 字段 | 说明 |
|---|---|
| `id` | 主键 |
| `username` | 唯一用户名 |
| `password_hash` | Werkzeug 生成的密码哈希 |
| `email` / `phone` | 用户资料，仅本人可见 |
| `balance` | 仅由审核后的充值申请更新 |
| `role` | `user` 或 `admin` |
| `avatar_filename` | 私有头像文件名 |

### 充值申请表 `recharge_requests`

提交充值申请不会直接增加余额。申请处于 `pending` 状态，只有管理员使用受保护的审批接口后，系统才在同一数据库事务中更新余额与申请状态。

## 3. 八类漏洞复查结果

| 类别 | 加固措施 | 验证方式 |
|---|---|---|
| 密码泄露 | 删除默认凭据、页面密码展示和密码日志；迁移旧明文为哈希 | 注册/登录/改密测试断言哈希不会回显 |
| SQL 注入 | 所有用户输入通过 SQLite 占位符绑定；搜索转义 `LIKE` 通配符 | SQL 参数化审计与搜索回归测试 |
| 文件上传 | CSRF 前置校验、扩展名白名单、Pillow 解码/像素限制/重新编码、私有读取、单头像替换 | 伪造 JPEG 头、无 CSRF 上传和私有头像测试 |
| 越权与业务逻辑 | session 保存用户 ID；个人中心忽略外部 user_id；改密验证当前密码；充值改为待审核 | IDOR、任意改密与重复充值测试 |
| 文件包含 | `/page` 使用固定模板白名单，不再将参数映射为文件路径 | `../`、反斜杠、绝对路径请求均返回 404 |
| SSRF/内网探测 | Ping 默认拒绝非公网地址；可配置受控 CIDR 白名单；按用户限频 | 环回、私网、链路本地地址均不会启动子进程 |
| SSTI / XSS | 使用固定 Jinja 模板；删除动态 `safe` 输出；自动转义用户输入；加入 CSP | `{{ 7*7 }}` 和 HTML 事件属性载荷原样转义 |
| 命令执行 | `ipaddress` 解析目标；参数列表调用；`shell=False`；固定次数/超时 | Shell 元字符、换行和选项注入载荷均不调用 subprocess |

## 4. 会话与响应安全

- 登录成功后清空旧会话并生成新的 CSRF Token，避免会话固定。
- Cookie 启用 `HttpOnly`、`SameSite=Lax`；HTTPS 部署可通过环境变量启用 `Secure`。
- 敏感页面设置 `Cache-Control: no-store, private`。
- 全局设置 `Content-Security-Policy`、`X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY`、`Referrer-Policy` 和 `Permissions-Policy`。

## 5. 测试说明

测试使用 Flask 测试客户端与子进程 Mock，不执行攻击命令。执行：

```bash
python3 -m unittest discover -s tests -v
```

若作为生产系统继续开发，建议将内存登录/Ping 限流迁移至 Redis，接入真实支付回调，使用审计日志与对象存储，并由 CI 持续运行 SAST 与依赖漏洞扫描。
