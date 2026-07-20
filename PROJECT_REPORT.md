# Flask 用户信息管理平台 — 项目报告

**项目名称**：用户信息管理平台  
**开发框架**：Python Flask  
**数据库**：SQLite  
**项目地址**：https://github.com/yutongz619-3636/Class_01-zsy  
**报告日期**：2026-07-20

---

## 一、项目概述

本项目是一个基于 Python Flask 框架开发的简易用户信息管理 Web 平台，提供用户登录、注册、信息展示和搜索功能。前端使用原生 HTML + CSS，后端数据存储采用内存字典（用户信息）和 SQLite 数据库（注册用户）双重架构。

### 项目定位

- 学习型 Demo 项目，用于演示 Flask Web 开发基础
- 包含完整的 CRUD 操作演示（查询用户、创建用户、搜索用户）
- 故意保留了若干安全漏洞，用于 SQL 注入等安全攻防教学演示

---

## 二、技术栈

| 技术 | 用途 |
|------|------|
| Python 3 + Flask | Web 框架 |
| Jinja2 | 模板引擎 |
| SQLite3 | 数据库存储 |
| HTML5 + CSS3 | 前端界面 |
| Git + GitHub | 版本控制与托管 |

---

## 三、项目结构

```
/opt/Class01/
├── app.py                      # Flask 主应用入口
├── static/
│   └── css/
│       └── style.css           # 全局样式表
├── templates/
│   ├── base.html               # 基础模板（导航栏）
│   ├── index.html              # 首页（用户信息 + 搜索）
│   ├── login.html              # 登录页
│   └── register.html           # 注册页
├── data/
│   └── users.db                # SQLite 数据库文件（运行时生成）
├── .gitignore
└── flask_user_management.zip   # 项目压缩包
```

---

## 四、功能模块详细说明

### 4.1 用户登录 (`/login`)

**请求方式**：GET / POST

**流程说明**：
1. 用户在登录页输入用户名和密码
2. 后端从内存字典 `USERS` 中查找用户
3. 使用 `==` 直接比对明文密码
4. 验证通过后将用户名存入 session，跳转到首页
5. 验证失败则显示"用户名或密码错误"

**默认账号**：

| 用户名 | 密码 | 角色 | 邮箱 | 手机 | 余额 |
|--------|------|------|------|------|------|
| admin | admin123 | admin | admin@example.com | 13800138000 | 99999 |
| alice | alice2025 | user | alice@example.com | 13900139001 | 100 |

**安全特性**：
- 密码以明文形式存储
- 登录页 HTML 注释中包含调试信息泄露默认账号

### 4.2 用户注册 (`/register`)

**请求方式**：GET / POST

**流程说明**：
1. 用户填写用户名、密码、邮箱、手机号
2. 后端使用 **f-string 字符串拼接** 构造 INSERT SQL 语句
3. 执行插入操作到 SQLite 数据库
4. 用户名重复时提示"用户名已存在"
5. 注册成功后跳转到登录页并提示"注册成功，请登录"

**SQL 示例**（控制台会打印实际执行的 SQL）：
```python
sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
print(f"[SQL] {sql}")
```

### 4.3 用户搜索 (`/search`)

**请求方式**：GET

**流程说明**：
1. 通过 URL 参数 `keyword` 接收搜索关键词
2. 后端使用 **f-string 字符串拼接** 构造 SELECT SQL 语句
3. 按用户名或邮箱模糊匹配（LIKE）
4. 结果以表格形式展示在首页

**SQL 示例**：
```python
sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
print(f"[SQL] {sql}")
```

### 4.4 首页 (`/`)

**功能**：
- 已登录：显示当前用户完整信息（含密码明文）+ 搜索功能
- 未登录：显示"请先登录"提示 + 跳转按钮
- 登录状态下展示：用户名、密码（明文）、邮箱、手机、角色、余额

### 4.5 退出登录 (`/logout`)

清除 session 后重定向到首页。

---

## 五、界面设计

### 5.1 导航栏

- 蓝色渐变背景（`#667eea` → `#764ba2`）
- Flex 布局，左侧品牌名"用户管理系统"
- 右侧根据登录状态显示：欢迎信息 + 退出 / 登录 + 注册

### 5.2 页面风格

- 全局白色背景卡片式布局，圆角 + 阴影
- 统一按钮样式（跟随渐变配色）
- 输入框有边框、内边距和焦点高亮效果
- 响应式主容器（最大宽度 800px）

---

## 六、数据库设计

### 6.1 用户表 (`users`)

| 字段名 | 类型 | 约束 | 说明 |
|--------|------|------|------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT | 用户ID |
| username | TEXT | UNIQUE NOT NULL | 用户名 |
| password | TEXT | NOT NULL | 密码（明文） |
| email | TEXT | | 邮箱 |
| phone | TEXT | | 手机号 |

### 6.2 初始化数据

- admin / admin123
- alice / alice2025

### 6.3 数据流

```
注册 ──→ SQLite (users.db)
登录 ──→ 内存字典 (USERS)
搜索 ──→ SQLite (users.db)
```

---

## 七、安全分析

本项目故意保留了以下安全风险，主要用于教学演示：

| 风险类型 | 位置 | 说明 |
|----------|------|------|
| 🚨 **SQL 注入** | `/register`、`/search` | 使用 f-string 字符串拼接 SQL，未做任何转义或参数化 |
| 🚨 **明文密码** | `app.py` USERS 字典 | 密码直接以明文形式存储和比对 |
| 🚨 **敏感信息泄露** | `login.html` | HTML 注释中包含默认管理员账号密码 |
| 🚨 **信息泄露** | `index.html` | 登录后页面直接展示密码明文 |
| ⚠️ **无输入过滤** | 所有表单 | 用户输入未做任何过滤或转义 |

### SQL 注入演示示例

在搜索框中输入以下内容可触发注入：

```
' OR '1'='1
' UNION SELECT 1, 'admin', 'hacked@test.com', '12345678901' --
```

控制台会打印实际执行的 SQL，便于观察注入效果。

---

## 八、部署指南

### 8.1 本地部署

```bash
# 1. 克隆项目
git clone https://github.com/yutongz619-3636/Class_01-zsy.git
cd Class_01-zsy

# 2. 安装依赖
pip install flask

# 3. 启动服务
python3 app.py

# 4. 访问
# http://localhost:5000
```

### 8.2 默认账号

| 账号 | 密码 | 角色 |
|------|------|------|
| admin | admin123 | 管理员 |
| alice | alice2025 | 普通用户 |

---

## 九、API 接口一览

| 路由 | 方法 | 功能 | 参数 |
|------|------|------|------|
| `/` | GET | 首页 | - |
| `/login` | GET / POST | 用户登录 | `username`, `password` |
| `/logout` | GET | 退出登录 | - |
| `/register` | GET / POST | 用户注册 | `username`, `password`, `email`, `phone` |
| `/search` | GET | 搜索用户 | `keyword` |

---

## 十、版本历史

| 版本 | 日期 | 更新内容 |
|------|------|----------|
| v1.0 | 2026-07-19 | 初始版本：登录功能 + 用户信息展示 |
| v2.0 | 2026-07-20 | 新增：用户注册（SQLite）、用户搜索（SQL LIKE 模糊查询） |

---

## 十一、后续优化建议

1. **数据库统一**：将登录也从 SQLite 验证，统一数据源
2. **密码加密**：使用哈希存储密码（如 bcrypt）
3. **SQL 参数化**：修复 SQL 注入漏洞
4. **输入校验**：增加前后端输入验证
5. **分页**：搜索大量结果时分页展示
6. **用户编辑/删除**：增加完整的用户管理功能

---

> **免责声明**：本项目为学习演示用途，代码中故意保留了安全漏洞用于教学。请勿在正式生产环境中使用。
