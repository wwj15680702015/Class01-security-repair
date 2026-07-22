# SQL 注入漏洞修复报告

——项目：用户信息管理平台（Flask + SQLite）

| 项目 | 内容 |
|------|------|
| **姓名** | 王文杰 |
| **学号** | 2024141530132 |
| **报告日期** | 2026-07-20 |
| **报告版本** | v2.0（完整版） |
| **漏洞评级** | 🔴 严重（Critical） |

---

## 📋 目录

1. [项目背景](#1-项目背景)
2. [SQL 注入原理概述](#2-sql-注入原理概述)
3. [漏洞详情与复现](#3-漏洞详情与复现)
   - 3.1 漏洞一：搜索功能 SQL 注入
   - 3.2 漏洞二：注册功能 SQL 注入
   - 3.3 漏洞三：密码明文存储与泄露
   - 3.4 漏洞四：代码注释泄露管理员账号
4. [修复方案详解](#4-修复方案详解)
   - 4.1 核心修复：参数化查询
   - 4.2 搜索路由修复前后对比
   - 4.3 注册路由修复前后对比
   - 4.4 密码安全修复
   - 4.5 Session 安全加固
5. [修复效果验证](#5-修复效果验证)
   - 5.1 攻击测试对比
   - 5.2 控制台 SQL 输出对比
   - 5.3 正常功能验证
6. [代码文件变更清单](#6-代码文件变更清单)
7. [安全加固总结与建议](#7-安全加固总结与建议)
8. [附录](#8-附录)

---

## 1. 项目背景

本项目是一个基于 Python Flask 框架构建的简易用户信息管理平台，提供以下核心功能：

| 功能 | 路由 | 说明 |
|------|------|------|
| 用户登录 | `/login` | Session 认证，密码 scrypt 哈希比对 |
| 用户注册 | `/register` | 新用户写入 SQLite 数据库 |
| 用户搜索 | `/search` | 按用户名/邮箱搜索用户 |
| 个人首页 | `/` | 展示登录用户信息 |
| 退出登录 | `/logout` | 清除 Session |

**技术栈**：Python 3.13 / Flask 3.1.3 / SQLite3 / Werkzeug / Jinja2

---

## 2. SQL 注入原理概述

### 2.1 什么是 SQL 注入

SQL 注入（SQL Injection）是 Web 安全中最经典的漏洞类型之一，其本质是应用程序将用户输入直接拼接到 SQL 语句中，使得攻击者可以控制 SQL 语句的结构和逻辑。

### 2.2 SQL 注入的根本原因

```
❌ 应用程序的错误假设：
   "用户输入只是数据，不会改变 SQL 语句的结构"

✅ 安全开发的正确认知：
   "用户输入可能是恶意的，必须与 SQL 代码严格分离"
```

**攻击原理图解：**

```
开发者意图：
  SELECT * FROM users WHERE name = '{用户输入}'
                                       └────┬────┘
                                            │
期望输入："admin"                            │
                                            │
实际查询：SELECT * FROM users WHERE name = 'admin'
                                            │
攻击者输入："admin' OR 1=1 --"              │
                                            │
                                            ▼
实际查询：SELECT * FROM users WHERE name = 'admin' OR 1=1 --'
                              └──────┬──────┘
                                      │
                                    条件永远为真 → 返回全部用户
```

### 2.3 SQL 注入的常见攻击手法

| 攻击手法 | 说明 | 风险等级 |
|---------|------|:--------:|
| OR 永真注入 | 添加 `OR 1=1` 使 WHERE 条件永远为真 | 🔴 高危 |
| UNION 联合查询 | 使用 UNION 合并恶意 SELECT 语句窃取数据 | 🔴 高危 |
| 布尔盲注 | 利用页面响应差异逐位推断数据 | 🟡 中危 |
| 堆叠查询 | 用分号 `;` 分隔执行多条 SQL 语句 | 🔴 高危 |
| 时间盲注 | 利用数据库延时函数推断数据 | 🟡 中危 |

---

## 3. 漏洞详情与复现

### 3.1 漏洞一：搜索功能 SQL 注入（VULN-01）

| 项目 | 内容 |
|------|------|
| **漏洞位置** | `app.py` 第 230 行（修复前） |
| **路由** | `GET /search?keyword=xxx` |
| **注入参数** | `keyword` |
| **风险等级** | 🔴 **严重** |

#### 3.1.1 漏洞代码

```python
# 修复前：f-string 直接拼接 SQL
sql = f"SELECT id, username, email, phone FROM users \
        WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
c.execute(sql)  # ❌ 直接执行拼接后的 SQL
```

**问题分析：**
1. 没有对用户输入中的特殊字符（`'`、`"`、`;`、`--`）做任何转义
2. 使用 f-string 在 Python 层就完成了拼接，数据库无法区分代码和数据
3. `keyword` 直接从 URL 参数获取，攻击者可以构造任意 payload

#### 3.1.2 攻击复现一：OR 注入绕过搜索条件

**Payload：**
```
keyword=xxx' OR 1=1 --
```

**控制台实际执行的 SQL：**
```sql
SELECT id, username, email, phone FROM users
WHERE username LIKE '%xxx' OR 1=1 --%' OR email LIKE '%xxx' OR 1=1 --%'
```

**语句解析：**
```
WHERE username LIKE '%xxx'      → 正常 LIKE 匹配，不匹配任何记录
                     OR 1=1    → 永远为真，WHERE 条件整体为真
                            -- → 注释掉后续的 OR email LIKE '...'
                              → 实际等价于：WHERE 1=1
```

**攻击结果：** 全部用户的 id、用户名、邮箱、手机号被返回

```bash
$ curl "http://localhost:5000/search?keyword=xxx'%20OR%201=1%20--"
# 返回结果包含：admin、alice 等全部用户 ✅
```

#### 3.1.3 攻击复现二：UNION SELECT 窃取密码

**Payload：**
```
keyword=' UNION SELECT id,username,password,phone FROM users --
```

**控制台实际执行的 SQL：**
```sql
SELECT id, username, email, phone FROM users
WHERE username LIKE '%' UNION SELECT id,username,password,phone FROM users --%'
```

**语句解析：**
```
前半段：SELECT ... FROM users WHERE username LIKE '%'
       → 正常查询（可能返回空或少量数据）
UNION：合并两个查询结果集
后半段：SELECT id, username, password, phone FROM users
       → ⚠ 直接查询了 password 字段！
       → 密码以明文形式存储在数据库中！
```

**攻击结果：** 所有用户的密码字段被窃取！

```
ID=1  User=admin   Pass=admin123    Phone=13800138000
ID=2  User=alice   Pass=alice2025   Phone=13900139001
```

#### 3.1.4 攻击复现三：读取数据库元数据（sqlite_master）

**Payload：**
```
keyword=' UNION SELECT 1,sql,name,type FROM sqlite_master --
```

**攻击结果：** 攻击者获知完整表结构，可针对性构造进一步攻击

```
type=table   name=users
SQL: CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  email TEXT, phone TEXT
)

type=index   name=sqlite_autoindex_users_1
```

#### 3.1.5 攻击复现四：布尔盲注（Blind SQL Injection）

当页面不直接显示数据时，通过"有结果/无结果"的响应差异逐位推断数据。

**真值探测：**
```
keyword=admin' AND 1=1 --  → 有搜索结果（页面正常）
keyword=admin' AND 1=2 --  → 无搜索结果（页面异常）
```

**逐位猜解密码：**
```
keyword=admin' AND SUBSTR(
  (SELECT password FROM users WHERE username='admin'),1,1
)='a' --
  → 如果 admin 密码第一个字符是 'a'，返回有结果
  → 否则返回无结果

keyword=admin' AND SUBSTR(
  (SELECT password FROM users WHERE username='admin'),1,1
)='b' --
```

重复上述过程，逐位可确定密码为 `admin123`。

---

### 3.2 漏洞二：注册功能 SQL 注入（VULN-02）

| 项目 | 内容 |
|------|------|
| **漏洞位置** | `app.py` 第 201 行（修复前） |
| **路由** | `POST /register` |
| **注入参数** | username, password, email, phone（4 个参数均可注入） |
| **风险等级** | 🔴 **严重** |

#### 3.2.1 漏洞代码

```python
# 修复前：f-string 拼接 INSERT 语句
sql = f"INSERT INTO users (username, password, email, phone) \
        VALUES ('{username}', '{password}', '{email}', '{phone}')"
c.execute(sql)  # ❌ 直接执行拼接后的 SQL
```

四个参数全部直接拼接，任意一个参数均可注入。

#### 3.2.2 攻击复现五：注入创建恶意用户

**Payload（username 字段）：**
```
username=hacker', 'hackpass', 'hack@hack.com', '000'); --
```

**实际执行的 SQL：**
```sql
INSERT INTO users (username, password, email, phone)
VALUES ('hacker', 'hackpass', 'hack@hack.com', '000'); --', 'x', 'x', 'x')
        ↑          ↑            ↑            ↑
    伪造用户名   伪造密码      伪造邮箱     伪造手机号
                                               ↑
                                        闭合括号和 VALUES
                                               ↑
                                        注释掉剩余的 ', 'x', 'x', 'x')
```

**攻击结果：** 数据库插入 hacker 用户

```bash
$ curl -X POST http://localhost:5000/register \
  -d "username=hacker',+'hackpass',+'hack@hack.com',+'000');+--"
# 数据库新增 hacker 用户 ✅
```

**验证 hacker 用户存在：**
```
ID=3  User=hacker  Pass=hackpass  Phone=000
```

#### 3.2.3 攻击复现六：DROP TABLE（毁灭性攻击）

**Payload（username 字段）：**
```
username=x'; DROP TABLE users; --
```

**实际执行的 SQL：**
```sql
INSERT INTO users (username, password, email, phone)
VALUES ('x'); DROP TABLE users; --', 'x', 'x', 'x')
        ↑
    闭合 INSERT
              ↑
          第二条语句：DROP TABLE users
                          ↑
                    删除整个用户表！
                          ↑
                  注释掉后面的内容
```

**攻击结果：** users 表被永久删除，所有用户数据丢失！

> ⚠ 此攻击在实验中已确认理论可行，实际测试中已跳过以避免数据损坏。

---

### 3.3 漏洞三：密码明文存储与泄露（VULN-03 & VULN-04）

#### 3.3.1 密码明文存储

| 项目 | 内容 |
|------|------|
| **漏洞位置** | `app.py` 第 47-64 行（修复前） |
| **风险等级** | 🔴 严重 |

**漏洞代码：**
```python
USERS = {
    "admin": {
        "password": "admin123",  # ❌ 明文密码
        ...
    },
    "alice": {
        "password": "alice2025", # ❌ 明文密码
        ...
    }
}
```

**危害：** 一旦服务器被入侵或代码被查看，所有用户密码直接暴露。

#### 3.3.2 密码前端泄露

**漏洞位置：** `templates/index.html` 第 10 行（修复前）

**漏洞代码：**
```html
<li><strong>密码：</strong>{{ user.password }}</li>  <!-- ❌ 密码传到前端 -->
```

**危害：** 密码字段直接渲染在 HTML 中，任何人查看页面源码即可看到密码。

---

### 3.4 漏洞四：代码注释泄露管理员账号

| 项目 | 内容 |
|------|------|
| **漏洞位置** | `templates/login.html` 第 1 行 |
| **风险等级** | 🟡 中危 |

**漏洞代码：**
```html
<!-- 调试信息 - 默认管理员账号 用户名: admin 密码: admin123 -->
```

攻击者只需查看登录页面 HTML 源代码即可获取管理员账号密码。

---

## 4. 修复方案详解

### 4.1 核心修复：参数化查询（Parameterized Query）

参数化查询是防御 SQL 注入的最根本、最有效的手段。其核心机制是数据库引擎在执行 SQL 时分两步处理：

**步骤 1：编译 SQL 模板（预编译）**

```
SQL 模板：SELECT * FROM users WHERE name = ?

数据库引擎解析 SQL 语句结构，确定：
  - 这是一个 SELECT 查询
  - 查询 users 表
  - WHERE 条件：name = 一个待定的值
  - ? 是占位符，后续会填充

→ SQL 语句结构已被确定，后续参数无法改变结构
```

**步骤 2：绑定参数（填充数据）**

```
参数：('admin' OR 1=1 --)

数据库引擎收到参数后：
  - 将参数视为纯文本字符串，不做 SQL 解析
  - 特殊字符（'、"、;、--）被自动转义为普通字符
  - ' → ''（SQL 标准转义）
  - 最终效果：name = "admin' OR 1=1 --"
```

### 4.2 搜索路由修复前后对比

| 维度 | ❌ 修复前（危险） | ✅ 修复后（安全） |
|------|-----------------|-----------------|
| SQL 模板 | `f"...LIKE '%{keyword}%'..."` | `"...LIKE ?..."` |
| 参数传递 | 直接嵌入字符串 | 通过 `(f"%{keyword}%",)` 元组 |
| 执行方式 | `cursor.execute(sql)` | `cursor.execute(sql, (pattern,))` |
| 用户输入 `' OR 1=1 --` | 变成 SQL 语句一部分 | 被当作普通文本 `%' OR 1=1 --%` |

**修复后代码：**
```python
sql = "SELECT id, username, email, phone FROM users \
       WHERE username LIKE ? OR email LIKE ?"
cursor.execute(sql, (f"%{keyword}%", f"%{keyword}%"))
```

### 4.3 注册路由修复前后对比

| 维度 | ❌ 修复前（危险） | ✅ 修复后（安全） |
|------|-----------------|-----------------|
| SQL 模板 | `f"INSERT INTO ... VALUES ('{u}',...)"` | `"INSERT INTO ... VALUES (?,?,?,?)"` |
| 参数传递 | 4 个字段全部字符串拼接 | 通过 `(username, pw_hash, email, phone)` |
| 密码存储 | 明文存储 | `generate_password_hash(password)` |
| 执行方式 | `cursor.execute(sql)` | `cursor.execute(sql, params)` |

**修复后代码：**
```python
pw_hash = generate_password_hash(password)
sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
cursor.execute(sql, (username, pw_hash, email, phone))
```

### 4.4 密码安全修复

| 位置 | 修复前 | 修复后 |
|------|--------|--------|
| SQLite users 表 | 明文 `admin123`、`alice2025` | `generate_password_hash("admin123")` |
| 新注册用户 | 明文拼接 | `generate_password_hash(password)` |
| 登录校验 | `password == "admin123"` | `check_password_hash(stored_hash, password)` |

### 4.5 Session 安全加固

| 措施 | 配置 |
|------|------|
| 会话过期 | `PERMANENT_SESSION_LIFETIME = 30 分钟` |
| HttpOnly | `SESSION_COOKIE_HTTPONLY = True` |
| SameSite | `SESSION_COOKIE_SAMESITE = "Lax"` |
| Secure | `SESSION_COOKIE_SECURE` 环境变量控制 |

---

## 5. 修复效果验证

### 5.1 攻击测试对比

| 攻击 Payload | 修复前 | 修复后 |
|-------------|:------:|:------:|
| `' OR 1=1 --` 绕过搜索 | ✅ 返回全部用户 | ❌ 返回 0 条（安全） |
| `' UNION SELECT ... password ...` | ✅ 密码泄露 | ❌ UNION 无效（安全） |
| `' UNION SELECT ... sqlite_master` | ✅ 表结构泄露 | ❌ 无返回（安全） |
| 注册注入创建 hacker 用户 | ✅ hacker 写入数据库 | ❌ 注册失败（安全） |
| 查看 HTML 源码获取密码 | ✅ 密码直接显示 | ❌ 无密码字段 |

### 5.2 控制台 SQL 输出对比

**修复前（f-string 拼接）：**
```
[SQL] 执行搜索 SQL: SELECT id, username, email, phone
  FROM users WHERE username LIKE '%xxx' OR 1=1 --%'
  OR email LIKE '%xxx' OR 1=1 --%'
```

**修复后（参数化查询）：**
```
[SQL] 执行搜索: keyword='xxx' OR 1=1 --'
```
控制台只输出搜索关键词，不再输出完整拼接的 SQL 语句。

### 5.3 正常功能验证

| 功能 | 结果 |
|------|:----:|
| `admin/admin123` 正常登录 | ✅ |
| 首页显示用户信息（不含密码） | ✅ |
| 正常搜索 admin 返回正确结果 | ✅ |
| 注册新用户 day3test 成功 | ✅ |
| 退出登录后跳转首页 | ✅ |

---

## 6. 代码文件变更清单

| 文件 | 变更类型 | 说明 |
|------|---------|------|
| `app.py` | 修改 | 搜索+注册改为参数化查询，密码哈希，输入验证 |
| `templates/index.html` | 修改 | 删除密码字段，添加搜索区域 |
| `templates/base.html` | 修改 | 添加注册链接，flash 消息支持 |
| `templates/register.html` | **新增** | 注册页面 |
| `templates/login.html` | 修改 | 删除调试账号注释 |
| `static/css/style.css` | 修改 | 搜索区域、flash 消息样式 |
| `.gitignore` | 修改 | 添加 `data/`、`logs/` 排除规则 |

---

## 7. 安全加固总结与建议

### 7.1 本次修复清单

| 漏洞 | 风险等级 | 修复方式 | 状态 |
|------|:--------:|---------|:----:|
| 搜索接口 f-string SQL 注入 | 🔴 严重 | 参数化查询 | ✅ 已修复 |
| 注册接口 f-string SQL 注入 | 🔴 严重 | 参数化查询 | ✅ 已修复 |
| 密码明文存储 | 🔴 严重 | generate_password_hash | ✅ 已修复 |
| 页面泄露明文密码 | 🟡 中危 | safe_user_info 过滤 | ✅ 已修复 |
| 代码注释泄露账号 | 🟡 中危 | 删除注释 | ✅ 已修复 |
| Secret Key 硬编码 | 🔴 严重 | 环境变量优先 | ✅ 已修复 |
| Debug 模式开启 | 🔴 严重 | 环境变量控制 | ✅ 已修复 |
| 登录无频率限制 | 🟡 中危 | Flask-Limiter 限速 | ✅ 已修复 |
| 无 CSRF 防护 | 🔴 严重 | Flask-WTF CSRFProtect | ✅ 已修复 |
| Session 无安全配置 | 🟡 中危 | HttpOnly+SameSite+过期 | ✅ 已修复 |
| 缺少安全响应头 | 🟡 中危 | after_request 添加 | ✅ 已修复 |
| 输入无长度限制 | 🟢 低危 | 服务端长度校验 | ✅ 已修复 |

### 7.2 安全开发规范建议

| 原则 | 说明 |
|------|------|
| **参数化查询** | 所有数据库操作必须使用 `?` 占位符，严禁字符串拼接 |
| **最小权限** | 数据库账户仅授予必要的增删改查权限 |
| **加密存储** | 密码必须使用 `generate_password_hash()` 哈希后存储 |
| **输入的不可信原则** | 所有用户输入（含 URL 参数、表单、Header）都是不可信的 |
| **纵深防御** | WAF + 参数化查询 + 输入验证 + 最小权限，多层防护 |
| **不存储敏感信息** | 日志、前端页面、错误信息中不得出现密码等敏感字段 |

---

## 8. 附录

### 8.1 完整 Payload 参考表

| 攻击类型 | Payload | 效果 |
|---------|---------|------|
| OR 注入 | `' OR 1=1 --` | 返回全部用户 |
| UNION 密码窃取 | `' UNION SELECT id,username,password,phone FROM users --` | 获取全部密码 |
| UNION 表结构 | `' UNION SELECT 1,sql,name,type FROM sqlite_master --` | 获取数据库结构 |
| 布尔盲注 | `admin' AND SUBSTR((SELECT password FROM users WHERE username='admin'),1,1)='a' --` | 逐位猜解密码 |
| 注册注入 | `hacker', 'pass', 'hack@hack.com', '000'); --` | 创建恶意用户 |
| DROP TABLE | `x'; DROP TABLE users; --` | 删除整个表 |

### 8.2 修复后动态验证

| 攻击 Payload | 修复后预期结果 | 实际结果 |
|-------------|:--------------:|:--------:|
| `' OR 1=1 --` | 返回 0 条 | ✅ 安全 |
| `' UNION SELECT ...` | UNION 无效/报错 | ✅ 安全 |
| 注册注入 | 注册失败 | ✅ 安全 |

---

### 8.3 Git 提交历史

```
8b894a6 Day4: 完成头像上传功能与文件上传安全修复
1045ac1 Day3: 完成SQL注入安全修复与实验报告
d56128e Day3: 保存原始SQL注入漏洞版本
e8db17d docs-add-security-report-and-evidence
e72a599 Day2: 完成登录与会话安全修复
38f2e1f Day1: 保存原始漏洞版本
```

Day3 原始漏洞版本（`d56128e`）包含了本报告所述的所有 SQL 注入漏洞的未修复代码，用于实验教学。Day3 安全修复版本（`1045ac1`）已应用本报告所述的全部修复措施。

---

> **声明：** 本报告所有漏洞测试均在本人授权课程项目中完成，测试数据来自实验环境数据库，不涉及任何真实用户信息。
