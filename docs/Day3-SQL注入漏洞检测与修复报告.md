# Day3 SQL 注入漏洞检测与安全修复报告

| 项目 | 内容 |
|------|------|
| **姓名** | 王文杰 |
| **学号** | 2024141530132 |
| **实验日期** | 2026-07-20 |
| **实验环境** | Kali Linux |
| **项目路径** | `/opt/Class01` |
| **实验性质** | 课程实训本地安全测试 |
| **Git 原始漏洞版本** | `d56128e` |

---

## 1. 实验基本信息

| 项目 | 内容 |
|------|------|
| 操作系统 | Kali Linux |
| Python 版本 | 3.13 |
| Web 框架 | Flask 3.1.3 |
| 数据库 | SQLite 3（`data/users.db`） |
| 测试工具 | 浏览器开发者工具、curl |
| 本地访问地址 | http://127.0.0.1:5000 |

---

## 2. 实验背景与目的

Day3 实训在 Day2 安全修复基础上，新增 SQLite 数据库、用户注册和用户搜索功能。Day3 原始漏洞版本故意在 `/search` 和 `/register` 接口中使用 f-string 字符串拼接 SQL，引入 SQL 注入漏洞，用于课程实训中的漏洞发现、验证和修复演练。

### 实验目的

1. 理解字符串拼接 SQL 的安全风险
2. 通过实际漏洞验证理解 OR 注入和 UNION SELECT 注入原理
3. 掌握参数化查询的修复方法
4. 理解密码哈希存储的必要性
5. 体验完整的"发现漏洞 → 验证利用 → 实施修复 → 回归检查"安全开发生命周期

---

## 3. 实验环境

### 技术栈

| 组件 | 版本 |
|------|------|
| Python | 3.13 |
| Flask | 3.1.3 |
| Flask-WTF | 1.3.0 |
| Flask-Limiter | 4.1.1 |
| Werkzeug | 3.1.8 |
| SQLite | 3（Python 内置） |

### Git 提交历史

| 提交 | 说明 |
|------|------|
| `38f2e1f` | Day1: 保存原始漏洞版本 |
| `e72a599` | Day2: 完成登录与会话安全修复 |
| `e8db17d` | docs-add-security-report-and-evidence |
| `d56128e` | Day3: 保存原始SQL注入漏洞版本 |

---

## 4. Day3 新增功能

### 4.1 SQLite 数据库

- 数据库路径：`/opt/Class01/data/users.db`
- 表结构：

| 字段 | 类型 | 约束 |
|------|------|------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT |
| username | TEXT | UNIQUE |
| password | TEXT | |
| email | TEXT | |
| phone | TEXT | |

- 默认教学用户：admin、alice

### 4.2 注册功能（`/register`）

支持 GET 和 POST 方法。用户提交用户名、密码、邮箱和手机号后写入 SQLite users 表。

### 4.3 搜索功能（`/search`）

支持 GET 方法，通过 `keyword` 参数搜索用户。仅已登录用户可访问。返回匹配用户的 ID、用户名、邮箱和手机号（不含密码）。

---

## 5. 漏洞原理

### 5.1 搜索接口字符串拼接 SQL

Day3 原始漏洞版本中，`/search` 接口的 SQL 语句通过 f-string 直接拼接用户输入：

```python
sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
cursor.execute(sql)
```

当用户输入包含 SQL 特殊字符（如单引号 `'`、注释 `--`）时，这些输入会成为 SQL 语法的一部分，改变原查询语义。

### 5.2 注册接口字符串拼接 SQL

```python
sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
cursor.execute(sql)
```

同样使用 f-string 拼接，用户输入直接嵌入 SQL 语句。

### 5.3 SQLite 密码明文存储

Day3 原始漏洞版本中，SQLite users 表的 password 字段直接存储明文密码，包括默认教学用户的密码。

---

## 6. 漏洞检测过程

### 6.1 正常搜索基线

**操作：** 登录后在搜索框输入 `admin`

**后台生成的 SQL：**
```sql
SELECT id, username, email, phone FROM users WHERE username LIKE '%admin%' OR email LIKE '%admin%'
```

**实际结果：** 页面正常返回 admin 用户的记录，包含 ID、用户名、邮箱和手机号。页面没有显示 password 字段。

> **截图位置：** `docs/images/day3-normal-search.png`（待整理）

### 6.2 OR 注入验证

**Payload：**
```
' OR 1=1 -- 
```

**后台实际生成的 SQL：**
```sql
SELECT id, username, email, phone FROM users WHERE username LIKE '%' OR 1=1 --%' OR email LIKE '%' OR 1=1 --%'
```

**注入原理：** 用户输入中的 `'` 闭合了原 SQL 中的开引号，`OR 1=1` 添加了一个恒真条件，`--` 注释了后续 SQL，最终查询返回表中所有用户记录。

**实际结果：** 页面同时返回了 admin 和 alice 两条用户记录。

| 结果 | 值 |
|------|-----|
| 攻击类型 | OR SQL 注入 |
| Payload | `' OR 1=1 -- ` |
| 注入位置 | `keyword` 参数 |
| 攻击效果 | 绕过搜索条件，返回全部用户数据 |
| **验证状态** | **✅ 实际验证成功** |

> **截图位置：** `docs/images/day3-or-injection.png`（待整理）

### 6.3 UNION SELECT 注入验证

**Payload：**
```
' UNION SELECT 999,'inj','inj@x.com','138' -- 
```

**注入原理：** 闭合原查询后，通过 `UNION SELECT` 添加自定义的 SELECT 查询结果。原查询返回 0 条（用户名无匹配），`UNION SELECT` 返回构造的 4 列数据。

**实际结果：** 页面新增显示一条自定义记录：

| ID | 用户名 | 邮箱 | 手机 |
|:--:|:------:|:----:|:----:|
| 999 | inj | inj@x.com | 138 |

**注意：** 该 Payload 仅改变查询结果，未向数据库持久化写入数据。数据库中没有实际创建名为 "inj" 的用户。

| 结果 | 值 |
|------|-----|
| 攻击类型 | UNION SELECT SQL 注入 |
| Payload | `' UNION SELECT 999,'inj','inj@x.com','138' -- ` |
| 注入位置 | `keyword` 参数 |
| 攻击效果 | 向搜索结果中合并自定义 SELECT 返回的数据 |
| **验证状态** | **✅ 实际验证成功** |

> **截图位置：** `docs/images/day3-union-injection.png`（待整理）

### 6.4 注册接口代码审计

通过代码审计确认 `/register` 接口同样使用 f-string 拼接 SQL：

```python
sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
```

**风险分析：** 由于用户输入直接拼接进 INSERT SQL，理论上可能改变原 INSERT 语句的字段值或 SQL 结构。本次仅通过代码审计确认风险，未完成实际成功利用验证。

| 结果 | 值 |
|------|-----|
| 发现方式 | 代码审计 |
| 风险等级 | 高危（理论上可被利用） |
| **实际利用验证** | **本次实验未完成实际成功利用验证** |
| **状态** | **代码审计确认存在风险** |

---

## 7. 漏洞影响分析

### 7.1 实际验证的影响

| 漏洞 | 实际验证的影响 |
|------|---------------|
| 搜索接口 OR 注入 | ✅ 攻击者可绕过搜索条件，返回全部用户记录（含其他用户信息） |
| 搜索接口 UNION SELECT 注入 | ✅ 攻击者可构造任意数据插入搜索结果页面 |

### 7.2 理论潜在影响（本次未实际验证）

以下风险通过代码分析确认理论存在，但本次实验未进行实际利用验证：

1. **注册接口 SQL 注入**：攻击者可能在注册时通过注入修改 INSERT SQL 语义，例如插入管理员账户或在 SQLite 支持 stacked query 的条件下执行多条语句。
2. **SQLite 密码明文存储**：如果攻击者通过 SQL 注入或其他方式获取了数据库文件的读取权限，可获取所有用户的明文密码。
3. **用户信息批量泄露**：OR 注入的进一步利用可查询全部注册用户的信息。

---

## 8. 安全修复方案

### 8.1 `/search` 参数化查询

**修复前（f-string 拼接）：**
```python
sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
cursor.execute(sql)
```

**修复后（? 占位符参数化）：**
```python
sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
cursor.execute(sql, (f"%{keyword}%", f"%{keyword}%"))
```

**修复原理：** 使用 SQLite 的 `?` 占位符，将 SQL 语句结构（代码）与用户输入（数据）分离。用户输入中的任何 SQL 特殊字符（`'`、`--`、`UNION` 等）都会被当作字面字符串值，不再被解释为 SQL 语法的一部分。

### 8.2 `/register` 参数化查询

**修复前（f-string 拼接）：**
```python
sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
cursor.execute(sql)
```

**修复后（? 占位符参数化 + 密码哈希）：**
```python
pw_hash = generate_password_hash(password)
sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
cursor.execute(sql, (username, pw_hash, email, phone))
```

### 8.3 密码哈希

| 位置 | 修复前 | 修复后 |
|------|--------|--------|
| `init_db()` 默认用户 | 明文 `'admin123'`、`'alice2025'` | `generate_password_hash("admin123")` |
| `/register` 新用户 | 明文拼接 | `generate_password_hash(password)` |

使用 Werkzeug 的 `generate_password_hash` 进行 scrypt 密码哈希。

**注意事项：** 代码修复后，新初始化的数据库和新注册用户使用密码哈希。现有 `data/users.db` 由于被 `.gitignore` 忽略且 `INSERT OR IGNORE` 不覆盖已有记录，历史明文密码不会自动迁移。

### 8.4 输入长度限制

| 接口 | 字段 | 长度限制 |
|------|------|---------|
| `/register` | username | 1 - 50 字符 |
| `/register` | password | 6 - 128 字符 |
| `/register` | email | 1 - 100 字符 |
| `/register` | phone | 1 - 20 字符 |
| `/search` | keyword | 最大 100 字符 |

**说明：** 输入长度限制属于纵深防御措施。SQL 注入的核心修复仍然是参数化查询，而非对用户输入做关键字黑名单过滤。

---

## 9. 修复前后代码对比

### 9.1 搜索接口

| 对比项 | 修复前（漏洞版本） | 修复后（安全版本） |
|--------|------------------|------------------|
| SQL 构造 | f-string 直接拼接用户输入 | `?` 占位符参数化查询 |
| 示例代码 | `sql = f"... LIKE '%{keyword}%'"` | `sql = "... LIKE ?"` |
| 执行方式 | `cursor.execute(sql)` | `cursor.execute(sql, (f"%{keyword}%", f"%{keyword}%"))` |
| 输入 `' OR 1=1 --` | 成为 SQL 语法的一部分 | 被作为字面字符串 `%' OR 1=1 --%` 处理 |

### 9.2 注册接口

| 对比项 | 修复前（漏洞版本） | 修复后（安全版本） |
|--------|------------------|------------------|
| SQL 构造 | f-string 拼接 4 个字段 | `?` 占位符参数化查询 |
| 密码存储 | 明文 | `generate_password_hash(password)` |
| 输入验证 | 无 | 长度校验 |

---

## 10. 修复验证

| 验证项目 | 结果 |
|---------|:----:|
| Python 编译检查 (`py_compile`) | ✅ 通过 |
| 静态代码检查——`/search` 使用 `?` 占位符 | ✅ 确认 |
| 静态代码检查——`/register` 使用 `?` 占位符 | ✅ 确认 |
| 静态代码检查——`generate_password_hash` 用于新密码 | ✅ 确认 |
| 静态代码检查——Day2 安全功能保留 | ✅ 确认 |
| 动态攻击 Payload 复测（OR / UNION） | ⚠️ 本次未执行 |

**说明：** 修复后已完成静态代码检查和 Python 编译检查，未继续执行动态攻击 Payload 复测。

---

## 11. Day2 安全功能回归检查

| 安全功能 | 状态 | 说明 |
|---------|:----:|------|
| 原登录功能（USERS 字典） | ✅ 保持 | 未修改 |
| Werkzeug 密码哈希认证（check_password_hash） | ✅ 保持 | 未修改 |
| CSRFProtect | ✅ 保持 | 全局启用 |
| 登录 5 次/分钟限速 | ✅ 保持 | `@limiter.limit("5 per minute")` |
| POST 登出 | ✅ 保持 | `@app.post("/logout")` |
| Session Cookie 安全配置 | ✅ 保持 | HttpOnly、SameSite=Lax、30 分钟过期 |
| 安全响应头 | ✅ 保持 | CSP、X-Frame-Options、X-Content-Type-Options 等 |
| SECRET_KEY 安全配置 | ✅ 保持 | 优先环境变量，未配置则随机生成 |
| 默认关闭 Debug | ✅ 保持 | 仅 `FLASK_DEBUG=1` 时开启 |
| 页面不显示 password | ✅ 保持 | 搜索结果仅含 id/username/email/phone |

---

## 12. 漏洞矩阵

| 漏洞类型 | 接口 | 发现方式 | 实际利用验证 | 修复方式 | 修复状态 |
|---------|:----:|:--------:|:----------:|---------|:--------:|
| OR SQL 注入 | `/search` | 实际测试 | ✅ 成功（返回全部用户） | 参数化查询 | ✅ 已修复 |
| UNION SELECT SQL 注入 | `/search` | 实际测试 | ✅ 成功（返回自定义数据） | 参数化查询 | ✅ 已修复 |
| SQL 注入风险 | `/register` | 代码审计 | ❌ 未实际利用验证 | 参数化查询 | ✅ 已修复 |
| 密码明文存储 | SQLite `users` 表 | 代码审计 | — | `generate_password_hash` | ✅ 已修复 |

---

## 13. 安全修复建议

### 13.1 针对本项目

1. **参数化查询是所有数据库操作的唯一方式** — 禁止任何形式的字符串拼接 SQL。
2. **密码应始终哈希存储** — 使用 Werkzeug 的 `generate_password_hash` 和 `check_password_hash`。
3. **输入验证作为纵深防御** — 长度、格式校验在前端和后端均应实施。
4. **搜索结果不应泄露敏感字段** — password_hash 等字段不得传递到模板。

### 13.2 一般性建议

1. **最小权限原则** — 数据库账户仅授予必要的增删改查权限。
2. **错误信息不直接暴露给用户** — 避免 SQL 错误信息助攻击者理解数据库结构。
3. **日志审计** — 记录异常查询行为和失败请求。
4. **代码审查** — 合并代码前检查是否存在字符串拼接 SQL，作为 CI/CD 的一环。
5. **安全意识** — 开发人员应了解 SQL 注入原理和参数化查询的必要性。

---

## 14. 实验总结

本次实验完成了 Day3 课程实训的核心目标：

1. **漏洞发现**：通过代码审计发现 `/search` 和 `/register` 接口存在 f-string 字符串拼接 SQL 的安全漏洞。
2. **漏洞验证**：在 `/search` 接口真实验证了 OR 注入（`' OR 1=1 --`）可返回全部用户记录，以及 UNION SELECT 注入可构造自定义返回数据。
3. **安全修复**：将两个接口的 SQL 操作改为参数化查询（`?` 占位符），从根本上消除 SQL 注入风险。
4. **密码加固**：安全修复版本使新初始化数据库中的默认用户以及后续新注册用户使用 `generate_password_hash()` 生成密码哈希；已有 `users.db` 中的历史明文记录不会自动迁移。
5. **输入验证**：增加字段长度上限作为纵深防御。
6. **回归检查**：确认 Day2 所有安全功能未受影响。

通过本次实训，完成了"漏洞发现 → 搜索接口实际验证 → 安全修复 → 静态代码与编译回归检查"的安全开发流程。修复后的 OR / UNION 动态攻击复测本次未继续执行。

### 截图证据清单

| 截图文件 | 说明 |
|---------|------|
| `docs/images/day3-normal-search.png` | 正常搜索 admin 返回正确结果 |
| `docs/images/day3-or-injection.png` | OR 注入返回全部用户记录 |
| `docs/images/day3-union-injection.png` | UNION SELECT 注入显示自定义数据 |
| `docs/images/day3-register.png` | 正常注册功能测试 |

> **注意：** 以上截图文件尚未就位，请实际测试完成后放入 `docs/images/` 目录。

---

*本报告基于 `/opt/Class01` 项目 Day3 真实实验数据编写，所有漏洞验证结果均有真实实验记录支持，未编造未经实验验证的攻击结果。*
