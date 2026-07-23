# Class01 简易用户信息管理平台

## 项目简介

本项目是一个基于 Python Flask 框架构建的简易用户信息管理平台，具备用户登录、信息展示和退出功能。项目包含原始漏洞版本（Day1）和安全修复版本（Day2）两个 Git 提交，用于课程实训中的 Web 安全漏洞分析与修复演练。

## 功能

- 用户登录认证
- 用户个人信息展示
- 用户注册
- 用户搜索
- **用户头像上传**（含图片预览）
- **个人中心**（查看资料、充值）
- **商城系统**（商品列表、加入购物车）
- **管理面板**（用户管理、删除用户）
- **动态页面加载**（帮助中心等静态页面）
- 安全退出登录
- 登录频率限制
- CSRF 防护

## 技术栈

- Python 3.13
- Flask 3.1.3
- Flask-WTF 1.3.0（CSRF 防护）
- Flask-Limiter 4.1.1（登录限速）
- Werkzeug 3.1.8（密码哈希）

## 目录结构

```
Class01/
├── app.py                 # Flask 主应用
├── requirements.txt       # Python 依赖
├── .gitignore             # Git 忽略规则
├── .env.example           # 环境变量示例
├── README.md              # 项目说明
├── pages/
│   └── help.html          # 帮助中心页面（路径穿越漏洞演示）
├── templates/
│   ├── base.html          # 基础模板（导航栏）
│   ├── index.html         # 首页（用户信息展示+快捷入口+页面加载）
│   ├── login.html         # 登录页面
│   ├── register.html      # 注册页面
│   ├── upload.html        # 头像上传页面
│   ├── profile.html       # 个人中心（IDOR越权漏洞）
│   ├── admin.html         # 管理面板（垂直越权漏洞）
│   └── shop.html          # 商城（价格篡改漏洞）
├── static/
│   ├── css/
│   │   └── style.css      # 样式文件
│   └── uploads/           # 用户头像上传目录
│       └── .htaccess      # 安全规则（禁止PHP执行）
├── logs/
│   └── upload.log          # 文件上传审计日志
└── docs/
    ├── 漏洞修复报告.md     # 漏洞修复报告
    └── images/            # 截图证据目录
```

## 环境要求

- Python 3.10+
- pip（Python 包管理器）
- Git

## 安装与启动

请按以下步骤在本地搭建并运行项目。

1.  **克隆或进入项目目录**

    ```bash
    cd /opt/Class01
    ```

2.  **创建虚拟环境**

    ```bash
    python3 -m venv .venv
    ```

3.  **激活虚拟环境**

    ```bash
    source .venv/bin/activate
    ```

4.  **安装依赖**

    ```bash
    python -m pip install -r requirements.txt
    ```

5.  **配置安全密钥**

    通过环境变量设置会话加密密钥：

    ```bash
    export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
    ```

    > 每次启动都会生成不同的密钥。若需维持已有会话，可固定该值并写入 `.env` 文件。

6.  **启动应用**

    ```bash
    python app.py
    ```

    Kali 本机可访问 http://127.0.0.1:5000；本次虚拟机实训中，Windows 主机通过 http://192.168.253.129:5000 访问。

### 可选环境变量

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `SECRET_KEY` | 会话加密密钥，建议设为 64 字符随机十六进制串 | 自动随机生成 |
| `FLASK_DEBUG` | 设为 `1` 开启调试模式 | `0`（关闭） |
| `SESSION_COOKIE_SECURE` | 设为 `1` 启用 Secure Cookie（仅 HTTPS） | `0` |

> **注意：** `SESSION_COOKIE_SECURE=1` 仅在配置了 HTTPS 的生产环境中启用。在本地 HTTP 环境开启会导致 Cookie 无法发送，登录功能失效。

## 安全修复概览

Day1 提交（38f2e1f）保留了存在多个安全漏洞的原始版本，用于漏洞分析和测试。Day2 提交（e72a599）完成了登录与会话安全修复。Day3 提交（d56128e/1045ac1）完成SQL注入漏洞版本及修复。Day4 提交（8b894a6）完成头像上传功能及文件上传安全修复。Day5 提交（f23fb16）完成个人中心、商城、管理面板功能及权限提升漏洞分析。Day6 提交（172c969）完成动态页面加载功能及路径穿越漏洞分析与修复。

### Day2 安全修复（提交 e72a599）

| 编号 | 漏洞描述 | 修复方式 |
|------|---------|---------|
| 1 | 密码明文存储与直接比对 | 使用 Werkzeug scrypt 哈希存储密码，采用 `check_password_hash` 进行安全比对 |
| 2 | 页面泄露明文密码 | 通过 `safe_user_info` 过滤返回字段，模板不再显示密码 |
| 3 | HTML 注释泄露默认账号 | 删除登录页中的调试账号注释 |
| 4 | Secret Key 硬编码 | 优先从环境变量读取，未配置时随机生成 |
| 5 | Debug 模式永久开启 | 仅在 `FLASK_DEBUG=1` 时开启 |
| 6 | 无登录频率限制 | 集成 Flask-Limiter，`POST /login` 限制为每分钟 5 次 |
| 7 | 无 CSRF 防护 | 集成 Flask-WTF CSRFProtect，退出改为 POST 方法 |
| 8 | Session 无过期和防篡改配置 | 设置 30 分钟过期、HttpOnly、SameSite=Lax |
| 9 | 缺少安全响应头 | 添加 CSP、X-Frame-Options、Referrer-Policy 等响应头 |
| 10 | 缺少输入长度和请求体限制 | 添加 `maxlength`、服务端校验和 `MAX_CONTENT_LENGTH` |
| 11 | 响应耗时可枚举用户名 | 使用固定虚拟哈希对不存在用户执行相同校验流程 |

### Day3 安全修复（提交 d56128e / 1045ac1）

| 编号 | 漏洞描述 | 修复方式 |
|------|---------|---------|
| 1 | /search 接口 SQL 注入（OR/UNION） | 使用 `?` 占位符参数化查询 |
| 2 | /register 接口 SQL 注入 | 使用 `?` 占位符参数化查询 |
| 3 | SQLite 密码明文存储 | `generate_password_hash()` 哈希存储 |
| 4 | 搜索/注册输入未校验 | 增加字段长度上限和服务端校验 |

### Day4 安全修复（提交 8b894a6）

| 编号 | 漏洞描述 | 修复方式 |
|------|---------|---------|
| 1 | 未校验文件后缀（高危） | 建立白名单，仅允许 7 种图片扩展名 |
| 2 | 不检测文件真实 MIME（高危） | 文件头部 12 字节魔数签名验证 |
| 3 | 路径穿越（高危） | UUID 重命名 + Path.resolve() 路径安全校验 |
| 4 | 无随机重命名（中危） | `uuid.uuid4().hex` 生成唯一文件名 |
| 5 | 仅前端限制（中危） | 后端独立完整检测流程 |
| 6 | 上传目录可执行（高危） | `.htaccess` 自动部署禁止 PHP 执行 |
| 7 | 无审计日志（低危） | `logging` 模块记录用户/IP/文件名/时间 |
| 8 | 越目录写入（高危） | `Path.resolve()` + `startswith()` 边界校验 |

### Day5 漏洞分析（提交 f23fb16）

Day5 在保持所有功能不变的基础上，新增了个人中心、商城、管理面板功能。这些功能**故意保留了以下安全漏洞**用于教学实验：

| 编号 | 漏洞类型 | 漏洞描述 | 路由 |
|:----:|---------|---------|------|
| 1 | 水平越权（IDOR） | 任意用户可通过修改 `user_id` 参数查看他人资料 | `/profile` |
| 2 | 垂直越权 | 普通用户可直接访问管理面板，无需管理员权限 | `/admin` |
| 3 | 垂直越权 | 普通用户可删除任意用户账号 | `/admin/delete-user` |
| 4 | 业务逻辑漏洞 | 商品价格由客户端提交，可篡改为任意值 | `/cart` |
| 5 | 业务逻辑漏洞 | 充值金额未校验正负，可提交负值扣减余额 | `/recharge` |

### Day6 漏洞分析（提交 172c969）

Day6 新增了动态页面加载功能，支持通过 `/page?name=help` 加载 `pages/` 目录下的静态页面。该功能**故意保留了路径穿越漏洞**用于教学实验，并在修复版中使用 `Path.resolve()` 进行边界校验。

| 编号 | 漏洞类型 | 漏洞描述 | Payload |
|:----:|---------|---------|---------|
| 1 | 路径穿越（高危） | 任意文件读取，可读取应用源码和系统文件 | `/page?name=../../../etc/passwd` |
| 2 | {{ content \| safe }}渲染（中危） | 文件内容直接渲染，可嵌入恶意HTML/JS | `/page?name=../app.py` |
| 3 | 未授权访问（中危） | `/page` 无需登录即可访问 | `/page?name=help` |

## 测试说明

### 启动测试

```bash
cd /opt/Class01
source .venv/bin/activate
python app.py
```

### 运行 Burp Suite 测试

1. 配置浏览器代理至 Burp Suite（默认 127.0.0.1:8080）
2. 访问本次实验地址 http://192.168.253.129:5000/login
3. 拦截登录请求并发送至 Intruder 模块进行密码枚举测试
4. 观察响应长度差异定位正确密码（原始版本）

### 功能验证

- 使用授权测试账号登录
- 验证首页展示正确的用户信息
- 验证退出功能正常
- 验证 CSRF 防护（不带 Token 的 POST 请求应返回 400）
- 验证安全响应头存在
- 验证登录限速（每分钟超过 5 次错误返回 429）

### 漏洞测试 Payload（Day5~Day6 教学漏洞）

```bash
# 1. IDOR越权：用alice的cookie查看admin资料
curl -b cookies.txt 'http://target:5000/profile?user_id=1'

# 2. 垂直越权：普通用户访问管理面板
curl -b cookies.txt 'http://target:5000/admin'

# 3. 价格篡改：1分钱买iPhone
curl -b cookies.txt -X POST http://target:5000/cart \
  -d 'product_id=1&product_name=iPhone&price=0.01&quantity=1'

# 4. 负值充值：扣减他人余额
curl -b cookies.txt -X POST http://target:5000/recharge \
  -d 'user_id=2&amount=-100'

# 5. 路径穿越：读取系统密码文件（漏洞版本）
curl 'http://target:5000/page?name=../../../etc/passwd'

# 6. 路径穿越：读取应用源码（漏洞版本）
curl 'http://target:5000/page?name=../app.py'

# 7. 正常访问帮助页面
curl 'http://target:5000/page?name=help'
```

## Git 提交说明

| 提交 | 说明 |
|------|------|
| `38f2e1f` | **Day1: 保存原始漏洞版本** — 包含全部安全漏洞的未加固代码，仅用于课程实训和授权的本地安全测试 |
| `e72a599` | **Day2: 完成登录与会话安全修复** — 针对 Day1 的 11 项漏洞逐一修复 |
| `d56128e` | **Day3: 保存原始SQL注入漏洞版本** — 包含 f-string 拼接 SQL 的教学漏洞版本 |
| `1045ac1` | **Day3: 完成SQL注入安全修复与实验报告** — 参数化查询、密码哈希 |
| `8b894a6` | **Day4: 完成头像上传功能与文件上传安全修复** — 8 项文件上传漏洞修复 |
| `f23fb16` | **Day5: 完成个人中心、管理面板、商城功能与权限提升漏洞分析** — IDOR越权、垂直越权、价格篡改、负值充值 |
| `172c969` | **Day6: 新增动态页面加载功能与路径穿越漏洞分析报告** — 路径穿越、文件包含、修复方案 |

> **重要：** Day1 提交是有意保留的漏洞基线，包含大量高危安全隐患。**严禁**将其用于任何形式的生产环境或对外部署。

## 授权使用声明

本项目仅用于王文杰（学号：**2024141530132**）的课程实训以及授权的本地安全测试。未经授权，不得将本项目及其代码用于任何商业用途、生产环境或对第三方系统进行测试。使用本项目进行安全测试时，必须确保已获得目标系统的明确授权。

---

*本 README 不包含任何真实密码、API 密钥或会话令牌。*
