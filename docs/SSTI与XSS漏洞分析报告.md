# SSTI 与 XSS 漏洞分析与修复报告

——服务端模板注入·跨站脚本·CSRF绕过·GET登出

| 项目 | 内容 |
|------|------|
| **姓名** | 王文杰 |
| **学号** | 2024141530132 |
| **实验项目** | Web安全漏洞分析与修复 |
| **课程名称** | 网络安全实训 |
| **报告日期** | 2026年7月 |
| **项目路径** | `/opt/Class01` |

---

## 目  录

1. 漏洞概述与风险评级
2. SSTI（服务端模板注入）原理
3. 漏洞分析与复现
4. 修复方案详解
5. 修复前后代码对比
6. 修复验证
7. 安全编码规范总结

---

## 1. 漏洞概述与风险评级

本次实验在个性化页面功能中发现了多个安全漏洞，涉及服务端模板注入、跨站脚本和CSRF绕过。

| 漏洞类型 | 漏洞名称 | 严重度 | CVSS |
|---------|---------|:------:|:----:|
| SSTI | 服务端模板注入 → RCE | 严重 | 9.8 |
| XSS | 跨站脚本攻击 | 高危 | 8.6 |
| CSRF | 反馈接口无Token保护 | 中危 | 6.5 |
| 业务逻辑 | 登出方式改为GET | 高危 | 7.5 |

### 漏洞思维导图

```
SSTI:  /welcome?name={{7*7}} → 服务器执行 → 49 → 模板注入成功
RCE:   {{config.__class__.__init__.__globals__['os'].popen('id').read()}} → 系统命令执行
XSS:   /welcome?name=<script>alert(1)</script> → 脚本在页面执行
CSRF:  /feedback POST → @csrf.exempt → 攻击者可伪造请求
GET退出: <a href="/logout"> → img标签即可触发登出 → 用户被强制退出
```

---

## 2. SSTI（服务端模板注入）原理

### 2.1 什么是SSTI

服务端模板注入（Server-Side Template Injection）是指攻击者通过提交恶意模板表达式（如 `{{7*7}}`），使服务器端的模板引擎执行这些表达式。Flask 使用 Jinja2 模板引擎，当用户输入直接通过 f-string 拼接到 `render_template_string()` 的模板参数中时，用户输入中的 `{{...}}` 会被当作模板语法执行。

### 2.2 SSTI → RCE 攻击链

```
用户输入: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
  ↓
f-string 拼接: render_template_string(f"...{{config.__class__...}}...")
  ↓
Jinja2 解析: 执行 Python 对象链
  ↓
访问 __class__ → __mro__ → __subclasses__()
  ↓
找到 os 模块 → popen('id') → 执行系统命令
  ↓
RCE 成功
```

### 2.3 XSS 原理

`render_template_string(f"...{name}...")` 不经过 Jinja2 的自动转义（因为 name 是在 f-string 层面拼入的），因此用户输入的 HTML/JS 代码会直接呈现在页面中。

### 2.4 CSRF 绕过

`/welcome` 和 `/feedback` 路由使用了 `@csrf.exempt` 装饰器，跳过了全局 CSRF 保护。攻击者可构造恶意表单提交到 `/feedback`。

### 2.5 GET 登出

`_build_nav_html()` 使用了 `<a href="/logout">` 而非 POST 表单。攻击者可在第三方页面嵌入 `<img src="http://target/logout">` 强制用户登出。

---

## 3. 漏洞分析与复现

### 3.1 V-01：SSTI 服务端模板注入（严重）

**漏洞代码：**
```python
name = request.args.get("name", "")
content = render_template_string(
    f"""<h1>欢迎你，{name}！</h1>"""  # ❌ f-string 拼接
)
```

**验证结果：**
```bash
# 计算表达式
$ curl "http://target:5000/welcome?name={{7*7}}"
# 返回: 欢迎你，49！  ✅ 模板注入成功

# 读取系统配置
$ curl -X POST "http://target:5000/feedback" -d "name=test&message={{config}}"
# 返回: SECRET_KEY、FLASK_DEBUG 等配置信息 ✅ 敏感信息泄露

# 远程命令执行
$ curl -X POST "http://target:5000/feedback" \
  -d "name=test&message={{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
# 返回: uid=0(root) gid=0(root) ✅ RCE成功
```

### 3.2 V-02：XSS 跨站脚本（高危）

**验证：**
```bash
$ curl "http://target:5000/welcome?name=<script>alert('XSS')</script>"
# 页面中直接渲染了 <script> 标签，浏览器执行脚本
```

### 3.3 V-03：CSRF 绕过（中危）

**验证：**
```bash
# 不带 CSRF Token 的 POST 请求可成功（修复前）
$ curl -X POST "http://target:5000/feedback" -d "name=test&message=test"
# 200 OK ✅ 被放行
```

### 3.4 V-04：GET 登出（高危）

**验证：**
```bash
# 攻击者构造恶意页面
<img src="http://target:5000/logout" style="display:none">
# 已登录用户访问时，浏览器自动发送 GET 请求到 /logout
# 用户被强制登出
```

---

## 4. 修复方案详解

### 4.1 SSTI 修复：模板变量替代 f-string 拼接

**核心思路：** 将用户输入作为模板变量传递，而不是用 f-string 拼接到模板字符串中。

```python
# ❌ 修复前（f-string 拼接，可注入）
render_template_string(f"<h1>欢迎你，{name}！</h1>")

# ✅ 修复后（模板变量，自动转义）
render_template_string("<h1>欢迎你，{{ name|e }}！</h1>", name=name)
```

**修复原理：**

| 步骤 | 说明 |
|:----:|------|
| 1 | 用户输入 `{{7*7}}` 作为 name 参数 |
| 2 | 模板引擎收到 `name = "{{7*7}}"`（纯字符串） |
| 3 | 模板 `{{ name\|e }}` 将其视为变量引用，输出转义后的字符串 |
| 4 | 页面显示 `{{7*7}}` 的原文，而非计算结果 |

### 4.2 XSS 修复：添加 |e 过滤器

Jinja2 的 `|e` 过滤器（或 `|escape`）将 HTML 特殊字符转义：
- `<` → `&lt;`
- `>` → `&gt;`
- `"` → `&quot;`
- `&` → `&amp;`

```html
<h1>欢迎你，{{ name|e }}！</h1>
```

### 4.3 CSRF 修复

**移除 `@csrf.exempt`：** 使全局 CSRF 保护覆盖 `/welcome` 和 `/feedback` 路由。

同时，表单中添加 CSRF Token：
```html
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
```

### 4.4 GET 登出修复

将 `_build_nav_html()` 中的 `<a href="/logout">` 改回 POST 表单：
```html
<form method="post" action="/logout" style="display:inline;">
    <input type="hidden" name="csrf_token" value="...">
    <button type="submit">退出</button>
</form>
```

### 4.5 完整修复后的代码示例

```python
@app.route("/welcome", methods=["GET"])
def welcome():
    name = request.args.get("name", "").strip()
    nav = _build_nav_html(generate_csrf())
    content = render_template_string(
        """<!DOCTYPE html>
<html><body>
{{ nav|safe }}
{% if name %}
<h1>欢迎你，{{ name|e }}！</h1>
{% else %}
<h1>亲爱的用户，欢迎你！</h1>
{% endif %}
</body></html>""",
        nav=nav, name=name   # ✅ 作为模板变量传递
    )
    return content
```

---

## 5. 修复前后代码对比

| 对比项 | ❌ 修复前（漏洞版本） | ✅ 修复后（安全版本） |
|--------|-------------------|--------------------|
| 模板渲染 | `f"...{name}..."` 拼接 | `"...{{name\|e}}..."` 变量传递 |
| XSS 防护 | 无 | `\|e` 过滤器转义 HTML |
| SSTI 防护 | 无 | 变量传递，f-string 不解析模板语法 |
| CSRF 保护 | `@csrf.exempt` 跳过 | 移除豁免，表单加 Token |
| 退出方式 | `<a href="/logout">` GET | POST 表单 + CSRF Token |

### 核心逻辑对比

**修复前：**
```python
render_template_string(f"<h1>欢迎你，{name}！</h1>")
# name = "{{7*7}}" → 执行模板表达式 → 显示 49
# name = "<script>alert(1)</script>" → 执行 JS
```

**修复后：**
```python
render_template_string("<h1>欢迎你，{{ name|e }}！</h1>", name=name)
# name = "{{7*7}}" → 显示 "{{7*7}}"（纯文本）
# name = "<script>alert(1)</script>" → 显示 "&lt;script&gt;..."
```

---

## 6. 修复验证

### 6.1 编译检查

```
$ python -m py_compile app.py
✅ app.py 编译通过
```

### 6.2 攻击测试对比

| 测试用例 | 修复前 | 修复后 |
|---------|:------:|:------:|
| SSTI: `{{7*7}}` → 是否显示 49 | ❌ 显示 49 | ✅ 显示原文 |
| SSTI: `{{config}}` → 是否泄露密钥 | ❌ 泄露 | ✅ 显示原文 |
| SSTI → RCE: 执行系统命令 | ❌ 执行成功 | ✅ 显示原文 |
| XSS: `<script>alert(1)</script>` | ❌ 执行脚本 | ✅ 转义为文本 |
| CSRF: 无Token POST | ❌ 被放行 | ✅ 400 拒绝 |
| GET 登出: `<a href="/logout">` | ❌ GET 登出 | ✅ POST 表单 |
| 正常功能: `/welcome?name=张三` | ✅ | ✅ |

---

## 7. 安全编码规范总结

### 服务端模板安全原则

| 原则 | 说明 |
|:----:|------|
| **永不拼接** | 永远不要用 f-string 拼接用户输入到 `render_template_string` |
| **变量传递** | 用户输入必须作为模板变量（`name=name`）传递给模板 |
| **自动转义** | 始终使用 `\|e` 过滤器确保 HTML 转义 |
| **CSRF 保护** | 所有 POST 接口必须带 CSRF Token |
| **POST 登出** | 退出登录必须用 POST 方法，禁止 GET 登出 |

### 本次修复清单

| 漏洞 | 风险 | 修复方式 | 状态 |
|:----:|:----:|---------|:----:|
| SSTI 模板注入 → RCE | 🔴 严重 | 模板变量替代 f-string 拼接 | ✅ |
| XSS 跨站脚本 | 🔴 高危 | 添加 `\|e` HTML 转义过滤器 | ✅ |
| CSRF 防护绕过 | 🟡 中危 | 移除 `@csrf.exempt`，表单加 Token | ✅ |
| GET 登出 | 🔴 高危 | 改用 POST 表单提交 | ✅ |

### 防御纵深建议

1. **模板引擎安全**：使用 `render_template`（文件模板）而非 `render_template_string`（字符串模板）
2. **内容安全策略（CSP）**：通过 `script-src 'self'` 限制脚本来源
3. **输入长度限制**：对 `name`、`message` 等参数添加最大长度校验
4. **WAF 规则**：对 `{{`、`}}`、`__class__` 等模板注入特征进行检测

---

*本报告基于 `/opt/Class01` 项目个性化页面功能的实际代码审计、漏洞测试和安全修复编写，所有漏洞均经过实际验证。*
