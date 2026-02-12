# 日志引擎 (Log Engine) 使用文档

Log Engine 是 netxfw 内置的高性能日志分析与防御子系统。它采用 Zero-Copy（零拷贝）技术直接处理字节流，支持从简单的关键词匹配到复杂的逻辑表达式分析，能够实时从日志中提取威胁情报并自动执行防御动作（如封禁 IP）。

## 1. 核心特性

*   **高性能**: 默认采用 `Byte Mode`，直接操作内存字节，无需字符串转换开销。
*   **双重语法**: 支持简单的 YAML 语义化配置（Cloudflare 风格）和高级表达式（Expr 语言）。
*   **频率控制**: 内置滑动窗口计数器，支持基于时间窗口的频率限制（如 60秒内错误 5 次）。
*   **上下文感知**: 支持根据日志文件路径 (`path`) 隔离规则。
*   **字段提取**: 支持 KV 提取 (`key=value`)、JSON 字段提取、分隔符提取。

## 2. 启用配置

在 `config.yaml` 中配置 `log_engine` 部分：

```yaml
log_engine:
  enabled: true       # 启用引擎
  workers: 4          # 并发处理协程数
  files:              # 监控的日志文件列表
    - "/var/log/nginx/access.log"
    - "/var/log/auth.log"
    - "/var/log/syslog"
  rules: []           # 规则列表（见下文）
```

## 3. 规则编写指南

Log Engine 支持两种规则编写方式，可以根据复杂度混合使用。

### 3.1 方式一：语义化配置 (推荐)

适合快速配置常见的匹配逻辑。使用类似 Cloudflare WAF 的直观字段。

**字段说明：**

| 字段 | 别名 | 说明 | 逻辑关系 |
| :--- | :--- | :--- | :--- |
| `contains` | `and`, `is`, `keywords` | 必须包含**所有**指定内容 | AND (&&) |
| `any_contains` | `or` | 必须包含**任意**指定内容 | OR (\|\|) |
| `not_contains` | `not` | 必须**不包含**任意指定内容 | NOT (!) |
| `regex` | - | 必须匹配正则表达式 | AND |
| `path` | - | 仅在匹配该文件路径时生效 | Filter |

**频率控制字段：**

| 字段 | 说明 | 默认值 |
| :--- | :--- | :--- |
| `threshold` | 触发阈值（次数） | 0 (即单次匹配立即触发) |
| `interval` | 计数时间窗口（秒） | 60 |

**示例 1：SSH 爆破防御**
*规则：在 `auth.log` 中，如果包含 "Failed password" 且不包含 "invalid user"，在 60秒内出现 5 次，则封禁。*

```yaml
- id: "ssh_bruteforce"
  path: "/var/log/auth.log"
  action: "dynblack"
  is: 
    - "Failed password"
  not:
    - "invalid user"  # 排除特定误报
  threshold: 5
  interval: 60
```

**示例 2：拦截特定 User-Agent**
*规则：拦截包含 "Go-http-client" 或 "python-requests" 的请求。*

```yaml
- id: "block_scrapers"
  path: "*.log"
  action: "dynblack"
  or:
    - "Go-http-client"
    - "python-requests"
    - "curl/"
```

### 3.2 方式二：高级表达式 (Expression)

当语义化配置无法满足需求时（例如需要提取字段值进行比较），可以使用 `expression` 字段。底层使用 [Expr](https://expr-lang.org/) 语言。

**内置变量：**

| 变量 | 类型 | 说明 |
| :--- | :--- | :--- |
| `Line` | `[]byte` | 完整的日志行原始字节 |
| `Log` | `[]byte` | `Line` 的别名 (为了书写方便) |
| `Msg` | `[]byte` | `Line` 的别名 (为了书写方便) |
| `Source` | `string` | 日志来源文件路径 |
| `IP` | `string` | 提取到的源 IP 字符串 |
| `Addr` | `netip.Addr` | 源 IP 对象 (可用于 CIDR 判断) |

**内置函数：**

| 函数 | 说明 | 示例 |
| :--- | :--- | :--- |
| `Contains(data, str)` | 包含字符串 | `Contains(Log, "error")` 或 `Contains(Msg, "fail")` |
| `IContains(data, str)` | 包含字符串 (忽略大小写) | `IContains(Line, "ERROR")` |
| `Get(key)` | 获取 KV 值 (key=val 或 key:val) | `Get("status") == "404"` |
| `Fields()[index]` | 按空格分割获取第 N 个字段 | `Fields()[8] == "500"` |
| `Split(sep)[index]` | 按分隔符分割 | `Split("|")[2] == "admin"` |
| `Lower(data)` | 转换为小写字符串 | `Lower(Line) matches "error"` |
| `InCIDR(cidr)` | IP 是否在网段内 | `InCIDR("192.168.0.0/16")` |
| `Count(window)` | 获取当前 IP 在窗口内的计数 | `Count(60) > 10` |

**示例 3：复杂的 Nginx 状态码封禁**
*规则：针对 Nginx 日志，如果状态码是 404 或 500，且 URL (第7列) 包含 "admin"，且 30秒内超过 10 次。*

```yaml
- id: "nginx_admin_scan"
  path: "/var/log/nginx/access.log"
  action: "dynblack"
  expression: |
    (Fields()[8] == "404" || Fields()[8] == "500") &&
    Contains(Fields()[6], "admin") &&
    Count(30) > 10
```

**示例 4：KV 格式日志提取**
*假设日志格式：`level=error msg="login failed" user=admin ip=1.2.3.4`*

```yaml
- id: "kv_auth_fail"
  action: "dynblack"
  expression: |
    Get("level") == "error" &&
    Get("msg") == "login failed" &&
    Get("user") != "whitelist_user"
```

## 4. Action 动作说明

| 动作 (Action) | 别名 (Aliases) | 类型 | 说明 |
| :--- | :--- | :--- | :--- |
| `dynblock` | `dynblack`, `dynlock` | 动态封禁 | **默认推荐**。将 IP 加入临时黑名单 (LRU Map)。支持自动过期。 |
| `dynblock:10m` | `dynblack:..`, `block:..`, `black:..` | 动态封禁 | 封禁指定时长（如 10m, 1h, 30s）。**注意**: 即使前缀是 `block`，只要带时长就是动态。 |
| `lock` | `deny`, `blacklist`, `block`, `black` | 静态封禁 | **永久封禁**。将 IP 加入持久化黑名单 (LPM Trie)。需手动解封。 |
| `log` | - | 仅日志 | 仅记录告警日志，不执行拦截。 |

> **注意**: 
> 1. **关键字兼容性**: `block` 和 `black` (无时长) 均视为**静态封禁** (`lock`)。
> 2. **智能时长识别**: 任何带有 `:duration` 后缀的动作 (如 `block:5m`, `black:1h`) 均视为**动态封禁**。
> 3. **推荐用法**: 
>    - 动态: `dynblock` 或 `dynblock:10m`
>    - 静态: `lock` 或 `deny`

## 5. 完整配置示例

```yaml
log_engine:
  enabled: true
  workers: 8
  files:
    - "/var/log/auth.log"
    - "/var/log/nginx/access.log"
    - "/var/log/app.log"
  
  rules:
    # 1. SSH 防爆破 (语义化写法)
    - id: "ssh_fail"
      path: "/var/log/auth.log"
      action: "dynblack"  # 动态封禁 (默认5分钟)
      is: ["Failed password"]
      threshold: 5
      interval: 60

    # 2. 限制特定用户的错误 (语义化 + 逻辑组合)
    - id: "admin_protect"
      path: "/var/log/app.log"
      action: "dynblack:1h" # 封禁 1 小时
      is: ["login_error"]
      and: ["user=admin"]
      threshold: 3
      interval: 300

    # 3. 拦截恶意爬虫 (正则支持)
    - id: "bad_bot"
      path: "/var/log/nginx/access.log"
      action: "dynblack"
      regex: "(?i)(curl|wget|python|java)/[0-9.]+"

    # 4. 高级逻辑：排除内网 IP 的高频请求
    - id: "rate_limit_external"
      action: "dynblack"
      expression: |
        !InCIDR("10.0.0.0/8") && 
        !InCIDR("192.168.0.0/16") &&
        Count(10) > 50
    
    # 5. 永久黑名单示例
    - id: "known_attacker"
      action: "blacklist"   # 永久封禁
      is: ["malicious_signature"]
```

## 6. 性能优化建议

1.  **优先使用 `path`**: 明确指定规则适用的日志文件，避免对所有日志运行无关规则。
2.  **优先使用语义化字段**: `is`, `contains` 等字段会被自动优化为高效的字节匹配指令。
3.  **正则慎用**: `regex` 比简单的字符串匹配消耗更多 CPU，尽量用 `contains` 代替。
4.  **避免过多的 `Lower()`**: 大小写转换涉及内存分配，尽量在规则中直接写明目标大小写，或使用 `IContains` (已优化)。
