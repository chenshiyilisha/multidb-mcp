# multidb-mcp

一个轻量的 **MCP Server**，让 AI 客户端（WorkBuddy、Claude Code、Cursor、Cline 等）通过 MCP 协议安全地访问 **达梦数据库（DM8）**、**SQL Server** 和 **MySQL / MariaDB**。对话里直接说"列出表""查一下某张表"，AI 就会调用工具执行，不用手动复制 SQL 切工具。

## 特性

- **三库支持**：达梦（官方 `dmdb` 驱动）+ SQL Server（`mssql` 驱动）+ MySQL（`mysql2` 驱动），同一套统一工具接口。
- **`npx` 一行启动**：无需手动装驱动、建环境，客户端配置里写 `npx multidb-mcp` 即可。
- **连接池复用**：每个连接懒加载、池常驻，重复调用复用连接，不反复重连。
- **查询超时**：统一的硬超时（JS 层 `Promise.race`），慢查询不会卡死 MCP 的 stdio 循环。
- **审计日志**：每次工具调用输出结构化 JSON 到 stderr（工具名、连接、耗时、行数、是否慢查询、是否写尝试），便于排查与合规。
- **安全默认**：默认只读，只允许 `SELECT / SHOW / DESCRIBE / EXPLAIN / WITH`；多语句注入拦截；标识符白名单校验；`list_connections` 绝不外泄密码。
- **多连接显式路由**：配置多个连接时，不传连接名会报错并返回连接目录，避免 LLM 静默查错库（dev/prod 搞混）。
- **查询治理**：`maxRows` 行数上限 + 截断标记，防止结果集过大。

## 提供的工具

| 工具 | 作用 |
|---|---|
| `test_connection` | 验证连接，返回数据库版本和当前 schema |
| `list_connections` | 列出所有已配置连接（不含密码） |
| `list_tables` | 列出指定 schema 下的所有表 |
| `describe_table` | 返回表的列名、类型、长度、是否可空、默认值、注释 |
| `execute_sql` | 执行单条 SQL，返回结果行（受只读策略和行数上限约束） |

## 安装与接入

### 1. 前置条件

- **Node.js ≥ 18**（本机已装 v22 即可）。MCP 通过 `npx` 启动，不需要 Python。

### 2. 配置连接信息

通过环境变量配置。**单连接**（最常见）：

| 环境变量 | 说明 | 默认 |
|---|---|---|
| `MULTIDB_DB_TYPE` | `dameng` / `sqlserver` / `mysql` | `dameng` |
| `MULTIDB_HOST` | 数据库主机 | 必填 |
| `MULTIDB_PORT` | 端口 | 达梦 `5236` / SQL Server `1433` / MySQL `3306` |
| `MULTIDB_USER` | 账号 | 必填 |
| `MULTIDB_PASSWORD` | 密码 | — |
| `MULTIDB_SCHEMA` | 达梦 schema / SQL Server 数据库名 / MySQL 数据库名 | — |
| `MULTIDB_READ_ONLY` | `true` 只读 / `false` 可写 | `true` |
| `MULTIDB_MAX_ROWS` | 单次查询最大返回行数 | `1000` |
| `MULTIDB_QUERY_TIMEOUT_MS` | 查询硬超时（毫秒），`0` 表示不限 | `30000` |
| `MULTIDB_SLOW_QUERY_MS` | 慢查询阈值（毫秒），超过则审计标记 `slow=true` | `1000` |

> **SQL Server 加密**：默认开启加密并信任服务器自签名证书（内网常见场景）。可用 `MSSQL_ENCRYPT=false` 关闭加密、`MSSQL_TRUST_CERT=false` 关闭证书信任。

**多连接**：用 `MULTIDB_CONNECTIONS` 传一个 JSON 数组，每个元素是一条连接（字段同上，另有 `name`）：

```json
[
  { "name": "dev",  "type": "dameng",   "host": "192.168.0.30", "port": 5236, "user": "SYSDBA", "password": "pw", "schema": "SYSDBA", "readOnly": true },
  { "name": "prod", "type": "sqlserver", "host": "10.0.1.100",   "port": 1433, "user": "sa",    "password": "pw", "schema": "PROD",  "readOnly": true },
  { "name": "web",  "type": "mysql",     "host": "10.0.2.50",    "port": 3306, "user": "web",   "password": "pw", "schema": "appdb",  "readOnly": true }
]
```

### 3. 写入客户端 MCP 配置

**WorkBuddy**：`C:\Users\hejih\.workbuddy\mcp.json`（注意不是带点前缀的 `.mcp.json`），在 `mcpServers` 里加：

```json
{
  "mcpServers": {
    "multidb": {
      "command": "npx",
      "args": ["-y", "multidb-mcp"],
      "env": {
        "MULTIDB_DB_TYPE": "dameng",
        "MULTIDB_HOST": "192.168.0.30",
        "MULTIDB_PORT": "5236",
        "MULTIDB_USER": "SYSDBA",
        "MULTIDB_PASSWORD": "你的密码",
        "MULTIDB_SCHEMA": "SYSDBA",
        "MULTIDB_READ_ONLY": "true",
        "MULTIDB_MAX_ROWS": "1000",
        "MULTIDB_QUERY_TIMEOUT_MS": "30000"
      }
    }
  }
}
```

写完重启客户端生效。多连接时把 `MULTIDB_CONNECTIONS` 换成 JSON 数组即可，工具调用时用 `connection` 参数指定连接名。

> **发布到 npm 之前**：项目尚未发布到公共 registry，`npx multidb-mcp` 依赖 `npm link`（本机已 link）或发布后才能全局拉取。若在未发布状态下使用，可把 `args` 改为本地入口：`["-y", "--", "node", "E:/WorkBuddy/.../multidb-mcp/build/index.js"]`，或先 `npm link`。

## 安全说明

- **默认只读**：首次接入建议保持 `MULTIDB_READ_ONLY=true`，先只读探一圈，确认无误再开写。
- **SQL 注入防护**：标识符白名单校验（`[A-Za-z_#$][A-Za-z0-9_$#]*`，允许 SQL Server 临时表 `#`/`##` 前缀）；多语句（非结尾分号）一律拦截；字符串字面量和注释先剥离再做策略检查。
- **密码保护**：`list_connections` 返回的连接信息已剔除密码，绝不外泄给客户端/LLM。密码写在配置文件是明文，注意别把配置文件随手分享。
- **数据库账号最小权限**：建议给 MCP 用的账号仅授予 `SELECT` 权限，作为最后一道闸。
- **审计**：所有工具调用（含被策略拒绝的写尝试、超时、慢查询）都会在 stderr 输出一条 JSON 审计记录，可用 shell 重定向 `2> audit.log` 收集。

## 开发

```bash
npm install          # 安装依赖
npm run build        # 编译 TypeScript 到 build/
npm run dev          # tsx 直接运行源码（开发模式）
npm run smoke        # stdio 冒烟测试（需真实数据库，配好环境变量）
npm run test:unit    # 安全策略 + 配置路由单元测试（无需数据库）
node tests/test_db.mjs   # 数据库层单元测试（假连接池，无需真实库）
```

项目结构：

```
multidb-mcp/
├── src/
│   ├── config.ts    # 连接配置解析与多连接路由
│   ├── security.ts  # SQL 安全策略（标识符、只读、多语句）
│   ├── db.ts        # 达梦 / SQL Server / MySQL 连接抽象（池 + 超时）
│   ├── audit.ts     # 审计日志（stderr JSON）
│   ├── server.ts    # MCP 工具层
│   └── index.ts     # stdio 入口
├── tests/
│   ├── smoke.mjs    # 真实 MCP 协议冒烟测试
│   ├── unit.mjs     # 安全策略 + 配置路由单元测试
│   └── test_db.mjs  # 数据库层单元测试（假池）
└── legacy-python/   # 原 Python 实现（已弃用，保留参考）
```

## 许可证

MIT
