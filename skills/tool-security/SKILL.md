---
name: tool-security
description: "Enforce a least-privilege security gateway between the model and tool execution — tool/directory/command whitelists, risk grading, dangerous-operation confirmation, and audit logging, with bandit & pip-audit as assessment engines."
metadata: {
  "nanobot": {
    "emoji": "🛡️",
    "requires": {"bins": ["python"]},
    "always": false
  }
}
---

# 工具安全控制（Tool Security）

> 本 Skill 配套一个**独立 Python Script/CLI**：项目根目录的 `cli.py`。
> nanobot（或任意 Agent Runtime）通过 bash 工具，在**项目根目录**执行
> `python cli.py "<自然语言指令>"` 即可调用本能力。CLI 负责确定性的文件处理与安全闸门，
> 本 SKILL.md 负责告诉智能体「何时用、参数怎么传、结果如何判定」。

## 0. Script 调用方式（供 Agent Runtime 调用）

- **脚本入口**：项目根目录 `cli.py`（工作目录必须为项目根，因为脚本依赖 `agent/` 包）。
- **调用命令**：`python cli.py "<自然语言指令>" [--max-risk low|medium|high] [--no-llm] [--auto-approve] [--list-tools]`
- **依赖**：`pip install -r requirements.txt`（运行期依赖 bandit；pip-audit 可离线降级）。
- **返回**：退出码 `0`=成功、`2`=拦截、`3`=执行异常；stdout 打印 `[成功]/[blocked]/[denied]` 与结构化结果。

## 1. 适用场景（能力边界与触发条件）

当用户要求智能体读取/写入/删除本地文件、列出目录、或执行系统命令时，本 Skill 负责在
「模型决策」与「工具执行」之间建立最小权限安全网关，确保：

- 只能调用**工具白名单**内注册的工具；
- 文件访问只能落在**目录白名单**允许的目录内；
- **中/高风险操作**（写文件、删除、执行命令）必须先获得用户明确确认；
- 会话级**最小权限**：只开放风险等级不超上限的工具；
- 全程记录**操作审计日志**（不含参数值）。

若意图超出白名单或目录范围，应直接拦截并给出友好提示，而非尝试绕过。

### 评估引擎（安全控制机制的一部分）

本 Skill 集成了两个真实 Python 开源安全工具作为**评估引擎**，在工具「接入/准入」阶段
自动产出安全决策依据，而不是把它们当作被管控的业务工具：

- `bandit`：扫描工具源码，命中危险模式（`subprocess shell=True`、`eval`、硬编码密钥等）
  时自动上调该工具的风险等级。
- `pip-audit`：审计工具依赖清单的已知 CVE，存在漏洞时拒绝该工具准入白名单；离线自动降级跳过。

## 2. 先后顺序（步骤与依赖）

**工具接入阶段（一次性）**：用评估引擎（bandit / pip-audit）扫描新工具源码与依赖，
自动产出风险等级与白名单准入，写入安全策略 `Policy.tool_policies`。

**运行期（每次调用）**：

1. 路由：把自然语言意图映射到（工具名，参数）。
2. 工具白名单校验：未注册工具直接拦截。
3. 最小权限门控：工具风险等级超过会话上限则拦截。
4. 危险操作确认：中/高风险操作请求用户确认，拒绝则终止。
5. 目录白名单 / 命令白名单校验：越界路径、越权命令拦截。
6. 执行工具，返回结构化结果。
7. 落审计日志（决策、风险、参数键名、是否执行、错误、耗时）。

## 3. 命令参数

CLI 入口为 `cli.py`（在项目根目录执行）：

```
python cli.py "<自然语言指令>" [--max-risk low|medium|high] [--auto-approve] [--list-tools] [--no-llm]
```

内置工具（白名单）：

| 工具 | 风险 | 是否确认 | 说明 |
| --- | --- | --- | --- |
| list_dir | low | 否 | 列出目录内容 |
| read_file | low | 否 | 读取文本文件（默认截断 2000 字符） |
| write_file | medium | 是 | 写入文本文件 |
| delete_file | high | 是 | 删除文件（不支持目录） |
| run_command | high | 是 | 命令白名单内执行命令 |

配置工具（元操作，均为 high 且强制确认）：

| 工具 | 说明 |
| --- | --- |
| assess_tool | 接入并评估第三方工具：bandit 划风险、pip-audit 判准入（`name` + `source` + 可选 `requirements`） |
| assess_builtin_tools | 用 bandit 自动评估内置工具的风险等级（自检） |
| set_tool_policy / set_max_risk / add_directory_whitelist / add_command_whitelist / configure_tools | 手动设置安全策略 |

## 4. 失败应对（失败信号与重试降级策略）

- 拦截类失败返回 `blocked` / `denied`，需调整意图或提升权限，不重试。
- 执行异常返回 `error`，保留原始错误信息，不静默吞错。
- 命令超时（默认 30s）自动终止子进程，防止失控。

## 5. 可信判断（结果判定标准与阈值）

- `ok=True` 且 `decision=allowed` 视为成功。
- 审计日志中 `decision` 字段用于回溯每一次调用的放行/拦截/拒绝原因。
- 审计日志只记录参数键名 `params_keys`，不记录参数值，规避敏感信息泄漏。

## 6. 示例

**示例 1：只读操作（自动放行）**

```
> python cli.py "读取 sample.txt"
[会话 12345678] 意图：读取 sample.txt
[成功] {'path': '.../data/sample.txt', 'content': '这是一个用于演示...', ...}
```

**示例 2：危险操作（需确认）**

```
> python cli.py "删除 sample.txt"
[危险操作确认] 即将调用工具 'delete_file'（风险 high），参数键 ['path']，是否继续？[y/N] y
[成功] {'path': '.../data/sample.txt', 'deleted': True}
```

**示例 3：最小权限拦截**

```
> python cli.py --max-risk low "删除 sample.txt"
[blocked] 最小权限拦截：当前会话最大风险 low，工具风险 high
```

**示例 4：评估引擎自检（bandit 自动划分内置工具风险等级）**

```
> python cli.py --no-llm "评估内置工具"
[成功] {'assessed': ['delete_file', 'list_dir', 'read_file', 'run_command', 'write_file'],
        'tool_policies': {..., 'run_command': {'allowed': True, 'risk': 'high'}, ...}}
```
