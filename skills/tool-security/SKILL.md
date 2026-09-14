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
> nanobot（或任意 Agent Runtime）通过 bash 工具，在**项目根目录**执行本 CLI 即可调用。
> 有两种调用方式：
> - **结构化调用（推荐给 Agent Runtime）**：`python cli.py --tool <工具名> --param key=value ...`
>   由宿主 LLM 负责「选工具 + 抽参数」，CLI 只做确定性执行与安全闸门，不再二次理解。
> - **自然语言调用（独立使用 / 离线兜底）**：`python cli.py "<自然语言指令>"`。
> CLI 负责确定性的文件处理与安全闸门，本 SKILL.md 负责告诉智能体「何时用、参数怎么传、结果如何判定」。

## 0. Script 调用方式（供 Agent Runtime 调用）

- **脚本入口**：项目根目录 `cli.py`（工作目录必须为项目根，因为脚本依赖 `core/` 包）。
- **依赖**：`pip install -r requirements.txt`（运行期依赖 bandit；pip-audit 可离线降级）。
- **结构化调用（推荐）**——宿主 LLM 已完成「选工具 + 抽参数」，CLI 只执行与安全校验，不再二次理解、也不加载 `.env`/LLM：

  ```
  python cli.py --tool <工具名> --param key=value [--param key2=value2 ...]
  python cli.py --tool <工具名> --params '{"key": "value", "key2": 42}'
  python cli.py --tool <工具名> [--max-risk low|medium|high] [--auto-approve]
  ```

  > 跨平台建议：`--param KEY=VALUE` 无需引号，最稳妥；`--params '{"key":"value"}'` 在 Windows
  > PowerShell 下会被剥掉双引号，需改用 `--param` 或转义。

- **自然语言调用（独立使用 / 离线兜底）**——由 CLI 内部路由（LLM 优先、关键词回退）：

  ```
  python cli.py "<自然语言指令>" [--max-risk low|medium|high] [--no-llm] [--auto-approve]
  ```

- **列出当前可用工具**：`python cli.py --list-tools`
- **返回**：退出码 `0`=成功、`2`=入口级拦截（未注册工具 / 无法解析意图 / 参数解析错误）、`3`=网关返回非成功结果（`blocked` / `denied` / `error`）；stdout 打印 `[成功]` / `[拦截]` / `[blocked]` / `[denied]` / `[error]` 与结构化结果。

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
# 结构化调用（推荐给 Agent Runtime）
python cli.py --tool <工具名> [--param KEY=VALUE ...] [--params '{"key": "value"}'] \
              [--max-risk low|medium|high] [--auto-approve]

# 自然语言调用（独立使用 / 离线兜底）
python cli.py "<自然语言指令>" [--max-risk low|medium|high] [--no-llm] [--auto-approve]

# 列出当前会话可用工具
python cli.py --list-tools
```

参数说明：

| 参数 | 说明 |
| --- | --- |
| `--tool` | 结构化调用：目标工具名（与自然语言 `intent` 二选一） |
| `--param KEY=VALUE` | 结构化调用：单个参数，可重复多次 |
| `--params '{"key":"value"}'` | 结构化调用：JSON 对象形式的整组参数（与 `--param` 可混用，后者覆盖前者） |
| `--max-risk` | 会话最小权限上限：`low` / `medium` / `high`（默认 `high`） |
| `--auto-approve` | 自动批准中/高风险业务操作；对配置工具（元操作）**不生效** |
| `--no-llm` | 仅自然语言模式：禁用 LLM 路由，强制关键词路由 |
| `--list-tools` | 列出当前可用工具（不执行任何动作） |

内置工具（白名单）：

| 工具 | 风险 | 是否确认 | 参数 | 说明 |
| --- | --- | --- | --- | --- |
| list_dir | low | 否 | `path`（可选，默认 `.`） | 列出目录内容 |
| read_file | low | 否 | `path`（必填）; `max_chars`（可选，默认 2000） | 读取文本文件 |
| write_file | medium | 是 | `path`（必填）; `content`（必填） | 写入文本文件 |
| delete_file | high | 是 | `path`（必填） | 删除文件（不支持目录） |
| run_command | high | 是 | `command`（必填）; `timeout`（可选，默认 30） | 命令白名单内执行命令 |

配置工具（元操作，均为 high 且**强制确认**，`--auto-approve` 不生效）：

| 工具 | 参数 | 说明 |
| --- | --- | --- |
| assess_tool | `name`（必填）; `source`（必填）; `requirements`（可选） | 接入并评估第三方工具：bandit 划风险、pip-audit 判准入 |
| assess_builtin_tools | 无 | 用 bandit 自动评估内置工具的风险等级（自检） |
| set_tool_policy | `tool`（必填）; `allowed`（可选）; `risk`（可选） | 手动设置某工具是否允许及其风险等级 |
| set_max_risk | `risk`（必填） | 设置会话最高风险等级 |
| add_directory_whitelist | `path`（必填）; `action`（add/remove，默认 add） | 新增/移除目录白名单 |
| add_command_whitelist | `command`（必填）; `action`（add/remove，默认 add） | 新增/移除命令白名单 |
| configure_tools | 无（多轮确认向导） | 查看策略并进入权限配置向导 |

## 4. 失败应对（失败信号与重试降级策略）

- 拦截类失败返回 `blocked` / `denied`，需调整意图或提升权限，不重试。
- 执行异常返回 `error`，保留原始错误信息，不静默吞错。
- 命令超时（默认 30s）自动终止子进程，防止失控。

## 5. 可信判断（结果判定标准与阈值）

- `ok=True` 且 `decision=allowed` 视为成功。
- 审计日志中 `decision` 字段用于回溯每一次调用的放行/拦截/拒绝原因。
- 审计日志只记录参数键名 `params_keys`，不记录参数值，规避敏感信息泄漏。

## 6. 示例

> 以下示例均采用**结构化调用**（推荐给 Agent Runtime）。宿主 LLM 负责把用户意图翻译成
> `--tool` + `--param`，CLI 只做确定性执行与安全闸门。

**示例 1：只读操作（自动放行）**

```
> python cli.py --tool read_file --param path=sample.txt
[会话 12345678] 结构化调用，工具=read_file，参数={'path': 'sample.txt'}
[成功] {'path': '.../data/sample.txt', 'content': '这是一个用于演示...', ...}
```

**示例 2：危险操作（需确认）**

```
> python cli.py --tool delete_file --param path=sample.txt
[会话 12345678] 结构化调用，工具=delete_file，参数={'path': 'sample.txt'}
[危险操作确认] 即将调用工具 'delete_file'（风险 high），参数键 ['path']，是否继续？[y/N] y
[成功] {'path': '.../data/sample.txt', 'deleted': True}
```

**示例 3：最小权限拦截**

```
> python cli.py --tool delete_file --param path=sample.txt --max-risk low
[会话 12345678] 结构化调用，工具=delete_file，参数={'path': 'sample.txt'}
[blocked] 最小权限拦截：当前会话最大风险 low，工具风险 high
```

**示例 4：评估引擎自检（bandit 自动划分内置工具风险等级）**

```
> python cli.py --tool assess_builtin_tools
[会话 12345678] 结构化调用，工具=assess_builtin_tools，参数={}
[危险操作确认] 即将调用工具 'assess_builtin_tools'（风险 high），参数键 []，是否继续？[y/N] y
[成功] {'assessed': ['delete_file', 'list_dir', 'read_file', 'run_command', 'write_file'],
        'tool_policies': {..., 'run_command': {'allowed': True, 'risk': 'high'}, ...}}
```

**示例 5：未注册工具（入口级拦截）**

```
> python cli.py --tool unknown_tool
[会话 12345678] 结构化调用，工具=unknown_tool，参数={}
[拦截] 工具白名单拦截：未注册的工具 'unknown_tool' 不允许调用
```

**示例 6：自然语言调用（独立使用 / 离线兜底）**

```
> python cli.py --no-llm "删除 sample.txt"
[会话 12345678] 路由模式=关键词，意图：删除 sample.txt
[危险操作确认] 即将调用工具 'delete_file'（风险 high），参数键 ['path']，是否继续？[y/N] y
[成功] {'path': '.../data/sample.txt', 'deleted': True}
```
