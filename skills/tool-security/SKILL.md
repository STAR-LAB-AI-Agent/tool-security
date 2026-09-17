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

> 本 Skill 配套一个**自包含 CLI 脚本**：项目根目录的 `cli.py`（核心安全网关仅用 Python 标准库即可运行）。
> nanobot（或任意 Agent Runtime）通过 bash 工具，在**项目根目录**执行 `cli.py`，把工具调用交给确定性的
> 安全网关执行。有两种调用方式：
> - **结构化调用（推荐给 Agent Runtime）**：`python cli.py --tool <工具名> --param key=value ...`
>   由宿主 LLM 负责「选工具 + 抽参数」，网关只做确定性执行与安全闸门，不再二次理解。
> - **自然语言调用**：`python cli.py "<自然语言指令>"`（需 `.env` 配置 LLM，否则走关键词回退）。
> 网关负责确定性的文件处理与安全闸门，本 SKILL.md 负责告诉智能体「何时用、参数怎么传、结果如何判定」。

## 0. Script 调用方式（供 Agent Runtime 调用）

- **脚本入口**：项目根目录 `cli.py`（工作目录必须为项目根，因为依赖 `core/` 包）。
- **依赖**：核心网关仅用 Python 标准库即可运行；bandit / pip-audit 评估引擎需 `pip install -r requirements.txt`。
- **结构化调用（推荐）**——宿主 LLM 已完成「选工具 + 抽参数」，脚本只做安全校验与执行：

  ```
  python cli.py --tool <工具名> --param key=value [--param key2=value2 ...]
  python cli.py --tool <工具名> --params '{"key": "value", "key2": 42}'
  python cli.py --tool <工具名> --max-risk low|medium|high
  ```

  > 跨平台建议：`--param KEY=VALUE` 无需引号，最稳妥；`--params '{"key":"value"}'` 在 Windows
  > PowerShell 下会被剥掉双引号，需改用 `--param` 或转义。

- **自然语言调用**——由脚本内部路由（LLM 优先、关键词回退）：

  ```
  python cli.py "<自然语言指令>"
  ```

- **危险操作确认**——中/高风险操作（写文件、删除、执行命令）与配置工具会**交互式询问确认**；在
  非交互环境（如 nanobot 的 bash 子进程）下会**安全拒绝**而非崩溃，需用 `--auto-approve`（仅演示）
  或改在交互终端执行：

  ```
  python cli.py --tool delete_file --param path=sample.txt                 # 交互终端：输入 y 执行 / n 拒绝
  python cli.py --tool delete_file --param path=sample.txt --auto-approve  # 演示：跳过确认
  ```

- **显式批准（两段式，供非交互 Agent 环境修改安全配置）**——配置工具是修改安全策略本身的元操作，
  必须由人类显式授权，`--auto-approve` 对其不生效。nanobot 等 Agent 在非交互子进程中调用配置工具时，
  脚本不会静默放行，而是**生成一条待批准请求**（`decision=pending`，退出码 `4`），由人类在本机交互
  终端审查批准后，Agent 再携带该请求 ID 重放执行：

  ```
  python cli.py --tool set_max_risk --param risk=low                    # 1) 生成待批准请求 → 返回 request_id
  python cli.py --approve <request_id>                                  # 2) 人类交互审查并批准
  python cli.py --tool set_max_risk --param risk=low --pending-id <request_id>  # 3) 重放执行
  ```

  约束：待批准请求**一次性消费**、默认 **10 分钟过期**、并**绑定精确的工具与参数**（不可跨工具/跨参数复用）；
  `configure_tools` 多轮向导仍只支持交互终端，不参与该两段式。

- **列出当前可用工具**：`python cli.py --list-tools`
- **返回**：退出码 `0`=成功、`2`=拦截、`3`=执行异常或拒绝、`4`=待人类批准（pending）；stdout 打印
  `[成功]` / `[拦截]` / `[blocked]` / `[denied]` / `[error]` / `[待批准]` 与结构化结果。

## 1. 适用场景（能力边界与触发条件）

当用户要求智能体读取/写入/删除本地文件、列出目录、或执行系统命令时，本 Skill 负责在
「模型决策」与「工具执行」之间建立最小权限安全网关，确保：

- 只能调用**工具白名单**内注册的工具；
- 文件访问只能落在**目录白名单**允许的目录内；
- **中/高风险操作**（写文件、删除、执行命令）必须先获得用户明确确认；
- 会话级**最小权限**：只开放风险等级不超上限的工具；
- 全程记录**操作审计日志**（不含参数值）。

若意图超出白名单或目录范围，应直接拦截并给出友好提示，而非尝试绕过。

### 白名单分层（内置工具 vs 外部工具）

不同白名单对两类工具的生效范围不同：

| 白名单 | 内置 func 工具（进程内执行） | 外部 subprocess 工具（external/ 收编） |
| --- | --- | --- |
| 工具白名单（tool_policies / 准入） | 生效 | 生效（deny-by-default 准入） |
| 目录白名单（directory_whitelist） | 生效（进程内 resolve 校验） | 不生效（进程边界） |
| 命令白名单（command_whitelist） | 生效（进程内 _check_command） | 不生效（进程边界） |

外部工具因独立进程边界，网关只能管控「是否启动 + 传入参数」，无法约束其内部访问的目录与执行的命令；
其内部危险进程/命令改由 bandit 在接入时静态扫描发现，并作为风险分级依据（命中 `subprocess shell=True`、
`eval` 等会调高风险等级），而非运行期命令白名单。

### 评估引擎（安全控制机制的一部分）

本 Skill 集成了两个真实 Python 开源安全工具作为**评估引擎**，在工具「接入/准入」阶段
自动产出安全决策依据，而不是把它们当作被管控的业务工具：

- `bandit`：扫描工具源码，命中危险模式（`subprocess shell=True`、`eval`、硬编码密钥等）
  时自动上调该工具的风险等级。
- `pip-audit`：审计工具依赖清单的已知 CVE，存在漏洞时拒绝该工具准入白名单；离线自动降级跳过。

## 2. 先后顺序（步骤与依赖）

> **休眠与激活**：安全控制默认处于**休眠态**（`policy.enabled=false`），业务工具旁路执行、只审计不拦截；
> 首次成功执行任一**配置工具**（如 `configure_tools`、`import_tool`、`confirm_tool_risk` 等）后自动**激活**
> 并持久化到 `config/policy.json`，此后业务工具每次调用都穿过全部运行期闸门。

**工具接入阶段（一次性）**：用评估引擎（bandit / pip-audit）扫描新工具源码与依赖，
自动产出风险等级与白名单准入，写入安全策略 `Policy.tool_policies`。

接入采用**分级确认环**，由「扫描 → 建议分级及原因 → 回显 → 用户确认」组成，并在 `import_tool` 内一步完成：

1. `import_tool` 复制项目后运行 bandit / pip-audit；
2. 产出**建议分级** `risk = max(基础风险, bandit 命中风险)`（bandit 只上调、不降级）；
3. 回显 `risk`（建议分级）与 `reasons`（逐条可读中文原因，含 bandit 命中项与依赖漏洞项）；
4. **可交互终端**：询问「是否按建议分级准入，或输入 low/medium/high 修改」，确认后写入 `allowed=True`；
   **非交互终端**（结构化/子进程调用）：直接按建议分级完成准入。

`confirm_tool_risk` 仍保留，用于接入后再调整某工具的评估分级。

> **接入已有 Skill + Script 项目的边界**：`import_tool` 会把目标项目整包复制到
> `external/<name>/` 并生成 `skills/<name>/SKILL.md` 声明，但**不会删除或移动原目录**。
> 若原目录仍在 nanobot 等 Runtime 的扫描范围内（例如之前已 onboard），会出现
> 「原 SKILL.md 直连原 cli.py」与「声明 SKILL.md 走网关」两个入口，模型可能选错而绕过安全网关。
> 接入后请把原目录从 Runtime 加载范围移除（或不要重复 onboard），仅保留本项目
> `skills/<name>/SKILL.md` 这一份声明作为唯一入口。

**运行期（每次调用）**：

1. 路由：把自然语言意图映射到（工具名，参数）。
2. 工具白名单校验：未注册工具直接拦截；已被策略禁用（allowed=false）或外部工具尚未准入（deny-by-default）同样拦截。
3. 最小权限门控：工具风险等级超过会话上限则拦截。
4. 危险操作确认：中/高风险操作请求用户确认，拒绝则终止。
5. 目录白名单 / 命令白名单校验：越界路径、越权命令拦截（仅内置工具生效）。
6. 执行工具，返回结构化结果。
7. 落审计日志（决策、风险、参数键名、是否执行、错误、耗时）。

## 3. 命令参数

CLI 入口为 `cli.py`（在项目根目录执行）：

```
# 结构化调用（推荐给 Agent Runtime）
python cli.py --tool <工具名> [--param KEY=VALUE ...] [--params '{"key": "value"}']

# 自然语言调用
python cli.py "<自然语言指令>"

# 列出当前可用工具
python cli.py --list-tools
```

参数说明：

| 参数 | 说明 |
| --- | --- |
| `--tool` | 结构化调用：目标工具名（与自然语言 `intent` 二选一） |
| `--param KEY=VALUE` | 结构化调用：单个参数，可重复多次 |
| `--params '{"key":"value"}'` | 结构化调用：JSON 对象形式的整组参数（与 `--param` 可混用，后者覆盖前者） |
| `--max-risk` | 会话最小权限上限：`low` / `medium` / `high`（默认 `high`） |
| `--auto-approve` | 自动批准危险操作（仅演示用；对配置工具不生效） |
| `--list-tools` | 列出当前会话可用工具（不执行任何动作） |
| `--no-llm` | 禁用 LLM 路由，强制使用关键词路由 |
| `--approve REQUEST_ID` | 人类在交互终端审查并批准一条待批准请求（显式批准） |
| `--pending-id REQUEST_ID` | 携带已批准的待批准请求 ID 重放执行配置工具（配合 `--tool` 使用） |
| `--list-pending` | 列出当前待批准请求 |

内置工具（白名单）：

| 工具 | 风险 | 是否确认 | 参数 | 说明 |
| --- | --- | --- | --- | --- |
| list_dir | low | 否 | `path`（可选，默认 `.`） | 列出目录内容 |
| read_file | low | 否 | `path`（必填）; `max_chars`（可选，默认 2000） | 读取文本文件 |
| write_file | medium | 是 | `path`（必填）; `content`（必填） | 写入文本文件 |
| delete_file | high | 是 | `path`（必填） | 删除文件（不支持目录） |
| run_command | high | 是 | `command`（必填）; `timeout`（可选，默认 30） | 命令白名单内执行命令 |

配置工具（元操作，均为 high 且**强制确认**，`import_tool` 除外；交互终端询问确认，`--auto-approve` 不生效，
非交互环境生成**待批准请求**，需人类 `--approve` 批准后 `--pending-id` 重放；`configure_tools` 向导仍需交互终端）：

| 工具 | 参数 | 说明 |
| --- | --- | --- |
| import_tool | `path`（必填）; `name`（可选） | 接入外部 Skill + Script 项目：复制、生成声明、评估风险，交互终端询问确认分级，非交互按建议分级直接准入 |
| confirm_tool_risk | `tool`（必填）; `risk`（可选：low/medium/high） | 分级确认环：确认或修改已接入工具的评估风险，并显式准入（allowed=True） |
| assess_tool | `name`（必填）; `source`（必填）; `requirements`（可选） | 接入并评估第三方工具：bandit 划风险、pip-audit 判准入 |
| assess_builtin_tools | 无 | 用 bandit 自动评估内置工具的风险等级（自检） |
| set_tool_policy | `tool`（必填）; `allowed`（可选）; `risk`（可选） | 手动设置某工具是否允许及其风险等级 |
| set_max_risk | `risk`（必填） | 设置会话最高风险等级 |
| add_directory_whitelist | `path`（必填）; `action`（add/remove，默认 add） | 新增/移除目录白名单 |
| add_command_whitelist | `command`（必填）; `action`（add/remove，默认 add） | 新增/移除命令白名单 |
| configure_tools | 无（多轮确认向导） | 查看策略并进入权限配置向导（需交互终端） |

## 4. 失败应对（失败信号与重试降级策略）

- 拦截类失败返回 `blocked` / `denied`，需调整意图或提升权限，不重试。
- 非交互环境（如 nanobot bash 子进程）无法确认危险操作时返回 `[拦截]`，改用 `--auto-approve`（演示）或交互终端，不重试。
- 非交互环境调用配置工具返回 `[待批准]`（退出码 `4`）：把 `request_id` 交给人类 `--approve` 批准后，用 `--pending-id` 重放，不自行绕过。
- 执行异常返回 `error`，保留原始错误信息，不静默吞错。
- 命令超时（默认 30s）自动终止子进程，防止失控。

## 5. 可信判断（结果判定标准与阈值）

- `ok=True` 且 `decision=allowed` 视为成功。
- 审计日志中 `decision` 字段用于回溯每一次调用的放行/拦截/拒绝原因。
- 审计日志只记录参数键名 `params_keys`，不记录参数值，规避敏感信息泄漏。

## 6. 示例

> 以下示例均采用**结构化调用**（推荐给 Agent Runtime）。宿主 LLM 负责把用户意图翻译成
> `--tool` + `--param`，网关只做确定性执行与安全闸门。

**示例 1：只读操作（自动放行）**

```
> python cli.py --tool read_file --param path=sample.txt
[会话 a1b2c3d4] 结构化调用，工具=read_file，参数={'path': 'sample.txt'}
[成功] {'path': '.../data/sample.txt', 'content': '这是一个用于演示...', ...}
```

**示例 2：危险操作（交互式确认）**

```
> python cli.py --tool delete_file --param path=sample.txt
[会话 a1b2c3d4] 结构化调用，工具=delete_file，参数={'path': 'sample.txt'}
[危险操作确认] 即将调用工具 'delete_file'（风险 high），参数键 ['path']，是否继续？[y/N] y
[成功] {'path': '.../data/sample.txt', 'deleted': True}
```

非交互环境（如 nanobot 的 bash 子进程）下同一操作会安全拒绝而非崩溃：

```
> python cli.py --tool delete_file --param path=sample.txt
[会话 a1b2c3d4] 结构化调用，工具=delete_file，参数={'path': 'sample.txt'}
[拦截] 危险操作需交互确认，但当前为非交互终端；请在交互终端运行，或使用 --auto-approve（仅演示用）
```

**示例 3：最小权限拦截**

```
> python cli.py --tool delete_file --param path=sample.txt --max-risk low
[会话 b2c3d4e5] 结构化调用，工具=delete_file，参数={'path': 'sample.txt'}
[blocked] 最小权限拦截：当前会话最大风险 low，工具风险 high
```

**示例 4：评估引擎自检（bandit 自动划分内置工具风险等级）**

```
> python cli.py --tool assess_builtin_tools
[会话 a1b2c3d4] 结构化调用，工具=assess_builtin_tools，参数={}
[危险操作确认] 即将调用工具 'assess_builtin_tools'（风险 high），参数键 []，是否继续？[y/N] y
[成功] {'assessed': ['delete_file', 'list_dir', 'read_file', 'run_command', 'write_file'],
        'tool_policies': {..., 'run_command': {'allowed': True, 'risk': 'high'}, ...}}
```

**示例 5：未注册工具（入口级拦截）**

```
> python cli.py --tool unknown_tool
[会话 a1b2c3d4] 结构化调用，工具=unknown_tool，参数={}
[拦截] 工具白名单拦截：未注册的工具 'unknown_tool' 不允许调用
```

**示例 6：自然语言调用（需 .env 配置 LLM）**

```
> python cli.py "读取 sample.txt"
[会话 a1b2c3d4] 路由模式=LLM，意图：读取 sample.txt
[成功] {'path': '.../data/sample.txt', 'content': '这是一个用于演示...', ...}
```

**示例 7：外部工具接入 + 分级确认环**

非交互终端（子进程 / nanobot `--tool`）下，`import_tool` 直接按建议分级准入：

```
> python cli.py --tool import_tool --param path=/path/to/some-tool
[会话 a1b2c3d4] 结构化调用，工具=import_tool，参数={'path': '/path/to/some-tool'}
[成功] {'tool': 'some-tool', 'risk': 'high', 'assessed_risk': 'high',
        'confirmed_risk': 'high', 'admitted': True, 'allowed': True, ...}
```

接入后如需再调整分级，可用 `confirm_tool_risk`（同样强制确认）：

```
> python cli.py --tool confirm_tool_risk --param tool=some-tool --param risk=medium
[会话 a1b2c3d4] 结构化调用，工具=confirm_tool_risk，参数={'tool': 'some-tool', 'risk': 'medium'}
[危险操作确认] 即将调用工具 'confirm_tool_risk'（风险 high），参数键 ['tool', 'risk']，是否继续？[y/N] y
[成功] {'tool': 'some-tool', 'assessed_risk': 'high', 'confirmed_risk': 'medium', 'allowed': True}
```

**示例 8：非交互环境修改安全配置（显式批准，两段式）**

```
> python cli.py --tool set_max_risk --param risk=low
[会话 a1b2c3d4] 结构化调用，工具=set_max_risk，参数={'risk': 'low'}
[待批准] 配置工具 'set_max_risk' 需人类显式批准；已生成待批准请求，请在本机交互终端执行 python cli.py --approve 1af16bf43a45f389 后重放
  请求ID: 1af16bf43a45f389
  人类批准: python cli.py --approve 1af16bf43a45f389

> python cli.py --approve 1af16bf43a45f389
[待批准请求] 1af16bf43a45f389
  工具: set_max_risk
  参数: {"risk": "low"}
  过期: 2026-09-15 19:11:43
是否批准该配置修改？[y/N] y
[已批准] 已批准。可携带 --pending-id 1af16bf43a45f389 重放执行该配置操作

> python cli.py --tool set_max_risk --param risk=low --pending-id 1af16bf43a45f389
[会话 b2c3d4e5] 结构化调用，工具=set_max_risk，参数={'risk': 'low'}
[成功] {'max_risk': 'low'}
```
