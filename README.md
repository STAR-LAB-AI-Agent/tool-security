# AI Agent 工具安全控制（题目 26 雏形）

为智能体可调用工具建立**最小权限机制**：工具白名单、目录白名单、危险操作确认，并提供
**完整操作审计日志**。核心安全网关仅用 Python 标准库即可运行，默认走关键词意图路由；
bandit / pip-audit 作为「评估引擎」需按 `requirements.txt` 安装。
在 `.env` 中配置 DeepSeek 后可切换为真实 LLM 意图路由——LLM 只负责「选工具 + 抽参数」，
执行仍受全部安全闸门约束。

## 用户场景

- **目标用户**：需要为智能体 / Agent（如 nanobot 等）接入文件读写、目录浏览、命令执行等工具，但不想把权限校验散落在业务代码里的开发者。
- **典型场景**：
  - 让 Agent 只读指定目录下的资料，越界路径自动拦截；
  - 对写文件、删除、执行命令等中/高风险操作，强制用户逐次确认；
  - 接入第三方 Skill + Script 项目时，先用 bandit / pip-audit 评估风险等级，再决定是否准入；
  - 以自然语言（或结构化 `--tool` 调用）动态调整工具白名单、目录/命令白名单、会话风险上限，无需改代码。

## 安全分层

```
自然语言意图
    │
    ├─[接入阶段] 工具准入评估   assessor.py      bandit 划风险等级 / pip-audit 判白名单准入
    │              + 分级确认环  importer.py     建议分级 + 原因回显 → 用户确认准入（交互/非交互）
    │                                          （结果写入 Policy.tool_policies）
    ├─[闸门 1]   工具白名单      registry.py     未注册工具一律拦截
    ├─[闸门 1.2] 策略禁用        policy_store.py 被策略显式禁用（allowed=false）的工具拦截
    ├─[闸门 1.3] 默认拒绝        gateway.py      外部工具 deny-by-default，未准入（allowed=false）拦截
    ├─[闸门 2]   最小权限        registry.py     风险分级 + 会话 max_risk 门控
    ├─[闸门 3]   危险操作确认    guard.py        中/高风险需用户确认
    ├─[闸门 4]   目录白名单      directory_policy.py  越界路径拦截（仅内置工具生效）
    ├─[闸门 5]   命令白名单      tools.py        越权命令拦截（仅内置工具生效）
    │
    ▼
  执行工具（返回结构化结果）
    │
审计日志（全程旁路）audit.py → logs/audit.jsonl
```

> bandit / pip-audit 是「安全控制机制内部的评估引擎」，负责自动产出风险等级与白名单
> 准入依据，而不是被管控的业务工具。详见「开源依赖与许可证」。

### 白名单分层（内置工具 vs 外部工具）

| 白名单 | 内置 func 工具（进程内执行） | 外部 subprocess 工具（external/ 收编） |
| --- | --- | --- |
| 工具白名单（tool_policies） | 生效 | 生效（deny-by-default 准入） |
| 目录白名单（directory_whitelist） | 生效（进程内 resolve 校验） | 不生效（进程边界） |
| 命令白名单（command_whitelist） | 生效（进程内 _check_command） | 不生效（进程边界） |

外部工具因独立进程边界，网关只能管控「是否启动 + 传入参数」，无法约束其内部访问的目录与执行的命令；
其内部危险进程/命令改由 bandit 在接入时静态扫描发现，并作为风险分级依据，而非运行期目录/命令白名单。

### 安全控制的休眠与激活

- 安全控制默认处于**休眠态**（`policy.enabled=false`）：此时业务工具旁路执行，只审计、不拦截，便于先完成工具接入与策略配置。
- 首次成功执行任一**配置工具**（如 `configure_tools`、`import_tool`、`confirm_tool_risk` 等）后，安全控制自动**激活**（`enabled=true`）并持久化到 `config/policy.json`。
- 激活后，业务工具的每次调用都穿过全部运行期闸门（工具白名单 → 最小权限 → 确认 → 目录/命令白名单）。
- 配置工具（元操作）无论休眠或激活都走独立的 `ConfigExecutor`，且**强制用户确认**（`--auto-approve` 对配置工具不生效），防止智能体静默给自己开权限。

### 显式批准（两段式，供非交互 Agent 环境）

配置工具修改的是安全策略本身，必须由人类显式授权。但 nanobot 等 Agent Runtime 在非交互子进程（无 TTY）
中调用工具，无法就地 `input()` 确认。因此采用**两段式待批准**，既不静默放行、也不一拒了之：

1. Agent 在非交互环境调用配置工具 → 生成**待批准请求**并返回 `request_id`（`decision=pending`，退出码 `4`），此时不做任何策略修改；
2. 人类在本机交互终端执行 `python cli.py --approve <request_id>`，逐条审查后批准；
3. Agent 携带 `--pending-id <request_id>` 重放同一调用 → 校验通过（已批准 / 未过期 / 工具与参数完全一致）后才执行，请求被**一次性消费**。

```bash
python cli.py --tool set_max_risk --param risk=low                    # 1) 生成待批准请求
python cli.py --approve <request_id>                                  # 2) 人类审查并批准
python cli.py --tool set_max_risk --param risk=low --pending-id <request_id>  # 3) 重放执行
```

约束：请求一次性消费、默认 10 分钟过期、绑定精确的工具与参数（不可复用）；`configure_tools` 多轮向导仍只支持交互终端。

## 目录结构

```
topic26_agent_tool_security/
├── cli.py                  # 独立 CLI 入口（自然语言 / 结构化两种调用）
├── core/
│   ├── security.py         # 风险等级、工具元数据、结果、异常
│   ├── tools.py            # 内置工具实现 + 命令白名单
│   ├── registry.py         # 工具白名单 + 最小权限门控
│   ├── directory_policy.py # 目录白名单（路径越界校验）
│   ├── guard.py            # 危险操作确认
│   ├── audit.py            # 审计日志（JSON Lines 落盘）
│   ├── policy_store.py     # 安全策略持久化（Policy / tool_policies）
│   ├── external_tools.py   # 外部工具 subprocess 执行 + 注册记录持久化
│   ├── importer.py         # 工具接入器（import_tool：复制/声明/评估/注册）
│   ├── assessor.py         # 工具准入评估引擎（bandit + pip-audit + 分级原因）
│   ├── config_tools.py     # 安全配置工具 + 配置执行器（含分级确认环）
│   ├── pending_approval.py # 显式批准：待批准请求存储（两段式，非交互 Agent 环境）
│   ├── gateway.py          # 工具安全执行网关（运行期闸门）
│   ├── settings.py         # .env 读取（零依赖）
│   ├── llm_router.py       # DeepSeek LLM 意图路由（urllib）
│   └── agent.py            # 意图路由 + 执行编排
├── skills/
│   └── tool-security/SKILL.md  # 统一 Skill 接口（供 nanobot 等 Agent Runtime 加载）
├── config/
│   ├── policy.json             # 安全策略（配置期写入，运行期加载）
│   └── external_tools.json     # 外部工具注册表（接入时写入，启动时恢复）
├── external/               # 收编的外部工具项目（import_tool 接入时生成）
├── data/                   # 目录白名单默认根目录 + 示例数据
├── logs/                   # 审计日志（运行时生成 logs/audit.jsonl）
├── tests/                  # 测试用例
├── .env.example            # .env 配置示例（脱敏）
├── requirements.txt
└── README.md
```

## 安装与运行

要求 Python 3.10+。安装依赖：

```bash
pip install -r requirements.txt
```

```bash
# 列出当前会话可用工具
python cli.py --list-tools

# 只读操作（自动放行）
python cli.py "读取 sample.txt"
python cli.py "列出 ."

# 危险操作（交互式确认）
python cli.py "删除 sample.txt"

# 最小权限会话（low 只读，写/删/命令会被拦截）
python cli.py --max-risk low "删除 sample.txt"

# 用 bandit 自动评估内置工具的风险等级（安全控制机制自检）
python cli.py --no-llm "评估内置工具"

# 接入并评估一个第三方工具（bandit 划风险 + pip-audit 判准入）
python cli.py --no-llm "评估工具 mytool 源码 \"path/to/tool.py\""

# 强制使用关键词路由（不读 .env / 不调 LLM）
python cli.py --no-llm "读取 sample.txt"
```

### 接入真实 LLM（可选）

将项目根目录的 `.env.example` 复制为 `.env`（或复用上级目录已有的 `.env`），填入 DeepSeek
配置后，agent 会自动切换到 LLM 意图路由，无需改动代码：

```bash
DEEPSEEK_API_KEY=sk-xxxxxx
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-chat
```

未配置 `DEEPSEEK_API_KEY` 或断网时，会自动回退到关键词路由，保证离线可运行。

## 工具与 Skill 使用方式

- 工具白名单见 `core/registry.py` 的 `TOOL_REGISTRY`。
- Skill 说明见 `skills/tool-security/SKILL.md`（使用场景、参数、调用方式、结果格式、示例）。

### 外部工具接入（import_tool）

可通过 `python cli.py --tool import_tool --param path=<外部项目路径>` 把一个外部
Skill + Script 项目收编进安全网关：整包复制到 `external/<name>/`、生成声明、bandit/pip-audit
评估，并注册为 deny-by-default。

接入即触发**分级确认环**，并在 `import_tool` 内一步完成：

1. **扫描**：bandit 扫源码危险模式（`B602 shell=True`、`B404 subprocess`、`B102 硬编码密钥` 等），
   pip-audit 扫 `requirements.txt` 已知 CVE；
2. **建议分级**：`risk = max(基础风险, bandit 命中风险)`，bandit 只上调、不降级；
3. **原因回显**：回显 `risk`（建议分级）与 `reasons`（逐条可读中文原因）；
4. **确认准入**：
   - **可交互终端**（检测到 TTY）：询问「是否按建议分级准入，或输入 `low/medium/high` 修改」，确认后写入 `allowed=True`；
   - **非交互终端**（子进程 / nanobot `--tool` 结构化调用）：直接按建议分级完成准入。

```bash
# 交互终端：回显建议分级与原因后，询问确认或修改分级，再完成准入
python cli.py --tool import_tool --param path=<外部项目路径>

# 非交互终端（子进程 / nanobot --tool）：直接按建议分级准入
python cli.py --tool import_tool --param path=<外部项目路径>
```

接入后如需再调整分级，可用 `confirm_tool_risk`：

```bash
# 沿用评估分级（省略 risk）即准入
python cli.py --tool confirm_tool_risk --param tool=<name>

# 或：修改分级后准入（如改成 medium）
python cli.py --tool confirm_tool_risk --param tool=<name> --param risk=medium
```

> 注意：接入不会删除/移动原项目目录。若原目录仍在 nanobot 等 Runtime 扫描范围内，
> 会出现「原 SKILL.md 直连原 cli.py」与「声明 SKILL.md 走网关」两个入口，可能绕过安全网关。
> 接入后请把原目录移出加载范围（或不要重复 onboard），仅保留 `skills/<name>/SKILL.md` 声明作为唯一入口。

## 开源依赖与许可证

本项目集成的两个真实 Python 开源项目，均作为「工具安全控制机制」的评估引擎使用：

| 项目 | 版本 | 许可证 | 实际使用方式 |
|------|------|--------|-------------|
| [bandit](https://github.com/PyCQA/bandit) | 1.9.4 | Apache-2.0 | `assessor.py` 调用其 CLI 对工具源码做静态安全扫描，命中危险模式（如 `subprocess shell=True`、`eval`、硬编码密钥）时自动上调该工具的风险等级 |
| [pip-audit](https://github.com/pypa/pip-audit) | 2.10.1 | Apache-2.0 | `assessor.py` 调用其 CLI 审计工具依赖清单的已知 CVE，存在漏洞则拒绝该工具准入白名单（`allowed=False`）；离线时自动降级跳过 |

- LLM 路由通过 `urllib` 直接调用 DeepSeek 的 OpenAI 兼容接口，不引入额外 SDK。

## 在 nanobot 中加载与调用

本项目遵循「统一 Skill + Script」接口：**Script（`cli.py`）负责确定性的安全闸门与工具执行，
Skill（`skills/tool-security/SKILL.md`）负责告诉 Agent Runtime 何时调用、如何传参、如何判定结果**。
因此不强制依赖 nanobot，但可被 nanobot 等任意遵循 `skills/<name>/SKILL.md` 规范的 Runtime 加载。

### 加载方式

将本项目根目录作为 nanobot 的 workspace（或把 `skills/tool-security/` 放入 workspace 的
`skills/` 下），nanobot 的 `SkillsLoader` 会扫描 `skills/*/SKILL.md` 并读取 YAML frontmatter：

```python
from pathlib import Path
from nanobot.agent.skills import SkillsLoader

loader = SkillsLoader(Path("本项目根目录"))
print(loader.list_skills())   # 应包含 {"name": "tool-security", ...}
```

Skill 的 frontmatter 声明了 `name`、`description`（LLM 触发依据）与
`metadata.nanobot`（`emoji`、`requires.bins: ["python"]`、`always: false`）。

### 调用方式

nanobot 加载 Skill 后，由 LLM 依据 `description` 触发；实际执行时通过 bash 工具在
**项目根目录**调用 Script：

```bash
python cli.py "<自然语言指令>"
```

最小交互示例（nanobot 会话内）：

```
用户：帮我读取 data/sample.txt
nanobot：调用 skill `tool-security` → 执行 python cli.py "读取 sample.txt"
CLI：[成功] {'path': '.../data/sample.txt', 'content': '...', ...}
```

退出码约定：`0`=成功、`2`=拦截、`3`=执行异常或拒绝、`4`=待人类批准（pending）；stdout 打印 `[成功]/[blocked]/[denied]/[待批准]`。
（安装：`pip install nanobot-ai`，随后在 workspace 下运行 `nanobot` 即可；调用本 skill 无需 nanobot 专属 API。）

## 低 Token 与性能优化

本项目遵循「长文本优先由 Python 程序筛选/截断，只把必要信息交给模型」的思路，已落地以下优化：

1. **长文本截断**：`read_file` 默认只返回前 `max_chars=2000` 字符，并附带 `truncated` / `total_chars` 标记；`run_command` 的 stdout / stderr 各截断到 2000 字符，避免大文件内容整体进入模型上下文。
2. **结构化返回**：所有工具返回紧凑的 dict（而非完整文件原文），便于模型只消费必要字段。
3. **审计脱敏同时减少冗余**：审计日志只记录参数键名（`params_keys`），既避免敏感信息泄漏，也避免把参数值写入日志带来额外体积。

优化思路：把「筛选、截断、统计」这类确定性工作留在 Python 层完成，只把最终必要信息交给 LLM，从而降低 Token 消耗与响应时间。

## 测试

```bash
python -m unittest discover -s tests -v
```

测试覆盖：工具白名单拦截、目录白名单拦截、最小权限拦截、危险操作确认（通过/拒绝）、
命令白名单拦截、意图路由、审计日志落盘且不含参数值、休眠/激活模式，评估引擎
（bandit 风险分级、pip-audit 白名单准入、离线降级、内置工具函数级评估），
分级确认环（import_tool 建议分级与原因回显、交互确认/修改分级、非交互按建议直接准入，
confirm_tool_risk 再调整分级并准入），以及显式批准（待批准请求两段式：生成、批准、
重放、一次性消费、参数/工具绑定、过期清理）。

## 已知问题

- 关键词路由为雏形；复杂自然语言需在 `.env` 配置 DeepSeek 后切换 LLM 路由。
- `nanobot` 未作为本项目运行期依赖，仅按课程要求提供可被 nanobot 加载的 Skill + Script 接口。
