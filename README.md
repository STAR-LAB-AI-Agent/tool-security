# AI Agent 工具安全控制（题目 26 雏形）

为智能体可调用工具建立**最小权限机制**：工具白名单、目录白名单、危险操作确认，并提供
**完整操作审计日志**。核心安全网关仅用 Python 标准库即可运行，默认走关键词意图路由；
bandit / pip-audit 作为「评估引擎」需按 `requirements.txt` 安装。
在 `.env` 中配置 DeepSeek 后可切换为真实 LLM 意图路由——LLM 只负责「选工具 + 抽参数」，
执行仍受全部安全闸门约束。

## 安全分层

```
自然语言意图
    │
    ├─[接入阶段] 工具准入评估   assessor.py      bandit 划风险等级 / pip-audit 判白名单准入
    │              + 分级确认环  importer.py     建议分级 + 原因回显 → confirm_tool_risk 用户确认
    │                                          （结果写入 Policy.tool_policies）
    ├─[闸门 1]   工具白名单      registry.py     未注册工具一律拦截
    ├─[闸门 1.2] 策略禁用        policy_store.py 被策略显式禁用（allowed=false）的工具拦截
    ├─[闸门 1.3] 默认拒绝        gateway.py      外部工具 deny-by-default，未准入（confirm_tool_risk）拦截
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

接入即触发**分级确认环**：

1. **扫描**：bandit 扫源码危险模式（`B602 shell=True`、`B404 subprocess`、`B102 硬编码密钥` 等），
   pip-audit 扫 `requirements.txt` 已知 CVE；
2. **建议分级**：`risk = max(基础风险, bandit 命中风险)`，bandit 只上调、不降级；
3. **原因回显**：`import_tool` 返回 `risk`（建议分级）与 `reasons`（逐条可读中文原因），供用户审阅；
4. **最终确认**：用户用 `confirm_tool_risk` 确认评估分级（或改成 `low/medium/high`），
   该工具随即被显式准入（`allowed=True`）。

```bash
# 接入：返回建议分级 risk 与分级原因 reasons（此刻 admitted=false，尚未准入）
python cli.py --tool import_tool --param path=<外部项目路径>

# 确认：沿用评估分级（省略 risk）即准入
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

退出码约定：`0`=成功、`2`=拦截、`3`=执行异常；stdout 打印 `[成功]/[blocked]/[denied]`。
（安装：`pip install nanobot-ai`，随后在 workspace 下运行 `nanobot` 即可；调用本 skill 无需 nanobot 专属 API。）

## 测试

```bash
python -m unittest discover -s tests -v
```

测试覆盖：工具白名单拦截、目录白名单拦截、最小权限拦截、危险操作确认（通过/拒绝）、
命令白名单拦截、意图路由、审计日志落盘且不含参数值、休眠/激活模式，评估引擎
（bandit 风险分级、pip-audit 白名单准入、离线降级、内置工具函数级评估），以及
分级确认环（import_tool 建议分级与原因回显、confirm_tool_risk 确认/修改分级并准入）。

## 已知问题

- 关键词路由为雏形；复杂自然语言需在 `.env` 配置 DeepSeek 后切换 LLM 路由。
- `nanobot` / `FastAPI` 未作为本项目运行期依赖，仅按课程要求提供可被 nanobot 加载的 Skill + Script 接口。
