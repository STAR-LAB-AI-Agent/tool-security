# AI Agent 工具安全控制（题目 26 雏形）

为智能体可调用工具建立**最小权限机制**：工具白名单、目录白名单、危险操作确认，并提供
**完整操作审计日志**（可选功能）。本雏形使用 Python 标准库即可运行，默认走关键词意图路由；
在 `.env` 中配置 DeepSeek 后可切换为真实 LLM 意图路由——LLM 只负责「选工具 + 抽参数」，
执行仍受全部安全闸门约束。

## 安全分层

```
自然语言意图
    │
    ├─[评估引擎] 工具准入评估   assessor.py      bandit 划风险等级 / pip-audit 判白名单准入
    │                                          （结果写入 Policy.tool_policies）
    ├─[闸门 1] 工具白名单       registry.py     未注册工具一律拦截
    ├─[闸门 2] 最小权限         风险分级 + 会话 max_risk 门控
    ├─[闸门 3] 危险操作确认      guard.py        中/高风险需用户确认
    ├─[闸门 4] 目录白名单        directory_policy.py  越界路径拦截
    ├─[闸门 5] 命令白名单        tools.py        越权命令拦截
    │
    ▼
  执行工具（返回结构化结果）
    │
审计日志（全程旁路）audit.py → logs/audit.jsonl
```

> bandit / pip-audit 是「安全控制机制内部的评估引擎」，负责自动产出风险等级与白名单
> 准入依据，而不是被管控的业务工具。详见「开源依赖与许可证」。

## 目录结构

```
topic26_agent_tool_security/
├── cli.py                  # 独立 CLI 入口
├── agent/
│   ├── security.py         # 风险等级、工具元数据、结果、异常
│   ├── tools.py            # 工具实现 + 命令白名单
│   ├── registry.py         # 工具白名单 + 最小权限门控
│   ├── directory_policy.py # 目录白名单
│   ├── guard.py            # 危险操作确认
│   ├── audit.py            # 审计日志
│   ├── policy_store.py     # 安全策略持久化（Policy / tool_policies）
│   ├── assessor.py         # 工具准入评估引擎（bandit + pip-audit）
│   ├── config_tools.py     # 安全配置工具 + 配置执行器
│   ├── gateway.py          # 工具安全执行网关
│   ├── settings.py         # .env 读取（零依赖）
│   ├── llm_router.py       # DeepSeek LLM 意图路由（urllib）
│   └── agent.py            # 意图路由 + 执行编排
├── skills/
│   └── tool-security/SKILL.md  # 统一 Skill 接口（供 nanobot 等 Agent Runtime 加载）
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

- 工具白名单见 `agent/registry.py` 的 `TOOL_REGISTRY`。
- Skill 说明见 `skills/tool-security/SKILL.md`（使用场景、参数、调用方式、结果格式、示例）。

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
命令白名单拦截、意图路由、审计日志落盘且不含参数值、休眠/激活模式，以及评估引擎
（bandit 风险分级、pip-audit 白名单准入、离线降级、内置工具函数级评估）。

## 已知问题

- 关键词路由为雏形；复杂自然语言需在 `.env` 配置 DeepSeek 后切换 LLM 路由。
- `nanobot` / `FastAPI` 未作为本项目运行期依赖，仅按课程要求提供可被 nanobot 加载的 Skill + Script 接口。
