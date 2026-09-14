"""用 DeepSeek（OpenAI 兼容接口）做自然语言意图路由，零依赖（urllib）。

职责边界：LLM 只负责「决定调用哪个工具 + 抽取参数」，真正的执行仍必须经过
工具白名单 / 最小权限 / 目录白名单等安全闸门，因此即便模型被诱导输出危险
指令，也会在后续闸门被拦截。
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Any, Dict, List, Tuple

from .security import SecurityError

# 兜底模型名（DeepSeek 官方公开模型），仅当 .env 未配置时使用。
_DEFAULT_BASE_URL = "https://api.deepseek.com"
_DEFAULT_MODEL = "deepseek-chat"


class LLMRouter:
    """调用兼容 OpenAI 的 /chat/completions 接口，返回 (工具名, 参数) 决策。"""

    def __init__(self, api_key: str, base_url: str, model: str, timeout: int = 30):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    @classmethod
    def from_env(cls, env: Dict[str, str]) -> "LLMRouter":
        """从 load_dotenv() 的结果构建；未配置 key 时 available 为 False。"""
        return cls(
            api_key=env.get("DEEPSEEK_API_KEY", ""),
            base_url=env.get("DEEPSEEK_BASE_URL", _DEFAULT_BASE_URL),
            model=env.get("DEEPSEEK_MODEL", _DEFAULT_MODEL),
        )

    @property
    def available(self) -> bool:
        return bool(self.api_key and self.base_url and self.model)

    def route(self, intent: str, tools_desc: str) -> Tuple[str, Dict[str, Any]]:
        """让 LLM 输出一个结构化工具决策，返回 (tool_name, params)。"""
        content = self._chat(self._system_prompt(tools_desc), intent)
        return self._parse(content)

    def resolve_tools(self, intent: str, tools_desc: str) -> List[str]:
        """让 LLM 规划完成任务所必需的最小工具集（自动最小权限）。"""
        content = self._chat(self._permission_prompt(tools_desc), intent)
        return self._parse_tools(content)

    def _chat(self, system_content: str, user_content: str) -> str:
        """调用 /chat/completions，返回模型回复文本。"""
        if not self.available:
            raise SecurityError("LLM 未配置（缺少 DEEPSEEK_API_KEY），无法路由")

        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_content},
                {"role": "user", "content": user_content},
            ],
            "temperature": 0,
        }

        req = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:300]
            raise SecurityError(f"LLM 调用失败 HTTP {e.code}: {detail}") from e
        except urllib.error.URLError as e:
            raise SecurityError(f"LLM 网络错误: {e.reason}") from e

        return body["choices"][0]["message"]["content"]

    @staticmethod
    def _system_prompt(tools_desc: str) -> str:
        return (
            "你是工具调用决策器。根据用户意图，从下面的白名单工具中选择一个并抽取参数。\n"
            "只输出一个 JSON 对象，不要输出解释或多余文字。\n"
            'JSON 格式：{"tool": "<工具名>", "params": {<参数名>: <值>}}\n'
            "无法匹配时输出：{\"tool\": null, \"params\": {}}\n\n"
            "可用工具（含参数说明）：\n"
            f"{tools_desc}"
        )

    @staticmethod
    def _parse(content: str) -> Tuple[str, Dict[str, Any]]:
        """从模型输出中稳健提取 JSON 决策（容忍前后有多余文字）。"""
        m = re.search(r"\{.*\}", content, re.DOTALL)
        if not m:
            raise SecurityError(f"LLM 未返回有效 JSON: {content[:200]}")
        try:
            obj = json.loads(m.group(0))
        except json.JSONDecodeError as e:
            raise SecurityError(f"LLM 返回 JSON 解析失败: {e}")

        tool = obj.get("tool")
        params = obj.get("params") or {}
        if tool is None:
            raise SecurityError("LLM 无法匹配该意图到任何工具")
        if not isinstance(tool, str) or not isinstance(params, dict):
            raise SecurityError("LLM 返回结构非法（tool/params 类型错误）")
        return tool, params

    @staticmethod
    def _permission_prompt(tools_desc: str) -> str:
        return (
            "你是最小权限规划器。根据用户任务，从下面的工具清单中选出完成该任务所必需的最小工具集。\n"
            "只输出一个 JSON 对象，不要输出解释或多余文字。\n"
            'JSON 格式：{"tools": ["<工具名>", ...]}\n'
            "任务无法由任何工具完成时输出：{\"tools\": []}\n\n"
            "可用工具（含参数说明）：\n"
            f"{tools_desc}"
        )

    @staticmethod
    def _parse_tools(content: str) -> List[str]:
        """从模型输出中稳健提取最小工具集列表。"""
        m = re.search(r"\{.*\}", content, re.DOTALL)
        if not m:
            raise SecurityError(f"LLM 未返回有效 JSON: {content[:200]}")
        try:
            obj = json.loads(m.group(0))
        except json.JSONDecodeError as e:
            raise SecurityError(f"LLM 返回 JSON 解析失败: {e}")

        tools = obj.get("tools")
        if not isinstance(tools, list):
            raise SecurityError("LLM 返回结构非法（tools 应为列表）")
        return [t for t in tools if isinstance(t, str)]
