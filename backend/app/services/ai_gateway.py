import re
import json
from typing import Any

import httpx
import json
from typing import Any, AsyncGenerator
from fastapi import HTTPException


async def async_chat_stream(
    messages: list[dict[str, str]],
    settings: dict[str, Any],
    *,
    temperature: float | None = None,
    timeout: int = 120,
) -> AsyncGenerator[str, None]:
    """
    异步流式请求大模型，生成 Token 序列。
    """
    provider = settings.get("provider", "openai-compatible")
    model = settings.get("model", "")
    base_url = (settings.get("base_url") or "").rstrip("/")
    api_key = settings.get("api_key") or ""
    temp = settings.get("temperature", 0.3) if temperature is None else temperature

    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    
    if provider == "ollama":
        if base_url.endswith("/v1"):
            base_url = base_url[:-3].rstrip("/")
        url = f"{base_url or 'http://localhost:11434'}/api/generate"
        prompt = "\n\n".join(f"{item.get('role', 'user')}:\n{item.get('content', '')}" for item in messages)
        payload = {"model": model or "llama3", "prompt": prompt, "stream": True}
        
        async with httpx.AsyncClient(timeout=timeout) as client:
            async with client.stream("POST", url, json=payload) as resp:
                if resp.status_code != 200:
                    raise HTTPException(status_code=resp.status_code, detail=f"Ollama stream error: {await resp.aread()}")
                async for line in resp.aiter_lines():
                    if not line: continue
                    try:
                        chunk = json.loads(line)
                        if "response" in chunk:
                            yield chunk["response"]
                    except Exception: continue
    else:
        # OpenAI Compatible
        url = f"{base_url or 'https://api.openai.com/v1'}/chat/completions"
        payload = {"model": model, "messages": messages, "temperature": temp, "stream": True}
        
        async with httpx.AsyncClient(timeout=timeout) as client:
            async with client.stream("POST", url, headers=headers, json=payload) as resp:
                if resp.status_code != 200:
                    raise HTTPException(status_code=resp.status_code, detail=f"AI stream error: {await resp.aread()}")
                async for line in resp.aiter_lines():
                    if line.startswith("data: "):
                        data_str = line[6:].strip()
                        if data_str == "[DONE]": break
                        try:
                            chunk = json.loads(data_str)
                            delta = chunk.get("choices", [{}])[0].get("delta", {})
                            if "content" in delta:
                                yield delta["content"]
                        except Exception: continue


def chat_completion(
    messages: list[dict[str, str]],
    settings: dict[str, Any],
    *,
    temperature: float | None = None,
    timeout: int = 120,
) -> str:
    # 保持同步接口，内部使用 httpx 同步客户端
    provider = settings.get("provider", "openai-compatible")
    model = settings.get("model", "")
    base_url = (settings.get("base_url") or "").rstrip("/")
    api_key = settings.get("api_key") or ""
    temp = settings.get("temperature", 0.3) if temperature is None else temperature

    if provider == "ollama":
        prompt = "\n\n".join(f"{item.get('role', 'user')}:\n{item.get('content', '')}" for item in messages)
        if base_url.endswith("/v1"):
            base_url = base_url[:-3].rstrip("/")
        url = f"{base_url or 'http://localhost:11434'}/api/generate"
        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.post(url, json={"model": model or "llama3", "prompt": prompt, "stream": False})
                resp.raise_for_status()
                return resp.json().get("response", "")
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"AI 服务调用失败 (Ollama): {exc}") from exc

    if not api_key:
        raise HTTPException(status_code=400, detail="AI 接口密钥未配置")
    
    url = f"{base_url or 'https://api.openai.com/v1'}/chat/completions"
    try:
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(url, headers=headers, json={"model": model, "messages": messages, "temperature": temp})
            resp.raise_for_status()
            data = resp.json()
            choices = data.get("choices") or []
            return choices[0].get("message", {}).get("content", "") if choices else ""
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"AI 服务调用失败: {exc}") from exc


def parse_json_object(text: str) -> dict[str, Any]:
    cleaned = _clean_regex(text or "")
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`").strip()
    try:
        return json.loads(cleaned)
    except Exception:
        match = re.search(r"\{[\s\S]*\}", cleaned)
        if match:
            try:
                return json.loads(match.group(0))
            except Exception:
                pass
    return {}


def generate_match_regex(sample_log: str, field_name: str, expected_output: str) -> str:
    """
    纯规则匹配生成核心逻辑优化：
    1. 严格锚点模式：定位上下文 Key，提取其与预期值之间的所有字符（含换行）作为前缀。
    2. 通用内容提取：捕获组使用 ([\\s\\S]+?)，确保能稳定提取任何形式的中间内容。
    3. 智能边界锁定：自动探测预期值后的第一个非单词字符（或行尾）作为结束边界。
    """
    log = sample_log or ""
    expected = (expected_output or "").strip()
    context = (field_name or "").strip()
    
    if not expected or expected not in log:
        return ""

    # 1. 定位预期输出在日志中的位置
    idx = log.find(expected)
    
    # 2. 提取搜索键（锚点）
    search_key = context
    if expected in context:
        search_key = context.split(expected)[0].strip()
    
    # 移除 search_key 结尾可能的冒号或等号
    search_key = search_key.rstrip(":：= \t-")

    prefix_regex = ""
    if search_key:
        # 在 idx 之前寻找最近的 search_key
        field_idx = log.rfind(search_key, 0, idx)
        if field_idx >= 0:
            # 提取从 search_key 结束到 expected 之前的所有文本（包括可能的空格、换行、符号）
            gap_text = log[field_idx + len(search_key) : idx]
            # 构建前缀：转义 Key + 转义间隙文本（并将空白符转为 \s*）
            prefix_regex = re.escape(search_key) + re.escape(gap_text)
    
    # 如果没找到锚点，或者锚点太远，尝试截取当前行
    if not prefix_regex or len(prefix_regex) > 100:
        last_newline = log.rfind("\n", 0, idx)
        start_pos = max(0, last_newline + 1 if last_newline >= 0 else idx - 20)
        prefix_regex = re.escape(log[start_pos : idx])

    # 将前缀中的转义空格/换行统一转为灵活匹配
    prefix_regex = re.sub(r"(\\n|\\r|\\t|\\\s)+", r"\\s*", prefix_regex)
    if not prefix_regex.endswith(r"\\s*") and not any(prefix_regex.endswith(c) for c in [":", "=", " ", ">"]):
        prefix_regex += r"\s*"

    # 3. 探测后缀边界：寻找预期值后的第一个字符
    after_text = log[idx + len(expected) : ]
    suffix_regex = ""
    # 寻找第一个非字母数字字符（包括换行、逗号、引号等）作为边界
    boundary_match = re.search(r"^[^\w\u4e00-\u9fa5]", after_text)
    if boundary_match:
        b_char = boundary_match.group(0)
        # 如果边界是引号、括号等闭合符，直接匹配该字符以确保提取完整
        if b_char in ["\"", "'", "]", "}", ")", ">"]:
            suffix_regex = re.escape(b_char)
        else:
            # 否则使用正向肯定断言，不吃掉该字符
            suffix_regex = f"(?={re.escape(b_char)})"
    elif not after_text:
        # 如果是行尾或全文结尾
        suffix_regex = r"$"

    # 4. 组合结果：使用通用提取模式 ([\s\S]+?)
    # 对于 IP/数字等简单类型，可以保持专用模式，但用户要求“不管预期匹配是什么”，所以优先保证提取成功
    val_pattern = r"[\s\S]+?"
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", expected):
        val_pattern = r"(?:\d{1,3}\.){3}\d{1,3}"
    elif re.fullmatch(r"\d+", expected):
        val_pattern = r"\d+"

    result = rf"{prefix_regex}({val_pattern}){suffix_regex}"

    # 兜底验证
    return _validate_expected(log, result, expected) or result


def generate_regex(sample_log: str, field_name: str, settings: dict[str, Any], expected_output: str = "") -> str:
    """AI 解析生成：优化提示词，确保精准定位键值对并在值结束处立即截止"""
    system_prompt = (
        "你是一个资深网络安全日志正则专家。\n"
        "任务：为用户提供的日志片段生成一个高精度的 Python 正则表达式（使用 re.S 模式）。\n"
        "准则：\n"
        "1. 必须使用锚点：利用匹配字段上下文（Key）作为前导锚点，严禁直接从行首开始盲目匹配。\n"
        "2. 精准截止：捕获组 () 必须在提取到预期值后立即结束，不能包含后续的引号、逗号、空格或换行符。\n"
        "3. 灵活性：日志中 Key 与 Value 之间的空格、冒号、等号请使用 \\s*[:=]?\\s* 处理，以兼容微小格式变化。\n"
        "4. 捕获模式：对 IP 地址使用 (?:\\d{1,3}\\.){3}\\d{1,3}，对其他内容优先使用非贪婪匹配 .*?。\n"
        "5. 格式要求：只输出正则表达式原文，不要 Markdown 代码块，不要文字解释，不要前缀说明。"
    )
    user_prompt = (
        f"【日志样例】:\n{sample_log}\n\n"
        f"【目标字段上下文】: {field_name}\n"
        f"【预期提取的值】: {expected_output}\n\n"
        "请生成正则表达式："
    )
    try:
        content = chat_completion(
            [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            settings,
            temperature=0,
            timeout=60,
        )
        return _clean_regex(content)
    except Exception as exc:
        if isinstance(exc, HTTPException):
            raise exc
        raise HTTPException(status_code=500, detail=f"AI 服务调用失败: {exc}") from exc


def _clean_regex(text: str) -> str:
    text = (text or "").strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if len(lines) > 2:
            text = "\n".join(lines[1:-1])
        else:
            text = text.strip("`").strip()
    # 移除 LLM 偶尔带出的说明前缀
    text = re.sub(r"^(Regex:|正则表达式:|Pattern:)\s*", "", text, flags=re.I)
    return text.strip()


def _validate_expected(sample_log: str, regex: str, expected: str) -> str:
    try:
        # 使用 re.S 确保 . 匹配换行
        pattern = re.compile(regex, re.S)
        m = pattern.search(sample_log)
        if m:
            val = m.group(1) if m.groups() else m.group(0)
            if val.strip() == expected.strip():
                return regex
    except re.error:
        pass
    return ""

