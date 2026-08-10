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
    异步流式请求大模型，生成 Token 序列。支持多种提供商适配。
    """
    provider = settings.get("provider", "openai-compatible")
    model = settings.get("model", "")
    base_url = (settings.get("base_url") or "").rstrip("/")
    api_key = settings.get("api_key") or ""
    temp = settings.get("temperature", 0.3) if temperature is None else temperature

    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    
    # 针对特定厂商的 Header 调整
    if provider == "zhipu":
        # 智谱 AI 如果使用标准 OpenAI 协议通常也支持，但这里预留特殊处理
        pass
    elif provider == "deepseek":
        # DeepSeek 官方地址默认
        if not base_url: base_url = "https://api.deepseek.com"
    elif provider == "siliconflow":
        if not base_url: base_url = "https://api.siliconflow.cn/v1"

    if provider == "ollama":
        if base_url.endswith("/v1"):
            base_url = base_url[:-3].rstrip("/")
        url = f"{base_url or 'http://localhost:11434'}/api/generate"
        prompt = "\n\n".join(f"{item.get('role', 'user')}:\n{item.get('content', '')}" for item in messages)
        payload = {"model": model or "llama3", "prompt": prompt, "stream": True}
        
        async with httpx.AsyncClient(timeout=timeout) as client:
            try:
                async with client.stream("POST", url, json=payload) as resp:
                    if resp.status_code != 200:
                        detail = await resp.aread()
                        raise HTTPException(status_code=resp.status_code, detail=f"Ollama 错误: {detail.decode('utf-8', 'ignore')}")
                    async for line in resp.aiter_lines():
                        if not line: continue
                        try:
                            chunk = json.loads(line)
                            content = chunk.get("response")
                            if content: # Skip None or empty string
                                yield content
                            if chunk.get("done"): break
                        except Exception: continue
            except httpx.ConnectError:
                raise HTTPException(status_code=503, detail="无法连接到 Ollama 服务，请检查地址是否正确且服务已启动")
    else:
        # OpenAI Compatible
        url = f"{base_url or 'https://api.openai.com/v1'}/chat/completions"
        payload = {"model": model, "messages": messages, "temperature": temp, "stream": True}
        
        async with httpx.AsyncClient(timeout=timeout) as client:
            try:
                async with client.stream("POST", url, headers=headers, json=payload) as resp:
                    if resp.status_code != 200:
                        detail = await resp.aread()
                        raise HTTPException(status_code=resp.status_code, detail=f"AI 服务错误 ({resp.status_code}): {detail.decode('utf-8', 'ignore')}")
                    async for line in resp.aiter_lines():
                        if line.startswith("data: "):
                            data_str = line[6:].strip()
                            if data_str == "[DONE]": break
                            try:
                                chunk = json.loads(data_str)
                                delta = chunk.get("choices", [{}])[0].get("delta", {})
                                content = delta.get("content")
                                if content: # Skip None or empty string
                                    yield content
                            except Exception: continue
            except httpx.ConnectError:
                raise HTTPException(status_code=503, detail=f"无法连接到 AI 服务商 ({provider})，请检查网络或 Base URL")


def chat_completion(
    messages: list[dict[str, str]],
    settings: dict[str, Any],
    *,
    temperature: float | None = None,
    timeout: int = 120,
) -> str:
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
                if resp.status_code != 200:
                    raise HTTPException(status_code=resp.status_code, detail=f"Ollama 错误: {resp.text}")
                return resp.json().get("response", "")
        except httpx.ConnectError:
            raise HTTPException(status_code=503, detail="无法连接到 Ollama 服务")
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"AI 服务调用失败 (Ollama): {exc}")

    url = f"{base_url or 'https://api.openai.com/v1'}/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(url, headers=headers, json={"model": model, "messages": messages, "temperature": temp})
            if resp.status_code != 200:
                raise HTTPException(status_code=resp.status_code, detail=f"AI 服务错误: {resp.text}")
            data = resp.json()
            choices = data.get("choices") or []
            return choices[0].get("message", {}).get("content", "") if choices else ""
    except httpx.ConnectError:
        raise HTTPException(status_code=503, detail=f"无法连接到 AI 服务 ({provider})")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"AI 服务调用失败: {exc}")


def fetch_models(settings: dict[str, Any], timeout: int = 15) -> list[dict[str, Any]]:
    """
    动态获取模型列表。适配 OpenAI 兼容接口和 Ollama。
    返回: [{"id": "model_id", "owned_by": "vendor"}, ...]
    """
    provider = settings.get("provider", "openai-compatible")
    base_url = (settings.get("base_url") or "").strip().rstrip("/")
    api_key = settings.get("api_key") or ""

    if not base_url:
        return []

    last_error = ""
    
    if provider == "ollama":
        # 兼容性处理：如果填了 /v1 后缀，由于获取标签接口在根路径，需要剥离
        temp_url = base_url
        if temp_url.endswith("/v1"):
            temp_url = temp_url[:-3].rstrip("/")
        url = f"{temp_url or 'http://localhost:11434'}/api/tags"
        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    return sorted(
                        [{"id": m["name"], "owned_by": "Ollama"} for m in data.get("models", [])],
                        key=lambda x: x["id"]
                    )
                else:
                    last_error = f"Ollama 返回错误 (HTTP {resp.status_code}): {resp.text[:200]}"
        except Exception as e:
            last_error = f"连接 Ollama 失败: {str(e)}"
            if "ConnectError" in last_error or "111" in last_error:
                last_error += "。请确保 Ollama 已启动且环境变量 OLLAMA_HOST=0.0.0.0 已设置（允许跨接口访问）。"
    else:
        # OpenAI Compatible
        # 构造候选 URL 列表 (参考 cc-switch-main)
        candidates = []
        
        # 如果用户填的是完整的聊天接口地址，尝试自动修正
        if "/chat/completions" in base_url:
            candidates.append(base_url.replace("/chat/completions", "/models"))
        
        # 标准候选
        if base_url.endswith("/v1"):
            candidates.append(f"{base_url}/models")
        else:
            candidates.append(f"{base_url}/v1/models")
            candidates.append(f"{base_url}/models")

        # 处理特殊的“兼容路径”后缀
        known_compat_suffixes = [
            "/api/claudecode", "/api/anthropic", "/apps/anthropic", 
            "/api/coding", "/claudecode", "/anthropic", "/step_plan", "/coding", "/claude"
        ]
        for suffix in known_compat_suffixes:
            if base_url.endswith(suffix):
                root = base_url[: -len(suffix)].rstrip("/")
                if root:
                    candidates.append(f"{root}/v1/models")
                    candidates.append(f"{root}/models")
                break

        # 去重并保持顺序
        seen = set()
        unique_candidates = []
        for c in candidates:
            if c not in seen:
                unique_candidates.append(c)
                seen.add(c)

        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        
        for url in unique_candidates:
            try:
                with httpx.Client(timeout=timeout) as client:
                    resp = client.get(url, headers=headers)
                    if resp.status_code == 200:
                        data = resp.json()
                        items = data.get("data") if isinstance(data, dict) else data
                        if isinstance(items, list):
                            models = []
                            for item in items:
                                if isinstance(item, dict) and "id" in item:
                                    models.append({
                                        "id": item["id"],
                                        "owned_by": item.get("owned_by") or "Other"
                                    })
                                elif isinstance(item, str):
                                    models.append({"id": item, "owned_by": "Other"})
                            return sorted(models, key=lambda x: x["id"])
                    else:
                        last_error = f"HTTP {resp.status_code}: {resp.text[:200]}"
            except Exception as e:
                last_error = str(e)
                continue
            
    if last_error:
        print(f"[AI Gateway] Fetch models failed for {base_url}. Last error: {last_error}")
    return []


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

