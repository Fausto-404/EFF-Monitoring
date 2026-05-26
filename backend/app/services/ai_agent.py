from __future__ import annotations

import json
import re
from typing import Any, AsyncGenerator, Sequence, TypedDict, Annotated, Literal
import asyncio
import operator
from datetime import datetime

from sqlalchemy.orm import Session
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage, SystemMessage

from app.models.entities import User, AiMessage, AiConversation
from app.services.ai_gateway import chat_completion, async_chat_stream, parse_json_object
from app.models.bootstrap import get_effective_setting
from app.services.ai_service import get_prompt
from app.services.ai_tools import execute_tool, get_tool_schemas


# --- 实体识别正则 (Entity Normalizer) ---
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_RE = re.compile(r"\b[a-f0-9]{16,64}\b", re.I)
DATE_RE = re.compile(r"(?<!\d)(20\d{2}-\d{2}-\d{2})(?!\d)")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

class AgentState(TypedDict):
    question: str
    messages: Sequence[BaseMessage]
    entities: dict[str, Any]
    understanding: dict[str, Any]
    plan: dict[str, Any]
    evidences: list[dict[str, Any]]
    final_answer: str
    trace: list[str]
    iteration: int
    error_context: str
    status: Literal["continue", "end"]


# --- 1. Entity Normalizer (线索抽取) ---
def normalize_entities(text: str) -> dict[str, Any]:
    return {
        "ips": sorted(list(set(IP_RE.findall(text)))),
        "hashes": sorted(list(set(HASH_RE.findall(text)))),
        "dates": sorted(list(set(DATE_RE.findall(text)))),
        "cves": sorted(list(set(CVE_RE.findall(text))))
    }


# --- 2. Task Understanding (意图理解) ---
async def understand_task(db: Session, user: User, question: str, entities: dict[str, Any], ai_settings: dict[str, Any]) -> dict[str, Any]:
    prompt = (
        "你是安全运营专家。你的任务是分析用户的自然语言提问，并将其转化为结构化的任务意图。\n"
        "### 核心准则：\n"
        "1. **意图对齐**：判断用户是想查告警、查资产、做统计、分析误报还是查审计。常用意图：alert.stats, alert.search, asset.lookup, ops.summary, experience.search。\n"
        "2. **关键槽位检查**：如果问题涉及特定对象（如“这个告警”、“它”），需检查实体（entities）中是否有对应的 Hash 或 IP。如果用户明确提到要查某项信息但缺少关键 ID，必须标记为需要用户补充。\n"
        "3. **边界判定**：如果问题超出安全运营范畴，或涉及写操作（如“删除用户”、“修改配置”），请在 user_question 中委婉拒绝，并说明你目前仅拥有只读查询权限。\n"
        "### 输出 JSON 格式：\n"
        "{\n"
        "  \"intent\": \"意图编码\",\n"
        "  \"user_goal\": \"用户核心诉求总结\",\n"
        "  \"required_resources\": [\"需要调用的数据分类\"],\n"
        "  \"missing_slots\": [\"缺失的关键参数\"],\n"
        "  \"need_user_input\": true/false,\n"
        "  \"user_question\": \"如果需要补充信息，请在此给出回复文案\"\n"
        "}"
    )
    try:
        content = await asyncio.to_thread(chat_completion, [
            {"role": "system", "content": prompt},
            {"role": "user", "content": f"问题：{question}\n已提取实体：{json.dumps(entities, ensure_ascii=False)}"}
        ], ai_settings, temperature=0)
        return parse_json_object(content) or {}
    except Exception:
        return {"intent": "unknown", "need_user_input": False}


# --- 3. AI Planner (路径规划) ---
async def generate_plan(db: Session, user: User, state: AgentState, tool_schemas: list[dict[str, Any]], ai_settings: dict[str, Any]) -> dict[str, Any]:
    prompt = (
        "你是安全运营查询规划专家。你的任务是规划最优的工具调用链路来获取回答问题所需的全部证据。\n"
        "### 规划原则：\n"
        "1. **先查资产，再查上下文**：如果问题涉及 IP，通常需要先调用 asset.get_by_ip 获取资产基本信息，再根据需要调用 alert.search 查询其最近告警。\n"
        "2. **统计优先**：如果用户问“有多少”、“趋势”、“分布”，应优先调用 stats/summary 类工具而非 search 列表类工具。\n"
        "3. **去重节约**：不要重复规划参数完全相同的工具调用。优先合并相似查询。\n"
        "4. **安全红线**：严禁尝试推测或假设数据，严禁请求敏感字段。\n"
        "### 输出 JSON 格式：\n"
        "{\"objective\":\"规划目标描述\", \"tool_calls\":[{\"tool\":\"工具名\", \"params\":{}, \"reason\":\"为什么要调用这个工具\"}]}"
    )
    ctx = {
        "question": state["question"],
        "understanding": state["understanding"],
        "entities": state["entities"],
        "available_tools": tool_schemas,
        "history_context": state["error_context"]
    }
    try:
        content = await asyncio.to_thread(chat_completion, [
            {"role": "system", "content": prompt},
            {"role": "user", "content": json.dumps(ctx, ensure_ascii=False)}
        ], ai_settings, temperature=0)
        return parse_json_object(content) or {"tool_calls": []}
    except Exception:
        return {"tool_calls": []}


# --- 4. Plan Validator (确定性校准) ---
def validate_plan(plan: dict[str, Any], tool_schemas: list[dict[str, Any]]) -> dict[str, Any]:
    valid_names = {t["tool"] for t in tool_schemas}
    validated_calls = []
    for call in plan.get("tool_calls", []):
        if call.get("tool") in valid_names:
            # 这里可以增加更复杂的参数校验逻辑
            validated_calls.append(call)
    plan["tool_calls"] = validated_calls
    return plan


# --- 5. Tool Executor (证据提取) ---
async def execute_plan(db: Session, user: User, plan: dict[str, Any]) -> list[dict[str, Any]]:
    evidences = []
    for call in plan.get("tool_calls", [])[:8]:
        # 调用原始 execute_tool 并将其封装为标准证据包
        result = await asyncio.to_thread(execute_tool, db, user, call["tool"], call.get("params", {}))
        evidences.append(result)
    return evidences


async def stream_chat_agent(db: Session, user: User, conversation_id: int, question: str) -> AsyncGenerator[str, None]:
    """
    意图驱动的 Agent 全量重构版本。
    """
    yield json.dumps({"event": "trace", "data": "Agent 启动：正在加载上下文..."})
    
    # 实体识别
    entities = normalize_entities(question)
    
    # 状态初始化
    state: AgentState = {
        "question": question,
        "messages": [],
        "entities": entities,
        "understanding": {},
        "plan": {},
        "evidences": [],
        "final_answer": "",
        "trace": [],
        "iteration": 0,
        "error_context": "",
        "status": "continue"
    }

    ai_settings = get_effective_setting(db, user.workspace_id, user.id, "ai")
    if not ai_settings:
        yield json.dumps({"event": "final_answer", "data": "AI 网关未配置，请先在系统设置中配置。"})
        return

    # 步骤 1：Task Understanding
    yield json.dumps({"event": "trace", "data": "AI 正在深度解析您的问题意图..."})
    state["understanding"] = await understand_task(db, user, question, entities, ai_settings)
    
    if state["understanding"].get("need_user_input"):
        yield json.dumps({"event": "final_answer", "data": state["understanding"].get("user_question") or "需要更多信息才能回答。"})
        return

    tool_schemas = get_tool_schemas(user)
    
    while state["iteration"] < 2:
        state["iteration"] += 1
        
        # 步骤 2：Planning
        yield json.dumps({"event": "trace", "data": f"第 {state['iteration']} 轮规划：正在调度查询工具..."})
        plan = await generate_plan(db, user, state, tool_schemas, ai_settings)
        state["plan"] = validate_plan(plan, tool_schemas)
        
        if not state["plan"].get("tool_calls"):
            yield json.dumps({"event": "trace", "data": "未规划出有效工具，尝试根据已有信息回答..."})
        else:
            # 步骤 3：Executing
            for call in state["plan"]["tool_calls"]:
                yield json.dumps({"event": "trace", "data": f"正在执行：{call['tool']} ({call.get('reason','')})"})
            
            new_evidences = await execute_plan(db, user, state["plan"])
            state["evidences"].extend(new_evidences)
        
        # 步骤 4：Answering (内部生成，暂不流式推向用户消息框)
        yield json.dumps({"event": "trace", "data": "正在基于获取的证据包生成回答草稿..."})
        
        prompt_config = get_prompt(db, user.workspace_id, "chat")
        llm_messages = [
            {"role": "system", "content": f"{prompt_config['system']}\n必须只基于提供的 Evidence Pack 回答。"},
            {"role": "user", "content": f"问题：{question}\n证据包：{json.dumps(state['evidences'], ensure_ascii=False)}"}
        ]
        
        # 内部静默生成完整回答
        full_answer = await asyncio.to_thread(chat_completion, llm_messages, ai_settings, temperature=0.3)
        
        # 步骤 5：Verifying (事实一致性校验与自动反思)
        yield json.dumps({"event": "trace", "data": "正在进行回答质量反思与事实核验..."})
        check_prompt = (
            "你是安全对话核验专家（Reflector）。你的职责是严审 AI 的回答草稿，确保其逻辑严密、事实准确。\n"
            "### 核验准则：\n"
            "1. **证据一致性**：检查回答中的每一个数字（如告警数）、每一个结论（如负责人是谁）是否都能在【工具结果】中找到直接证据。严禁脑补或猜测。\n"
            "2. **完整性检查**：如果工具结果中包含了有价值的信息（如资产标签、情报风险），但回答中没有体现，必须指出并要求补充。\n"
            "3. **能力诚实性**：如果工具结果为空，回答必须如实告知。如果 AI 声称“没有权限”或“无法查询”，但实际上对应工具已经返回了数据，这属于严重错误。\n"
            "### 输出规则：\n"
            "- 如果回答完美，请仅回复 'PASS'。\n"
            "- 否则，请列出具体的错误点和下一步补查/修正建议。"
        )

        try:
            check_result = await asyncio.to_thread(chat_completion, [
                {"role": "system", "content": check_prompt},
                {"role": "user", "content": f"用户问题：{question}\n工具结果：{json.dumps(state['evidences'], ensure_ascii=False)}\n当前草稿：{full_answer}"}
            ], ai_settings, temperature=0)
            
            if "PASS" in check_result.upper() or state["iteration"] >= 2:
                yield json.dumps({"event": "trace", "data": f"反思完成：{'达到迭代上限' if state['iteration'] >= 2 else '回答通过验证'}"})
                state["final_answer"] = full_answer
                # 最终确认通过，执行 Token 级流式输出
                yield json.dumps({"event": "trace", "data": "回答已通过核验，正在输出..."})
                async for token in async_chat_stream(llm_messages, ai_settings, temperature=0.3):
                    yield json.dumps({"event": "token", "data": token})
                break
            else:
                state["error_context"] = check_result
                yield json.dumps({"event": "trace", "data": f"反思发现问题，准备修正：{check_result}"})
                # 继续 while 循环进行下一轮，不给用户发 Token
        except Exception as e:
            yield json.dumps({"event": "trace", "data": f"反思阶段异常: {str(e)}"})
            state["final_answer"] = full_answer
            # 异常时直接输出当前的
            async for token in async_chat_stream(llm_messages, ai_settings, temperature=0.3):
                yield json.dumps({"event": "token", "data": token})
            break

    yield json.dumps({"event": "evidences", "data": state["evidences"]})
    yield json.dumps({"event": "final_answer", "data": state["final_answer"]})
    yield json.dumps({"event": "completion", "data": "done"})
