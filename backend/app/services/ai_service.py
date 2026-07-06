from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

from fastapi import HTTPException
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.models.bootstrap import get_effective_setting
from app.models.entities import (
    AiExperience,
    AiPrompt,
    Alert,
    Asset,
    AuditLog,
    Device,
    Message,
    ParseRule,
    Project,
    TaskRecord,
    Template,
    User,
)
from app.services.ai_gateway import chat_completion, parse_json_object
from app.services.ai_tools import execute_tool
from app.services.workflow_constants import GROUP_LABELS, ROLE_LABELS, STATUS_LABELS


TERMINAL_STATUSES = {"false_positive", "ignored", "disposed"}


DEFAULT_OUTPUT_SCHEMA = {
    "meta": {"id": "KNOW-STE-0000", "title": "", "tags": []},
    "index": {
        "rule_id": [],
        "cve": [],
        "event_type_keywords": [],
        "request_paths": [],
        "payload_keywords": [],
        "response_codes": [],
        "asset_tags": [],
        "asset_area": "",
        "attack_result": "",
        "terminal_status": "",
    },
    "ste": {"S": "", "T": {"steps": [], "conclusion": ""}, "E": {"alarm": {}, "proof": {}}},
    "action": {"asset": "", "soar": ""},
    "quality": {"confidence": "medium", "risk": "", "review_notes": ""},
}


def default_prompt(prompt_key: str) -> dict[str, str]:
    prompts = {
        "evidence_extract": {
            "system": (
                "你是安全日志证据提取器。只允许从原始日志中抽取明确出现的信息，禁止推断、补全、猜测。"
                "没有出现就返回空值。每个字段必须包含 value、evidence、confidence。只输出 JSON。"
            ),
            "user": "已知字段：{known_fields}\n需要补充字段：{missing_fields}\n原始日志片段：\n{raw_text_excerpt}",
        },
        "ste_extract": {
            "system": (
                "你是资深安全运营复盘专家。根据证据包提取 STE 经验，必须输出合法 JSON。"
                "S 是策略，T 是可复用战术步骤和结论，E 是告警样例与证据，action 是资产或自动化建议。"
            ),
            "user": "证据包：\n{evidence_pack}\n\n请按这个 JSON Schema 输出：\n{output_schema}",
        },
        "alert_analysis": {
            "system": "你是资深安全运营分析师，需要基于告警事实、资产、情报和历史经验进行研判。",
            "user": (
                "当前告警证据包：\n{evidence_pack}\n\n"
                "可参考历史经验：\n{experience_injection}\n\n"
                "输出研判结论、风险等级、证据、处置建议、不确定性，并列出引用的经验编号。"
            ),
        },
        "template_generate": {
            "system": (
                "你是安全运营模板生成专家。你的核心任务是将用户样例中的真实值（如 IP、时间、Hash）精准替换为平台变量（如 {{源IP}}, {{当前时间}}）。\n"
                "### 核心准则：\n"
                "1. **格式零变动**：禁止添加、删除、重排或修改样例中的任何文本、标点或排版。样例如有缩进或换行，必须严格保留。\n"
                "2. **严禁幻觉内容**：如果用户样例只有一行（如：封禁源IP：1.1.1.1），输出也必须只有一行（如：封禁源IP：{{源IP}}）。严禁生成多余的总结、标题或表格。\n"
                "3. **变量精准匹配**：只能使用提供的候选变量，不要臆造变量名。\n"
                "4. **只输出合法 JSON**：返回结构包含 name, content, variables, warnings。"
            ),
            "user": (
                "模板类型：{template_type}\n"
                "用户意图：{intent}\n"
                "候选变量（仅限此处选择）：\n{variables}\n\n"
                "用户样例原文：\n{sample_text}\n\n"
                "请严格基于原文生成模板 JSON："
            ),
        },
        "chat": {
            "system": "你是安全运营平台助手。你可以根据平台查询工具返回的数据回答问题，不能声称已执行写操作。",
            "user": "用户问题：{question}\n工具结果：\n{tool_results}",
        },
    }
    return prompts.get(prompt_key, {"system": "", "user": "{input}"})


def get_prompt(db: Session, workspace_id: int, prompt_key: str) -> dict[str, Any]:
    row = (
        db.query(AiPrompt)
        .filter_by(workspace_id=workspace_id, prompt_key=prompt_key, enabled=True, is_default=True)
        .order_by(AiPrompt.updated_at.desc())
        .first()
    )
    if row:
        return {
            "system": row.system_prompt,
            "user": row.user_prompt,
            "output_schema": row.output_schema or {},
        }
    base = default_prompt(prompt_key)
    return {"system": base["system"], "user": base["user"], "output_schema": DEFAULT_OUTPUT_SCHEMA}


def field(value: Any, source: str, confidence: str = "high", evidence: str = "") -> dict[str, Any]:
    return {"value": value if value is not None else "", "source": source, "confidence": confidence, "evidence": evidence}


def _first(data: dict[str, Any], keys: list[str]) -> Any:
    for key in keys:
        val = data.get(key)
        if val not in (None, "", [], {}):
            return val
    return ""


def _unique(items: list[Any]) -> list[Any]:
    result = []
    seen = set()
    for item in items:
        text = str(item).strip()
        if text and text not in seen:
            result.append(item)
            seen.add(text)
    return result


def _truncate(text: Any, limit: int = 1200) -> str:
    value = str(text or "")
    return value if len(value) <= limit else value[:limit] + "...[已截断]"


def _extract_builtin(raw_text: str) -> dict[str, dict[str, Any]]:
    text = raw_text or ""
    cves = _unique(re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.I))
    rule_match = re.search(r"(?:规则\s*ID|Rule\s*ID|signature\s*id)\s*[:：]?\s*([A-Za-z0-9_-]+)", text, flags=re.I)
    response_codes = []
    for pattern in (r"响应码\s*[:：]\s*(\d{3})", r"HTTP/\d(?:\.\d)?\s+(\d{3})", r"\bstatus\s*[:=]\s*(\d{3})"):
        response_codes.extend(re.findall(pattern, text, flags=re.I))
    request_paths = []
    for method, path in re.findall(r"\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s]+)", text, flags=re.I):
        if path.startswith("/"):
            request_paths.append(path.split("?")[0])
    keyword_pool = [
        "XMLDecoder",
        "ProcessBuilder",
        "/bin/sh",
        "cmd.exe",
        "powershell",
        "wls-wsat",
        "CoordinatorPortType",
        "JNDI",
        "ldap://",
        "bash -c",
        "wget",
        "curl",
    ]
    payload_keywords = [item for item in keyword_pool if item.lower() in text.lower()]
    return {
        "cve": field(cves, "builtin_regex", "high"),
        "rule_id": field(rule_match.group(1) if rule_match else "", "builtin_regex", "medium"),
        "response_codes": field(_unique(response_codes), "builtin_regex", "medium"),
        "request_paths": field(_unique(request_paths), "builtin_regex", "high"),
        "payload_keywords": field(_unique(payload_keywords), "builtin_regex", "high"),
    }


def _field_value(pack: dict[str, Any], key: str, default: Any = "") -> Any:
    val = pack.get(key)
    if isinstance(val, dict) and "value" in val:
        return val.get("value") if val.get("value") not in (None, "") else default
    return val if val not in (None, "") else default


def _needs_ai_evidence(pack: dict[str, Any]) -> list[str]:
    missing = []
    for key in ("rule_id", "request_paths", "response_codes"):
        val = _field_value(pack, key, [] if key.endswith("s") else "")
        if not val or val == "--":
            missing.append(key)
    keywords = _field_value(pack, "payload_keywords", [])
    if not isinstance(keywords, list) or len(keywords) < 2:
        missing.append("payload_keywords")
    event_type = str(_field_value(pack, "event_type", ""))
    if event_type in {"", "入侵防护日志", "威胁类", "告警分析"}:
        missing.append("event_type")
    return _unique(missing)


def _merge_ai_evidence(pack: dict[str, Any], ai_data: dict[str, Any]) -> None:
    for key, val in ai_data.items():
        if not isinstance(val, dict):
            continue
        current = _field_value(pack, key, [] if key.endswith("s") else "")
        new_val = val.get("value")
        if current not in (None, "", [], "--"):
            continue
        pack[key] = {
            "value": new_val or ([] if key.endswith("s") else ""),
            "source": "ai_extract",
            "confidence": val.get("confidence") or "medium",
            "evidence": val.get("evidence") or "",
        }


def _history_summary(db: Session, alert: Alert) -> list[dict[str, Any]]:
    rows = (
        db.query(AuditLog)
        .filter(AuditLog.workspace_id == alert.workspace_id, AuditLog.target_type == "alert", AuditLog.target_id == str(alert.id))
        .order_by(AuditLog.created_at.asc())
        .limit(30)
        .all()
    )
    result = []
    for row in rows:
        result.append(
            {
                "time": row.created_at.isoformat(sep=" ", timespec="seconds") if row.created_at else "",
                "action": row.action,
                "detail": row.detail or {},
            }
        )
    return result


def build_alert_evidence_pack(
    db: Session,
    user: User,
    alert: Alert,
    *,
    use_ai: bool = False,
) -> dict[str, Any]:
    parsed = alert.parsed_fields or {}
    raw_text = alert.raw_text or ""
    builtin = _extract_builtin(raw_text)
    src_asset = alert.src_asset_context or parsed.get("src_asset_context") or {}
    dst_asset = alert.dst_asset_context or parsed.get("dst_asset_context") or {}
    event_type = alert.event_type or _first(parsed, ["event_type", "事件类型", "日志消息内容"])
    pack = {
        "alert_hash": field(alert.alert_hash, "alert", "high"),
        "event_type": field(event_type, "parsed_fields" if event_type else "alert", "high"),
        "rule_id": field(_first(parsed, ["rule_id", "规则ID", "规则 ID"]) or _field_value(builtin, "rule_id"), "parsed_fields" if _first(parsed, ["rule_id", "规则ID", "规则 ID"]) else "builtin_regex", "high"),
        "cve": builtin["cve"],
        "attack_result": field(_first(parsed, ["attack_result", "攻击结果", "日志附带的结果"]), "parsed_fields", "high"),
        "severity": field(alert.severity or _first(parsed, ["severity", "威胁等级"]), "alert", "high"),
        "status": field(alert.status, "alert", "high"),
        "status_label": field(STATUS_LABELS.get(alert.status, alert.status), "alert", "high"),
        "current_group": field(GROUP_LABELS.get(alert.current_group, alert.current_group), "alert", "high"),
        "closure_action": field(alert.closure_action, "alert", "high"),
        "false_positive_reason": field(alert.false_positive_reason, "alert", "high"),
        "src_ip": field(alert.source_ip or parsed.get("src_ip", ""), "parsed_fields", "high"),
        "dst_ip": field(alert.destination_ip or parsed.get("dst_ip", ""), "parsed_fields", "high"),
        "request": field(_truncate(_first(parsed, ["request", "请求内容"]), 1200), "parsed_fields", "high"),
        "response": field(_truncate(_first(parsed, ["response", "响应内容"]), 1200), "parsed_fields", "high"),
        "payload": field(_truncate(_first(parsed, ["payload", "载荷", "攻击载荷"]), 1200), "parsed_fields", "high"),
        "response_codes": builtin["response_codes"],
        "request_paths": builtin["request_paths"],
        "payload_keywords": builtin["payload_keywords"],
        "src_asset": field(src_asset, "asset_context", "high"),
        "dst_asset": field(dst_asset, "asset_context", "high"),
        "ti_summary": field(_truncate(json.dumps(alert.ti_result or {}, ensure_ascii=False), 1200), "ti_result", "medium"),
        "previous_ai_result": field(_truncate(alert.ai_result or "", 1200), "ai_result", "medium"),
        "workflow_history": field(_history_summary(db, alert), "audit_logs", "high"),
    }
    if use_ai:
        missing = _needs_ai_evidence(pack)
        ai_settings = get_effective_setting(db, user.workspace_id, user.id, "ai")
        if missing and ai_settings:
            prompt = get_prompt(db, user.workspace_id, "evidence_extract")
            excerpt = _truncate(raw_text, 5000)
            try:
                content = chat_completion(
                    [
                        {"role": "system", "content": prompt["system"]},
                        {
                            "role": "user",
                            "content": prompt["user"].format(
                                known_fields=json.dumps({k: _field_value(pack, k) for k in pack}, ensure_ascii=False),
                                missing_fields=json.dumps(missing, ensure_ascii=False),
                                raw_text_excerpt=excerpt,
                            ),
                        },
                    ],
                    ai_settings,
                    temperature=0,
                    timeout=60,
                )
                _merge_ai_evidence(pack, parse_json_object(content))
            except HTTPException:
                pass
    return pack


def compact_evidence_for_prompt(pack: dict[str, Any]) -> dict[str, Any]:
    result = {}
    for key, val in pack.items():
        if isinstance(val, dict) and "value" in val:
            result[key] = {
                "value": val.get("value"),
                "source": val.get("source"),
                "confidence": val.get("confidence"),
            }
        else:
            result[key] = val
    return result


def generate_knowledge_id(db: Session, workspace_id: int) -> str:
    count = db.query(AiExperience).filter_by(workspace_id=workspace_id).count() + 1
    return f"KNOW-STE-{count:04d}"


def fallback_ste(db: Session, alert: Alert, pack: dict[str, Any]) -> dict[str, Any]:
    knowledge_id = generate_knowledge_id(db, alert.workspace_id)
    event = _field_value(pack, "event_type", alert.event_type)
    cves = _field_value(pack, "cve", [])
    dst_asset = _field_value(pack, "dst_asset", {}) or {}
    return {
        "meta": {"id": knowledge_id, "title": f"{event} 处置经验", "tags": _unique([*(cves or []), event, _field_value(pack, "status_label", "")])},
        "index": {
            "rule_id": _unique([_field_value(pack, "rule_id", "")]),
            "cve": cves or [],
            "event_type_keywords": _unique(re.findall(r"[A-Za-z0-9_.-]+|[\u4e00-\u9fa5]{2,}", str(event))),
            "request_paths": _field_value(pack, "request_paths", []),
            "payload_keywords": _field_value(pack, "payload_keywords", []),
            "response_codes": _field_value(pack, "response_codes", []),
            "asset_tags": dst_asset.get("tags", []) if isinstance(dst_asset, dict) else [],
            "asset_area": dst_asset.get("area", "") if isinstance(dst_asset, dict) else "",
            "attack_result": _field_value(pack, "attack_result", ""),
            "terminal_status": alert.status,
        },
        "ste": {
            "S": "基于告警证据、资产上下文和闭环结果沉淀可复用研判策略。",
            "T": {
                "steps": ["核验证据字段和资产指纹", "结合处置闭环结果确认同类特征", "复用该经验时仍需检查当前响应和资产状态"],
                "conclusion": alert.false_positive_reason or "该经验来自已闭环告警，可作为同类事件研判参考。",
            },
            "E": {"alarm": {"event": event, "alert_hash": alert.alert_hash}, "proof": {"request_paths": _field_value(pack, "request_paths", []), "payload_keywords": _field_value(pack, "payload_keywords", [])}},
        },
        "action": {"asset": "复核资产标签与暴露服务是否仍准确。", "soar": ""},
        "quality": {"confidence": "medium", "risk": "AI 未配置或输出不可解析时生成的基础经验，需要人工确认。", "review_notes": ""},
    }


def extract_ste_experience(db: Session, user: User, alert: Alert) -> dict[str, Any]:
    if alert.status not in TERMINAL_STATUSES:
        raise HTTPException(status_code=400, detail="只有已闭环告警可以提取 STE 经验")
    pack = build_alert_evidence_pack(db, user, alert, use_ai=True)
    ai_settings = get_effective_setting(db, user.workspace_id, user.id, "ai")
    if not ai_settings:
        raise HTTPException(status_code=400, detail="请先配置 AI 网关，STE 经验提取需要由 AI 总结生成")
    prompt = get_prompt(db, user.workspace_id, "ste_extract")
    output_schema = prompt.get("output_schema") or DEFAULT_OUTPUT_SCHEMA
    content = chat_completion(
        [
            {"role": "system", "content": prompt["system"]},
            {
                "role": "user",
                "content": prompt["user"].format(
                    evidence_pack=json.dumps(compact_evidence_for_prompt(pack), ensure_ascii=False),
                    output_schema=json.dumps(output_schema, ensure_ascii=False),
                ),
            },
        ],
        ai_settings,
        temperature=0.2,
        timeout=120,
    )
    data = parse_json_object(content)
    if not data:
        # 记录原始输出以便调试（如果环境允许）
        raise HTTPException(
            status_code=500, 
            detail="AI 提取经验失败：未能生成合法的 JSON 格式，请尝试重新提取或检查提示词设置"
        )
    data.setdefault("meta", {})
    if not data["meta"].get("id") or data["meta"].get("id") == "KNOW-STE-0000":
        data["meta"]["id"] = generate_knowledge_id(db, user.workspace_id)
    data["meta"].setdefault("title", alert.event_type or "未命名经验")
    data["meta"].setdefault("tags", [])
    data.setdefault("index", {})
    data.setdefault("ste", {})
    data.setdefault("action", {})
    data.setdefault("quality", {"confidence": "medium"})
    return data


def handle_auto_ste_task(db: Session, task: TaskRecord) -> dict[str, Any]:
    alert_id = int(task.target_id)
    alert = db.get(Alert, alert_id)
    if not alert:
        raise ValueError(f"Alert {alert_id} not found")
    
    user = db.get(User, task.actor_id)
    if not user:
        raise ValueError(f"Actor user {task.actor_id} not found")
        
    # 执行静默提取
    try:
        ste_data = extract_ste_experience(db, user, alert)
        # 保存为草稿
        exp = experience_from_ste(db, user, alert, ste_data, status="draft")
        return {"experience_id": exp.id, "knowledge_id": exp.knowledge_id}
    except Exception as e:
        raise e


def experience_from_ste(db: Session, user: User, alert: Alert, ste_data: dict[str, Any], status: str = "draft") -> AiExperience:
    meta = ste_data.get("meta") or {}
    knowledge_id = meta.get("id") or generate_knowledge_id(db, user.workspace_id)
    exists = db.query(AiExperience).filter_by(workspace_id=user.workspace_id, knowledge_id=knowledge_id).first()
    if exists:
        knowledge_id = generate_knowledge_id(db, user.workspace_id)
    row = AiExperience(
        workspace_id=user.workspace_id,
        knowledge_id=knowledge_id,
        source_alert_id=alert.id,
        alert_hash=alert.alert_hash,
        title=meta.get("title") or alert.event_type or "未命名经验",
        tags=meta.get("tags") or [],
        index_data=ste_data.get("index") or {},
        ste=ste_data.get("ste") or {},
        action=ste_data.get("action") or {},
        quality=ste_data.get("quality") or {},
        status=status,
        created_by_id=user.id,
        updated_by_id=user.id,
    )
    db.add(row)
    db.flush()
    return row


def _as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if value:
        return [str(value).strip()]
    return []


def _confidence_weight(pack: dict[str, Any], key: str) -> float:
    val = pack.get(key) or {}
    confidence = val.get("confidence") if isinstance(val, dict) else "high"
    return {"high": 1.0, "medium": 0.7, "low": 0.4}.get(confidence, 0.7)


def score_experience(pack: dict[str, Any], exp: AiExperience) -> int:
    idx = exp.index_data or {}
    score = 0.0
    rule_id = str(_field_value(pack, "rule_id", "") or "")
    if rule_id and rule_id in _as_list(idx.get("rule_id")):
        score += 40 * _confidence_weight(pack, "rule_id")
    pack_cves = set(_as_list(_field_value(pack, "cve", [])))
    if pack_cves.intersection(_as_list(idx.get("cve"))):
        score += 30 * _confidence_weight(pack, "cve")
    event_text = str(_field_value(pack, "event_type", "")).lower()
    if any(item.lower() in event_text for item in _as_list(idx.get("event_type_keywords"))):
        score += 20 * _confidence_weight(pack, "event_type")
    if str(_field_value(pack, "attack_result", "")) and str(_field_value(pack, "attack_result", "")) == str(idx.get("attack_result", "")):
        score += 10 * _confidence_weight(pack, "attack_result")
    dst_asset = _field_value(pack, "dst_asset", {}) or {}
    if isinstance(dst_asset, dict):
        tag_hits = set(_as_list(dst_asset.get("tags"))).intersection(_as_list(idx.get("asset_tags")))
        score += min(len(tag_hits) * 5, 15)
        if dst_asset.get("area") and dst_asset.get("area") == idx.get("asset_area"):
            score += 5
    if set(_as_list(_field_value(pack, "request_paths", []))).intersection(_as_list(idx.get("request_paths"))):
        score += 15 * _confidence_weight(pack, "request_paths")
    keyword_hits = set(_as_list(_field_value(pack, "payload_keywords", []))).intersection(_as_list(idx.get("payload_keywords")))
    score += min(len(keyword_hits) * 5, 20) * _confidence_weight(pack, "payload_keywords")
    if set(_as_list(_field_value(pack, "response_codes", []))).intersection(_as_list(idx.get("response_codes"))):
        score += 10 * _confidence_weight(pack, "response_codes")
    return int(score)


def search_relevant_experiences(db: Session, user: User, pack: dict[str, Any], limit: int = 3) -> list[tuple[AiExperience, int]]:
    rows = db.query(AiExperience).filter_by(workspace_id=user.workspace_id, status="published").all()
    scored = [(row, score_experience(pack, row)) for row in rows]
    return [(row, score) for row, score in sorted(scored, key=lambda item: item[1], reverse=True) if score >= 50][:limit]


def summarize_experience(exp: AiExperience, score: int) -> str:
    steps = ((exp.ste or {}).get("T") or {}).get("steps") or []
    conclusion = ((exp.ste or {}).get("T") or {}).get("conclusion") or ""
    action = exp.action or {}
    idx = exp.index_data or {}
    return (
        f"{exp.knowledge_id} / {exp.title}（匹配分 {score}）\n"
        f"适用条件：规则ID={','.join(_as_list(idx.get('rule_id')))}；CVE={','.join(_as_list(idx.get('cve')))}；"
        f"路径={','.join(_as_list(idx.get('request_paths')))}；关键词={','.join(_as_list(idx.get('payload_keywords'))[:5])}。\n"
        f"判断策略：{'；'.join(steps[:3]) or conclusion}\n"
        f"建议动作：{action.get('asset') or action.get('soar') or '参考该经验完成复核。'}"
    )


def build_experience_injection(matches: list[tuple[AiExperience, int]]) -> str:
    if not matches:
        return "未命中可引用的历史经验。"
    return "\n\n".join(f"{index}. {summarize_experience(exp, score)}" for index, (exp, score) in enumerate(matches, start=1))


def plan_alert_analysis(db: Session, user: User, pack: dict[str, Any], matches: list[tuple[AiExperience, int]]) -> dict[str, Any]:
    """Planner: decide what the analysis must verify before the model writes a conclusion."""
    plan = {
        "objective": "基于证据包和历史经验完成告警研判",
        "must_check": ["告警事实", "资产重要性", "请求/载荷证据", "响应结果", "历史经验适用性"],
        "experience_ids": [item.knowledge_id for item, _score in matches],
        "risk_controls": ["缺少响应码时必须说明不确定性", "不得把低置信 AI 提取字段当作确定事实", "引用经验时必须说明适用条件"],
    }
    ai_settings = get_effective_setting(db, user.workspace_id, user.id, "ai")
    if not ai_settings:
        return plan
    try:
        content = chat_completion(
            [
                {"role": "system", "content": "你是 AI 研判 Planner。只输出 JSON，规划需要核验的证据点、风险点和可引用经验，不做最终研判。"},
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "evidence_pack": compact_evidence_for_prompt(pack),
                            "matched_experiences": [{"id": exp.knowledge_id, "score": score, "title": exp.title} for exp, score in matches],
                        },
                        ensure_ascii=False,
                    ),
                },
            ],
            ai_settings,
            temperature=0,
            timeout=45,
        )
        parsed = parse_json_object(content)
        if parsed:
            plan.update(parsed)
    except Exception:
        pass
    return plan


def reflect_alert_analysis(db: Session, user: User, draft: str, pack: dict[str, Any], matches: list[tuple[AiExperience, int]], plan: dict[str, Any]) -> str:
    """Reflector: review whether the answer is grounded in evidence and experience references."""
    ai_settings = get_effective_setting(db, user.workspace_id, user.id, "ai")
    if not ai_settings:
        return draft
    try:
        content = chat_completion(
            [
                {
                    "role": "system",
                    "content": (
                        "你是 AI 研判 Reflector。检查草稿是否存在无证据断言、经验引用不当、忽略不确定性。"
                        "输出修订后的最终研判文本，必须保留证据依据和引用经验编号。"
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "plan": plan,
                            "evidence_pack": compact_evidence_for_prompt(pack),
                            "experience_ids": [exp.knowledge_id for exp, _score in matches],
                            "draft": draft,
                        },
                        ensure_ascii=False,
                    ),
                },
            ],
            ai_settings,
            temperature=0.1,
            timeout=60,
        )
        return content or draft
    except Exception:
        return draft


def analyze_alert_with_experience(db: Session, user: User, alert: Alert) -> tuple[str, list[str]]:
    pack = build_alert_evidence_pack(db, user, alert, use_ai=True)
    matches = search_relevant_experiences(db, user, pack)
    ai_settings = get_effective_setting(db, user.workspace_id, user.id, "ai")
    if not ai_settings:
        return "AI 网关未配置", []
    prompt = get_prompt(db, user.workspace_id, "alert_analysis")
    plan = plan_alert_analysis(db, user, pack, matches)
    runtime_evidences = [
        execute_tool(db, user, "alert.detail", {"alert_hash": alert.alert_hash}),
        execute_tool(db, user, "alert.timeline", {"alert_hash": alert.alert_hash}),
    ]
    if alert.source_ip:
        runtime_evidences.extend(
            [
                execute_tool(db, user, "asset.get_by_ip", {"ip": alert.source_ip}),
                execute_tool(db, user, "alert.similar_by_ip", {"ip": alert.source_ip}),
            ]
        )
    if alert.destination_ip:
        runtime_evidences.extend(
            [
                execute_tool(db, user, "asset.get_by_ip", {"ip": alert.destination_ip}),
                execute_tool(db, user, "alert.similar_by_ip", {"ip": alert.destination_ip}),
            ]
        )
    try:
        draft = chat_completion(
            [
                {
                    "role": "system",
                    "content": (
                        f"{prompt['system']}\n"
                        "必须基于 evidence_pack、tool_evidences 和历史经验回答；不能编造响应码、资产信息或处置结果。"
                        "输出结构：结论、关键证据、风险判断、处置建议、不确定性、引用经验。"
                    ),
                },
                {
                    "role": "user",
                    "content": prompt["user"].format(
                        evidence_pack=json.dumps(
                            {
                                "compact_pack": compact_evidence_for_prompt(pack),
                                "tool_evidences": runtime_evidences,
                            },
                            ensure_ascii=False,
                        ),
                        experience_injection=build_experience_injection(matches),
                    ),
                },
                {"role": "user", "content": f"Planner 研判计划：\n{json.dumps(plan, ensure_ascii=False)}"},
            ],
            ai_settings,
            temperature=0.2,
            timeout=120,
        )
        final = reflect_alert_analysis(db, user, draft, pack, matches, {**plan, "tool_evidences": runtime_evidences})
    except HTTPException as exc:
        summaries = "\n".join(f"- {item.get('summary')}" for item in runtime_evidences if item.get("summary"))
        final = f"AI 研判失败：{exc.detail}\n\n已完成平台证据查询：\n{summaries}"
    return final, [item.knowledge_id for item, _score in matches]


def available_template_variables(db: Session, user: User, device_id: int | None) -> list[str]:
    return [item["name"] for item in available_template_variable_catalog(db, user, device_id)]


def available_template_variable_catalog(db: Session, user: User, device_id: int | None) -> list[dict[str, Any]]:
    rules = db.query(ParseRule).filter(ParseRule.workspace_id == user.workspace_id, ParseRule.enabled.is_(True)).all()
    items = [
        {
            "name": r.name, 
            "field_key": r.field_key or "", 
            "field_label": r.field_label or "",
            "source": "parse_rule",
            "domain": "alert",
            "description": f"从日志中提取的字段：{r.name}",
            "available_for": ["message", "excel", "csv"]
        }
        for r in rules
        if not r.device_id or not device_id or r.device_id == device_id
    ]
    system_items = [
        {
            "name": name, 
            "field_key": key, 
            "field_label": label,
            "source": "system",
            "domain": domain,
            "description": desc,
            "available_for": ["message", "excel", "csv", "report"]
        }
        for name, key, label, domain, desc in [
            ("告警ID", "alert_code", "告警ID", "alert", "告警唯一自增ID"),
            ("告警Hash", "alert_hash", "告警Hash", "alert", "告警唯一哈希标识"),
            ("状态", "status", "状态", "alert", "当前处理状态"),
            ("所属组", "current_group", "所属组", "alert", "当前负责的安全小组"),
            ("设备名称", "device_name", "设备名称", "alert", "产生告警的设备名称"),
            ("当前时间", "current_time", "当前时间", "system", "变量填充时的实时时间"),
            ("当前日期", "current_date", "当前日期", "system", "变量填充时的实时日期"),
            ("源资产名称", "src_asset_name", "源资产名称", "asset", "源 IP 对应的资产名称"),
            ("源资产区域", "src_asset_area", "源资产区域", "asset", "源资产所属网络区域"),
            ("源资产负责人", "src_asset_owner", "源资产负责人", "asset", "源资产主要负责人"),
            ("源资产重要性", "src_asset_criticality", "源资产重要性", "asset", "源资产重要程度等级"),
            ("目的资产名称", "dst_asset_name", "目的资产名称", "asset", "目的 IP 对应的资产名称"),
            ("目的资产区域", "dst_asset_area", "目的资产区域", "asset", "目的资产所属网络区域"),
            ("目的资产负责人", "dst_asset_owner", "目的资产负责人", "asset", "目的资产主要负责人"),
            ("目的资产重要性", "dst_asset_criticality", "目的资产重要性", "asset", "目的资产重要程度等级"),
            ("AI 研判结果", "ai_result", "AI 研判结果", "ai", "AI 对该告警的综合研判意见"),
            ("威胁情报结果", "ti_result", "威胁情报结果", "threat_intel", "外部威胁情报查询汇总结果"),
        ]
    ]
    report_items = [
        {
            "name": name, 
            "field_key": key, 
            "field_label": label,
            "source": "report_metric",
            "domain": domain,
            "description": desc,
            "available_for": ["message", "excel", "csv", "report"]
        }
        for name, key, label, domain, desc in [
            ("告警总数", "alert_total", "告警总数", "report", "统计周期内的告警总数"),
            ("高危告警数", "high_alert_count", "高危告警数", "report", "统计周期内高危等级告警总数"),
            ("极高危告警数", "critical_alert_count", "极高危告警数", "report", "统计周期内极高危等级告警总数"),
            ("高危极高告警占比", "high_critical_ratio", "高危极高告警占比", "report", "高危及以上告警占总告警的百分比"),
            ("已完成处置数", "handled_alert_count", "已完成处置数", "report", "统计周期内已闭环的告警总数"),
            ("整体处置率", "handling_rate", "整体处置率", "report", "已处置告警占总告警的百分比"),
            ("平均处置耗时", "avg_handling_duration", "平均处置耗时", "report", "从告警产生到闭环的平均耗时"),
            ("待处理告警数", "pending_alert_count", "待处理告警数", "report", "当前处于待分析或待处置状态的告警数"),
            ("活跃攻击源Top5", "top_src_ips", "活跃攻击源Top5", "report", "攻击次数排名前 5 的源 IP 列表"),
            ("受攻击资产Top5", "top_attacked_assets", "受攻击资产Top5", "report", "被攻击次数排名前 5 的资产列表"),
            ("资产信息命中率", "asset_hit_rate", "资产信息命中率", "report", "告警 IP 在资产库中已备案的比例"),
            ("新增告警数", "new_alert_count", "新增告警数", "report", "较上一周期新增的告警数"),
            ("未闭环告警数", "open_alert_count", "未闭环告警数", "report", "当前所有未闭环的告警总数"),
            ("误报数", "false_positive_count", "误报数", "report", "统计周期内确认并标记为误报的告警数"),
            ("今日日期", "report_date", "今日日期", "report", "报表生成的对应日期"),
        ]
    ]
    items.extend(system_items)
    items.extend(report_items)
    seen = set()
    result = []
    for item in items:
        if item["name"] and item["name"] not in seen:
            result.append(item)
            seen.add(item["name"])
    return result


def _pick_template_var(catalog: list[dict[str, str]], field_keys: list[str], labels: list[str]) -> str:
    for key in field_keys:
        for item in catalog:
            if item.get("field_key") == key:
                return item["name"]
    normalized_labels = [label.lower().replace(" ", "") for label in labels]
    for label in labels:
        for item in catalog:
            if item.get("name") == label or item.get("field_label") == label:
                return item["name"]
    for item in catalog:
        haystack = f"{item.get('name', '')}{item.get('field_label', '')}{item.get('field_key', '')}".lower().replace(" ", "")
        if any(label in haystack for label in normalized_labels):
            return item["name"]
    return ""


def deterministic_template_from_sample(sample_text: str, catalog: list[dict[str, str]]) -> dict[str, Any]:
    content = sample_text or ""
    mappings: list[dict[str, str]] = []

    def replace_value(pattern: str, variable: str, value_group: int = 1):
        nonlocal content
        if not variable:
            return
        for match in list(re.finditer(pattern, content, flags=re.I)):
            value = match.group(value_group)
            if not value or "{{" in value:
                continue
            content = content.replace(value, f"{{{{{variable}}}}}", 1)
            mappings.append({"value": value, "variable": variable, "reason": "样例字段值匹配"})

    src_ip_var = _pick_template_var(catalog, ["src_ip"], ["源IP", "来源IP", "攻击来源IP", "源地址"])
    dst_ip_var = _pick_template_var(catalog, ["dst_ip"], ["目的IP", "目标IP", "受害IP", "目的地址"])
    generic_ip_var = src_ip_var or dst_ip_var or _pick_template_var(catalog, ["ip"], ["IP"])
    replace_value(r"(?:(?:源|来源|攻击来源)\s*IP|src[_ -]?ip)\s*[:：]?\s*((?:\d{1,3}\.){3}\d{1,3})", src_ip_var)
    replace_value(r"(?:(?:目的|目标|受害|目的地)\s*IP|dst[_ -]?ip)\s*[:：]?\s*((?:\d{1,3}\.){3}\d{1,3})", dst_ip_var)
    replace_value(r"(?:封禁|拉黑|加黑|阻断)\s*(?:源\s*)?ip\s*[:：]?\s*((?:\d{1,3}\.){3}\d{1,3})", src_ip_var or generic_ip_var)
    replace_value(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])", generic_ip_var)

    replace_value(r"(?:告警时间|时间戳|发生时间|开始时间)\s*[:：]?\s*([0-9]{4}-[0-9]{2}-[0-9]{2}\s+[0-9]{2}:[0-9]{2}:[0-9]{2})", _pick_template_var(catalog, ["alert_time"], ["告警时间", "时间戳", "发生时间"]))
    replace_value(r"(?:规则\s*ID|Rule\s*ID)\s*[:：]?\s*([A-Za-z0-9_.-]+)", _pick_template_var(catalog, ["rule_id"], ["规则ID", "Rule ID"]))
    replace_value(r"(?:威胁等级|风险等级|严重性)\s*[:：]?\s*([^\n\r]+)", _pick_template_var(catalog, ["severity"], ["威胁等级", "风险等级", "严重性"]))
    replace_value(r"(?:攻击结果|日志附带的结果|处置结果)\s*[:：]?\s*([^\n\r]+)", _pick_template_var(catalog, ["attack_result"], ["攻击结果", "日志附带的结果", "处置结果"]))
    replace_value(r"(?:攻击链阶段|攻击阶段)\s*[:：]?\s*([^\n\r]+)", _pick_template_var(catalog, ["attack_stage"], ["攻击链阶段", "攻击阶段"]))
    replace_value(r"(?:事件名称|日志消息内容|事件类型)\s*[:：]?\s*([^\n\r]+)", _pick_template_var(catalog, ["event_type"], ["事件名称", "日志消息内容", "事件类型"]))
    replace_value(r"(?:响应码|状态码|status)\s*[:：=]?\s*(\d{3}|--)", _pick_template_var(catalog, ["response_code"], ["响应码", "状态码"]))

    # 新增运营报表类识别逻辑
    replace_value(r"(?:\d{4}-\d{2}-\d{2})", _pick_template_var(catalog, ["current_date"], ["当前日期", "今日日期"]))
    replace_value(r"共监测到告警\s*(\d+)\s*条", _pick_template_var(catalog, ["alert_total"], ["告警总数"]))
    replace_value(r"其中高危/极高告警占比\s*([\d.]+%?)", _pick_template_var(catalog, ["high_critical_ratio"], ["高危极高告警占比"]))
    replace_value(r"已完成处置\s*(\d+)\s*条", _pick_template_var(catalog, ["handled_alert_count"], ["已完成处置数"]))
    replace_value(r"整体处置率为\s*([\d.]+%?)", _pick_template_var(catalog, ["handling_rate"], ["整体处置率"]))
    replace_value(r"平均处置耗时[:：]?\s*(\d+[秒分]|[\d.]+\s*minutes)", _pick_template_var(catalog, ["avg_handling_duration"], ["平均处置耗时"]))
    replace_value(r"目前仍有\s*(\d+)\s*条告警处于待处理", _pick_template_var(catalog, ["pending_alert_count"], ["待处理告警数"]))
    replace_value(r"资产信息命中率[:：]?\s*([\d.]+%?)", _pick_template_var(catalog, ["asset_hit_rate"], ["资产信息命中率"]))
    
    # TopN 块状识别 (如果内容匹配特定关键词，则替换整个区域为变量)
    if "活跃攻击源 Top" in content and "暂无数据" in content:
        var = _pick_template_var(catalog, ["top_src_ips"], ["活跃攻击源Top5"])
        if var:
            content = re.sub(r"【活跃攻击源 Top \d+】\n暂无数据", f"【活跃攻击源 Top 5】\n{{{{{var}}}}}", content)
            mappings.append({"value": "暂无数据", "variable": var, "reason": "报表 TopN 占位符匹配"})

    if "受攻击资产 Top" in content and "暂无数据" in content:
        var = _pick_template_var(catalog, ["top_attacked_assets"], ["受攻击资产Top5"])
        if var:
            content = re.sub(r"【受攻击资产 Top \d+】\n暂无数据", f"【受攻击资产 Top 5】\n{{{{{var}}}}}", content)
            mappings.append({"value": "暂无数据", "variable": var, "reason": "报表 TopN 占位符匹配"})

    variables = re.findall(r"\{\{\s*([^{}]+)\s*\}\}", content)
    return {
        "name": "AI 生成模板",
        "content": content,
        "variables": _unique(variables),
        "mappings": mappings,
        "warnings": [] if variables else [{"code": "no_variable_detected", "message": "未识别到可替换字段，请检查样例或候选变量。"}],
    }


def _count_placeholders(text: str) -> int:
    return len(re.findall(r"\{\{\s*[^{}]+\s*\}\}", text or ""))


def _merge_template_result(ai_data: dict[str, Any], deterministic_data: dict[str, Any], sample_text: str) -> dict[str, Any]:
    content = str(ai_data.get("content") or "")
    if _count_placeholders(content) < _count_placeholders(deterministic_data.get("content", "")):
        ai_data["content"] = deterministic_data["content"]
        ai_data["variables"] = deterministic_data["variables"]
        ai_data["mappings"] = deterministic_data["mappings"]
        ai_data["warnings"] = [
            warning
            for warning in (ai_data.get("warnings") or [])
            if not isinstance(warning, dict) or warning.get("code") not in {"format_not_consistent", "unused_variables"}
        ]
        ai_data.setdefault("warnings", []).append({"code": "deterministic_fallback", "message": "AI 未完成足够变量替换，已使用平台字段识别结果兜底。"})
    if ai_data.get("content") == sample_text and deterministic_data.get("content") != sample_text:
        ai_data["content"] = deterministic_data["content"]
    return ai_data


def generate_template_from_sample(db: Session, user: User, sample_text: str, device_id: int | None, template_type: str, intent: str) -> dict[str, Any]:
    ai_settings = get_effective_setting(db, user.workspace_id, user.id, "ai")
    if not ai_settings:
        raise HTTPException(status_code=400, detail="AI 网关未配置")
    
    catalog = available_template_variable_catalog(db, user, device_id)
    variables = [item["name"] for item in catalog]
    deterministic_data = deterministic_template_from_sample(sample_text, catalog)
    prompt = get_prompt(db, user.workspace_id, "template_generate")
    template_evidences = [
        execute_tool(db, user, "rule.search", {"q": intent or sample_text[:80]}),
        execute_tool(db, user, "template.search", {"q": template_type}),
        execute_tool(db, user, "device.search", {"q": str(device_id or "")}),
    ]
    
    # 轮次 1：初次生成
    content = chat_completion(
        [
            {
                "role": "system",
                "content": (
                    f"{prompt['system']}\n"
                    "必须优先使用候选变量和工具证据中的规则/模板信息。严禁新增样例原文没有的段落。"
                    "输出必须是合法 JSON，content 字段必须保持样例行文结构。"
                ),
            },
            {
                "role": "user",
                "content": prompt["user"].format(
                    template_type=template_type,
                    intent=intent,
                    variables=json.dumps(
                        {
                            "candidate_variables": variables,
                            "variable_catalog": catalog,
                            "tool_evidences": template_evidences,
                            "platform_suggestion": deterministic_data,
                        },
                        ensure_ascii=False,
                    ),
                    sample_text=sample_text,
                ),
            },
        ],
        ai_settings,
        temperature=0.1,
        timeout=180,
    )
    
    data = parse_json_object(content)
    if not data:
        raise HTTPException(status_code=500, detail="AI 未返回有效模板 JSON")

    # 轮次 2：自我反思与修正
    # 检查是否引入了幻觉字段，或破坏了原始格式
    check_prompt = (
        "你是模板 Reflector。请对比原始样例、候选变量和 AI 生成结果。"
        "判断是否保持原格式、是否只使用候选变量、是否有幻觉新增内容。"
        "样例中没有出现的字段不需要补充，短样例保持短样例，不得提示缺少未出现字段。"
        "只输出 JSON：{\"passed\":true/false,\"content\":\"修正后的模板内容或原内容\",\"warnings\":[]}"
    )
    
    reflection = chat_completion(
        [
            {"role": "system", "content": check_prompt},
            {
                "role": "user", 
                "content": json.dumps(
                    {
                        "sample_text": sample_text,
                        "candidate_variables": variables,
                        "platform_suggestion": deterministic_data,
                        "generated": data,
                    },
                    ensure_ascii=False,
                )
            }
        ],
        ai_settings,
        temperature=0,
        timeout=180
    )
    
    reflection_data = parse_json_object(reflection)
    if reflection_data:
        if not reflection_data.get("passed") and reflection_data.get("content"):
            data["content"] = reflection_data["content"]
        data["warnings"] = (data.get("warnings") or []) + (reflection_data.get("warnings") or [])
        data["reflection"] = {
            "passed": bool(reflection_data.get("passed")),
            "warnings": reflection_data.get("warnings") or [],
        }

    content_value = data.get("content", sample_text)
    if isinstance(content_value, dict):
        content_value = (
            content_value.get("content")
            or content_value.get("template")
            or content_value.get("text")
            or json.dumps(content_value, ensure_ascii=False)
        )
    elif isinstance(content_value, list):
        content_value = "\n".join(str(item) for item in content_value)
    else:
        content_value = str(content_value or sample_text)
    data["content"] = content_value
    data = _merge_template_result(data, deterministic_data, sample_text)

    data.setdefault("name", "AI 生成模板")
    data["variables"] = _unique(re.findall(r"\{\{\s*([^{}]+)\s*\}\}", data.get("content", "")) or data.get("variables") or [])
    data.setdefault("mappings", [])
    data.setdefault("warnings", [])
    data.setdefault("tool_evidences", template_evidences)
    data.setdefault("platform_suggestion", deterministic_data)
    return data


def generate_template_suggestion(db: Session, user: User, payload: TemplateAiGenerateRequest) -> dict[str, Any]:
    return generate_template_from_sample(
        db, user, payload.sample_text, payload.device_id, payload.template_type, payload.intent
    )


CHAT_TOOL_SCHEMAS = [
    {"tool": "get_asset_by_ip", "description": "按单个 IP 精确查询资产、负责人、区域、标签和指纹", "params": {"ip": "IP 地址"}},
    {"tool": "search_assets", "description": "按 IP、域名、资产名、负责人、区域、标签、指纹搜索资产", "params": {"q": "搜索词"}},
    {"tool": "get_alert_by_hash", "description": "按告警 Hash 精确查询告警详情", "params": {"alert_hash": "告警 Hash"}},
    {"tool": "search_alerts", "description": "查询告警列表、状态、源/目的 IP、负责人和最近更新时间", "params": {"q": "搜索词，可为空"}},
    {"tool": "list_rules", "description": "查询可用的解析规则变量，包含内置变量和自定义提取规则。生成模板时需调用此工具获取候选变量名。", "params": {"q": "变量名或分类，可为空"}},
    {"tool": "list_templates", "description": "查询模板中心模板", "params": {"q": "模板名或类型，可为空"}},
    {"tool": "list_devices", "description": "查询接入设备和产品信息", "params": {"q": "设备名或产品，可为空"}},
    {"tool": "list_projects", "description": "查询项目空间", "params": {"q": "项目名，可为空"}},
    {"tool": "list_users", "description": "查询团队成员、角色和启用状态，不返回密码或密钥", "params": {"q": "姓名或账号，可为空"}},
    {"tool": "list_messages", "description": "查询当前用户消息，管理员可看最近消息概览", "params": {"q": "搜索词，可为空"}},
    {"tool": "list_ai_experiences", "description": "查询已沉淀的 AI STE 经验", "params": {"q": "经验编号、标题或标签，可为空"}},
    {"tool": "search_audit_logs", "description": "查询审计日志和操作记录", "params": {"q": "操作名、目标类型或关键词，可为空"}},
    {"tool": "list_tasks", "description": "查询最近的 AI 分析、情报查询或导出任务状态", "params": {"q": "任务类型，可为空"}},
    {"tool": "get_ip_lists", "description": "查询当前的 IP 黑名单和白名单配置", "params": {}},
    {"tool": "ops_summary", "description": "查询运营概览计数", "params": {}},
    {"tool": "list_asset_segments", "description": "查询配置的网段资产，了解网络区域划分和网段负责人", "params": {"q": "搜索词，可为空"}},
    {"tool": "lookup_assets_batch", "description": "批量查询多个 IP 或域名的归属资产上下文", "params": {"ips": "IP 列表", "domains": "域名列表"}},
    {"tool": "get_alert_history", "description": "查询单个告警的全生命周期操作流转历史", "params": {"alert_id": "告警 ID"}},
    {"tool": "get_operational_summary", "description": "获取深度运营分析，包含 MTTR 耗时、处置率趋势和状态波动数据", "params": {"start_date": "YYYY-MM-DD", "end_date": "YYYY-MM-DD"}},
    {"tool": "generate_operational_report", "description": "调用系统报告引擎，根据预设模板生成日报或运营报告", "params": {"template_id": "模板 ID，可选"}},
    {"tool": "check_ip_status", "description": "快速校验 IP 是否存在于白名单或黑名单中", "params": {"ip": "需要检查的 IP"}},
    {"tool": "platform_context", "description": "说明可查询的平台数据范围", "params": {}},
]

CHAT_TOOL_NAMES = {item["tool"] for item in CHAT_TOOL_SCHEMAS}
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ALERT_HASH_RE = re.compile(r"\b[a-f0-9]{16,64}\b", flags=re.I)


def _query_text_filter(column: Any, q: str) -> Any:
    return column.ilike(f"%{q}%")


def _extract_ips(text: str) -> list[str]:
    return _unique(IP_RE.findall(text or ""))


def _extract_alert_hashes(text: str) -> list[str]:
    return _unique(ALERT_HASH_RE.findall(text or ""))


def _chat_call(tool: str, **params: Any) -> dict[str, Any]:
    return {"tool": tool, "params": {k: v for k, v in params.items() if v not in (None, "", [], {})}}


def _merge_tool_calls(*groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen = set()
    for group in groups:
        for call in group:
            tool = call.get("tool")
            if tool not in CHAT_TOOL_NAMES:
                continue
            params = call.get("params") or {}
            key = (tool, json.dumps(params, ensure_ascii=False, sort_keys=True))
            if key in seen:
                continue
            merged.append({"tool": tool, "params": params})
            seen.add(key)
    priority = {"get_asset_by_ip": 0, "get_alert_by_hash": 1, "search_assets": 2, "search_alerts": 3}
    return sorted(merged, key=lambda item: priority.get(item.get("tool", ""), 20))


def _deterministic_chat_calls(question: str) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    ips = _extract_ips(question)
    hashes = _extract_alert_hashes(question)
    for ip in ips[:5]:
        calls.append(_chat_call("get_asset_by_ip", ip=ip))
    for alert_hash in hashes[:3]:
        calls.append(_chat_call("get_alert_by_hash", alert_hash=alert_hash))
    if any(word in question for word in ("资产", "服务器", "主机", "负责人", "区域", "部门", "业务系统")):
        calls.append(_chat_call("search_assets", q=question))
    if any(word in question for word in ("告警", "事件", "研判", "处置", "误报")):
        calls.append(_chat_call("search_alerts", q=question))
    if "规则" in question:
        calls.append(_chat_call("list_rules", q=question))
    if "模板" in question:
        calls.append(_chat_call("list_templates", q=question))
    if any(word in question for word in ("设备", "产品", "态势感知")):
        calls.append(_chat_call("list_devices", q=question))
    if any(word in question for word in ("项目", "空间")):
        calls.append(_chat_call("list_projects", q=question))
    if any(word in question for word in ("用户", "人员", "成员", "账号", "角色", "谁")):
        calls.append(_chat_call("list_users", q=question))
    if any(word in question for word in ("消息", "通知", "未读")):
        calls.append(_chat_call("list_messages", q=question))
    if any(word in question for word in ("经验", "STE", "知识")):
        calls.append(_chat_call("list_ai_experiences", q=question))
    if any(word in question for word in ("审计", "日志", "记录", "操作", "审计日志")):
        calls.append(_chat_call("search_audit_logs", q=question))
    if any(word in question for word in ("任务", "分析中", "进度")):
        calls.append(_chat_call("list_tasks", q=question))
    if any(word in question for word in ("名单", "白名单", "黑名单")):
        calls.append(_chat_call("get_ip_lists"))
    if any(word in question for word in ("运营", "总览", "统计", "多少", "数量", "趋势")):
        calls.append(_chat_call("ops_summary"))
    if not calls:
        calls.append(_chat_call("platform_context"))
    return calls


def plan_chat_tools(db: Session, user: User, question: str) -> dict[str, Any]:
    deterministic = _deterministic_chat_calls(question)
    plan = {
        "mode": "planner_executor_reflector",
        "reason": "AI 规划只读工具调用，后端按白名单安全执行；本地确定性识别会兜住 IP、告警 Hash 等精确查询。",
        "tool_calls": deterministic,
        "available_tools": CHAT_TOOL_SCHEMAS,
    }
    ai_settings = get_effective_setting(db, user.workspace_id, user.id, "ai")
    if not ai_settings:
        return plan
    try:
        content = chat_completion(
            [
                {
                    "role": "system",
                    "content": (
                        "你是安全运营平台的查询 Planner。你的任务是根据用户问题，从给定的工具列表中选择合适的工具并生成参数。"
                        "你可以调用多个工具。即便问题包含具体 IP，如果需要查询负责人、所属区域等完整资产上下文，请同时调用搜索工具以确保信息完整。"
                        "禁止选择未列出的工具，禁止请求密钥、密码、token、cookie、API Key 等敏感信息。"
                        "只输出 JSON，格式为 {\"tool_calls\":[{\"tool\":\"工具名\",\"params\":{}}],\"reason\":\"选择原因\"}。"
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        {"question": question, "available_tools": CHAT_TOOL_SCHEMAS, "detected_ips": _extract_ips(question), "detected_alert_hashes": _extract_alert_hashes(question)},
                        ensure_ascii=False,
                    ),
                },
            ],
            ai_settings,
            temperature=0,
            timeout=30,
        )
        parsed = parse_json_object(content)
        ai_calls = parsed.get("tool_calls") if isinstance(parsed, dict) else []
        if isinstance(ai_calls, list):
            plan["tool_calls"] = _merge_tool_calls(deterministic, ai_calls)
            if parsed.get("reason"):
                plan["reason"] = parsed["reason"]
    except Exception:
        plan["tool_calls"] = deterministic
    return plan


def _asset_payload(row: Asset | None) -> dict[str, Any] | None:
    if not row:
        return None
    return {
        "id": row.id,
        "ip": row.ip,
        "domain": row.domain,
        "name": row.name,
        "area": row.area,
        "owner": row.owner,
        "department": row.department,
        "criticality": row.criticality,
        "environment": row.environment,
        "tags": row.tags or [],
        "fingerprints": row.fingerprints or {},
        "description": row.description,
        "updated_at": row.updated_at.isoformat(sep=" ", timespec="seconds") if row.updated_at else "",
    }


def _alert_payload(row: Alert | None) -> dict[str, Any] | None:
    if not row:
        return None
    return {
        "alert_code": getattr(row, "alert_code", row.id),
        "alert_hash": row.alert_hash,
        "event_type": row.event_type,
        "src_ip": row.source_ip,
        "dst_ip": row.destination_ip,
        "severity": row.severity,
        "status": STATUS_LABELS.get(row.status, row.status),
        "current_group": GROUP_LABELS.get(row.current_group, row.current_group),
        "assignee": row.assignee_id,  # 后续可在列表接口中映射姓名
        "created_at": row.created_at.isoformat(sep=" ", timespec="seconds") if row.created_at else "",
        "updated_at": row.updated_at.isoformat(sep=" ", timespec="seconds") if row.updated_at else "",
    }


def run_chat_tools(db: Session, user: User, question: str, plan: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    calls = (plan or {}).get("tool_calls") or _deterministic_chat_calls(question)
    results: list[dict[str, Any]] = []
    for call in calls[:12]:
        tool = call.get("tool")
        params = call.get("params") or {}
        q = str(params.get("q") or "").strip()
        if tool == "get_asset_by_ip":
            ip = str(params.get("ip") or "").strip()
            row = db.query(Asset).filter(Asset.workspace_id == user.workspace_id, Asset.ip == ip).order_by(Asset.updated_at.desc()).first()
            results.append({"tool": tool, "params": params, "data": _asset_payload(row)})
        elif tool == "search_assets":
            rows = db.query(Asset).filter(Asset.workspace_id == user.workspace_id)
            if q:
                rows = rows.filter(
                    or_(
                        _query_text_filter(Asset.ip, q),
                        _query_text_filter(Asset.domain, q),
                        _query_text_filter(Asset.name, q),
                        _query_text_filter(Asset.area, q),
                        _query_text_filter(Asset.owner, q),
                        _query_text_filter(Asset.department, q),
                    )
                )
            rows = rows.order_by(Asset.updated_at.desc()).limit(10).all()
            results.append({"tool": tool, "params": params, "data": [_asset_payload(row) for row in rows]})
        elif tool == "get_alert_by_hash":
            alert_hash = str(params.get("alert_hash") or "").strip()
            row = db.query(Alert).filter(Alert.workspace_id == user.workspace_id, Alert.alert_hash == alert_hash).first()
            results.append({"tool": tool, "params": params, "data": _alert_payload(row)})
        elif tool == "search_alerts":
            rows = db.query(Alert).filter(Alert.workspace_id == user.workspace_id)
            if q:
                rows = rows.filter(
                    or_(
                        _query_text_filter(Alert.alert_hash, q),
                        _query_text_filter(Alert.event_type, q),
                        _query_text_filter(Alert.source_ip, q),
                        _query_text_filter(Alert.destination_ip, q),
                        _query_text_filter(Alert.severity, q),
                        _query_text_filter(Alert.status, q),
                    )
                )
            rows = rows.order_by(Alert.updated_at.desc()).limit(10).all()
            results.append({"tool": tool, "params": params, "data": [_alert_payload(row) for row in rows]})
        elif tool == "list_rules":
            query = db.query(ParseRule).filter(ParseRule.workspace_id == user.workspace_id, ParseRule.enabled.is_(True))
            if q:
                query = query.filter(or_(_query_text_filter(ParseRule.name, q), _query_text_filter(ParseRule.field_key, q), _query_text_filter(ParseRule.field_label, q)))
            custom_rules = query.order_by(ParseRule.priority.asc()).limit(50).all()
            
            # 整合内置变量
            all_rules = []
            for r in custom_rules:
                all_rules.append({
                    "name": r.name, 
                    "field_key": r.field_key, 
                    "label": r.field_label or r.name,
                    "type": "custom",
                    "match_type": r.match_type
                })
            
            # 添加系统内置变量描述
            builtin_vars = [
                {"name": "告警ID", "field_key": "alert_code", "label": "告警ID", "type": "builtin"},
                {"name": "状态", "field_key": "status_label", "label": "状态", "type": "builtin"},
                {"name": "当前时间", "field_key": "current_time", "label": "当前时间", "type": "builtin"},
                {"name": "源IP地理位置", "field_key": "src_ip_location", "label": "源IP地理位置", "type": "builtin"},
                {"name": "目的IP地理位置", "field_key": "dst_ip_location", "label": "目的IP地理位置", "type": "builtin"},
                {"name": "AI 研判结果", "field_key": "ai_result", "label": "AI 研判结果", "type": "builtin"},
                {"name": "威胁情报结果", "field_key": "ti_result", "label": "威胁情报结果", "type": "builtin"}
            ]
            if not q:
                all_rules.extend(builtin_vars)
            else:
                all_rules.extend([v for v in builtin_vars if q.lower() in v["name"].lower() or q.lower() in v["field_key"].lower()])
                
            results.append({"tool": tool, "params": params, "data": all_rules})
        elif tool == "list_templates":
            rows = db.query(Template).filter(Template.workspace_id == user.workspace_id)
            if q:
                rows = rows.filter(or_(_query_text_filter(Template.name, q), _query_text_filter(Template.type, q)))
            rows = rows.order_by(Template.updated_at.desc()).limit(20).all()
            results.append({"tool": tool, "params": params, "data": [{"id": r.id, "name": r.name, "type": r.type, "scope": r.scope, "device_id": r.device_id, "variables": r.variables or []} for r in rows]})
        elif tool == "list_devices":
            rows = db.query(Device).filter(Device.workspace_id == user.workspace_id)
            if q:
                rows = rows.filter(or_(_query_text_filter(Device.name, q), _query_text_filter(Device.vendor, q), _query_text_filter(Device.product, q)))
            rows = rows.order_by(Device.updated_at.desc()).limit(20).all()
            results.append({"tool": tool, "params": params, "data": [{"id": r.id, "name": r.name, "vendor": r.vendor, "product": r.product, "version": r.version} for r in rows]})
        elif tool == "list_projects":
            rows = db.query(Project).filter(Project.workspace_id == user.workspace_id)
            if q:
                rows = rows.filter(_query_text_filter(Project.name, q))
            rows = rows.order_by(Project.updated_at.desc()).limit(20).all()
            results.append({"tool": tool, "params": params, "data": [{"id": r.id, "name": r.name, "description": r.description} for r in rows]})
        elif tool == "list_users":
            rows = db.query(User).filter(User.workspace_id == user.workspace_id)
            if q:
                rows = rows.filter(or_(_query_text_filter(User.username, q), _query_text_filter(User.display_name, q), _query_text_filter(User.role, q)))
            rows = rows.order_by(User.updated_at.desc()).limit(30).all()
            results.append({"tool": tool, "params": params, "data": [{"id": r.id, "username": r.username, "display_name": r.display_name, "role": ROLE_LABELS.get(r.role, r.role), "is_active": r.is_active} for r in rows]})
        elif tool == "list_messages":
            rows = db.query(Message).filter(Message.workspace_id == user.workspace_id)
            if user.role != "admin":
                rows = rows.filter(Message.recipient_id == user.id)
            if q:
                rows = rows.filter(or_(_query_text_filter(Message.title, q), _query_text_filter(Message.content, q), _query_text_filter(Message.alert_hash, q)))
            rows = rows.order_by(Message.created_at.desc()).limit(20).all()
            results.append({"tool": tool, "params": params, "data": [{"id": r.id, "title": r.title, "content": _truncate(r.content, 180), "alert_hash": r.alert_hash, "is_read": r.is_read, "created_at": r.created_at.isoformat(sep=" ", timespec="seconds")} for r in rows]})
        elif tool == "list_ai_experiences":
            rows = db.query(AiExperience).filter(AiExperience.workspace_id == user.workspace_id)
            if q:
                rows = rows.filter(or_(_query_text_filter(AiExperience.knowledge_id, q), _query_text_filter(AiExperience.title, q), _query_text_filter(AiExperience.alert_hash, q)))
            rows = rows.order_by(AiExperience.updated_at.desc()).limit(20).all()
            results.append({"tool": tool, "params": params, "data": [{"knowledge_id": r.knowledge_id, "title": r.title, "alert_hash": r.alert_hash, "tags": r.tags or [], "status": r.status} for r in rows]})
        elif tool == "search_audit_logs":
            rows = db.query(AuditLog).filter(AuditLog.workspace_id == user.workspace_id)
            if q:
                rows = rows.filter(or_(_query_text_filter(AuditLog.action, q), _query_text_filter(AuditLog.target_type, q)))
            rows = rows.order_by(AuditLog.created_at.desc()).limit(20).all()
            results.append({"tool": tool, "params": params, "data": [{"time": r.created_at.isoformat(sep=" ", timespec="seconds"), "action": r.action, "target": f"{r.target_type}:{r.target_id}"} for r in rows]})
        elif tool == "list_tasks":
            rows = db.query(TaskRecord).filter(TaskRecord.workspace_id == user.workspace_id)
            if q:
                rows = rows.filter(_query_text_filter(TaskRecord.task_type, q))
            rows = rows.order_by(TaskRecord.created_at.desc()).limit(10).all()
            results.append({"tool": tool, "params": params, "data": [{"type": r.task_type, "status": r.status, "target_type": r.target_type, "target_id": r.target_id, "time": r.created_at.isoformat(sep=" ", timespec="seconds")} for r in rows]})
        elif tool == "get_ip_lists":
            from app.services.ip_list_service import get_ip_list_setting
            row = get_ip_list_setting(db, user.workspace_id)
            val = row.value or {"whitelist": [], "blacklist": []}
            results.append({"tool": tool, "params": params, "data": {"whitelist_count": len(val.get("whitelist", [])), "blacklist_count": len(val.get("blacklist", [])), "recent_whitelist": val.get("whitelist", [])[:10], "recent_blacklist": val.get("blacklist", [])[:10]}})
        elif tool == "ops_summary":
            total_alerts = db.query(Alert).filter(Alert.workspace_id == user.workspace_id).count()
            open_alerts = db.query(Alert).filter(Alert.workspace_id == user.workspace_id, Alert.status.in_(["analysis", "disposal"])).count()
            total_assets = db.query(Asset).filter(Asset.workspace_id == user.workspace_id).count()
            unread = db.query(Message).filter(Message.workspace_id == user.workspace_id, Message.recipient_id == user.id, Message.is_read.is_(False)).count()
            tasks = db.query(TaskRecord).filter(TaskRecord.workspace_id == user.workspace_id).order_by(TaskRecord.created_at.desc()).limit(5).all()
            results.append({"tool": tool, "params": params, "data": {"告警总数": total_alerts, "未闭环告警": open_alerts, "资产总数": total_assets, "我的未读消息": unread, "最近任务": [{"task_type": t.task_type, "status": t.status, "target_type": t.target_type, "target_id": t.target_id} for t in tasks]}})
        elif tool == "list_asset_segments":
            from app.models.entities import AssetSegment
            query = db.query(AssetSegment).filter(AssetSegment.workspace_id == user.workspace_id)
            if q:
                query = query.filter(or_(_query_text_filter(AssetSegment.segment, q), _query_text_filter(AssetSegment.name, q), _query_text_filter(AssetSegment.owner, q), _query_text_filter(AssetSegment.area, q)))
            rows = query.order_by(AssetSegment.updated_at.desc()).limit(20).all()
            results.append({"tool": tool, "params": params, "data": [{"segment": r.segment, "name": r.name, "area": r.area, "owner": r.owner, "criticality": r.criticality} for r in rows]})
        elif tool == "lookup_assets_batch":
            from app.services.asset_service import build_asset_context, lookup_asset_by_ip, lookup_asset_by_domain
            ips = params.get("ips") or []
            if isinstance(ips, str): ips = [ips]
            domains = params.get("domains") or []
            if isinstance(domains, str): domains = [domains]
            by_ip = {ip: build_asset_context(lookup_asset_by_ip(db, user.workspace_id, ip)) for ip in ips[:20]}
            by_domain = {dom: build_asset_context(lookup_asset_by_domain(db, user.workspace_id, dom)) for dom in domains[:20]}
            results.append({"tool": tool, "params": params, "data": {"ips": {k: v for k, v in by_ip.items() if v}, "domains": {k: v for k, v in by_domain.items() if v}}})
        elif tool == "get_alert_history":
            alert_id = params.get("alert_id")
            if alert_id:
                history_rows = db.query(AuditLog).filter(AuditLog.workspace_id == user.workspace_id, AuditLog.target_type == "alert", (AuditLog.target_id == str(alert_id)) | (AuditLog.target_id.like(f"%,{alert_id},%") | AuditLog.target_id.like(f"{alert_id},%") | AuditLog.target_id.like(f"%,{alert_id}"))).order_by(AuditLog.created_at.desc()).limit(50).all()
                results.append({"tool": tool, "params": params, "data": [{"time": r.created_at.isoformat(sep=" ", timespec="seconds"), "action": r.action, "detail": r.detail} for r in history_rows]})
        elif tool == "get_operational_summary":
            from app.api.ops import dashboard_summary
            start_date = params.get("start_date")
            end_date = params.get("end_date")
            try:
                data = dashboard_summary(start_date=start_date, end_date=end_date, db=db, user=user)
                # 剔除可能包含较多敏感信息的 latest 列表
                if "latest" in data: del data["latest"]
                results.append({"tool": tool, "params": params, "data": data})
            except Exception as e:
                results.append({"tool": tool, "params": params, "error": str(e)})
        elif tool == "generate_operational_report":
            from app.api.ops import dashboard_report
            template_id = params.get("template_id")
            try:
                data = dashboard_report(template_id=template_id, db=db, user=user)
                results.append({"tool": tool, "params": params, "data": data})
            except Exception as e:
                results.append({"tool": tool, "params": params, "error": str(e)})
        elif tool == "check_ip_status":
            from app.api.ops import check_ip_list
            ip = params.get("ip")
            if ip:
                data = check_ip_list(payload={"ip": ip}, db=db, user=user)
                results.append({"tool": tool, "params": params, "data": data})
        elif tool == "platform_context":
            results.append({"tool": tool, "params": params, "data": "可查询：告警、资产、规则、模板、设备、项目、团队成员、消息、AI 经验、审计日志、后台任务和运营统计。不会返回密码、密钥、token、cookie、API Key。"})
    if not results:
        results.append({"tool": "platform_context", "params": {}, "data": "可查询平台只读数据，但没有命中合适工具。"})
    return results


def deterministic_tool_answer(question: str, tool_results: list[dict[str, Any]], suffix: str = "") -> str:
    for result in tool_results:
        if result.get("tool") == "get_asset_by_ip":
            data = result.get("data") or {}
            params = result.get("params") or {}
            ip = params.get("ip") or data.get("ip") or ""
            if data:
                owner = data.get("owner") or "未填写"
                parts = [f"{ip} 的负责人是 {owner}"]
                if data.get("name"):
                    parts.append(f"资产名称：{data['name']}")
                if data.get("area"):
                    parts.append(f"所属区域：{data['area']}")
                if data.get("department"):
                    parts.append(f"部门：{data['department']}")
                answer = "；".join(parts) + "。"
            else:
                answer = f"没有在资产库中查到 IP {ip} 的资产记录。"
            return answer + (f"\n\n{suffix}" if suffix else "")
    return (suffix or "已完成平台查询，请查看工具结果。").strip()


def reflect_chat_answer(db: Session, user: User, question: str, answer: str, tool_results: list[dict[str, Any]], plan: dict[str, Any]) -> str:
    ai_settings = get_effective_setting(db, user.workspace_id, user.id, "ai")
    if not ai_settings:
        return answer
    try:
        content = chat_completion(
            [
                {"role": "system", "content": "你是对话 Reflector。检查回答是否完全基于工具结果，删除无依据内容，保留简洁结论。"},
                {"role": "user", "content": json.dumps({"question": question, "plan": plan, "tool_results": tool_results, "draft": answer}, ensure_ascii=False)},
            ],
            ai_settings,
            temperature=0,
            timeout=45,
        )
        return content or answer
    except Exception:
        return answer


def answer_chat(db: Session, user: User, question: str, tool_results: list[dict[str, Any]], plan: dict[str, Any] | None = None) -> str:
    ai_settings = get_effective_setting(db, user.workspace_id, user.id, "ai")
    if not ai_settings:
        return deterministic_tool_answer(question, tool_results, "AI 网关未配置，已先基于平台查询结果给出直接回答。")
    prompt = get_prompt(db, user.workspace_id, "chat")
    try:
        draft = chat_completion(
            [
                {
                    "role": "system",
                    "content": (
                        f"{prompt['system']}\n"
                        "必须优先使用工具结果中的真实数据回答。若工具结果已包含负责人、资产名、告警状态等具体字段，请直接给出确定性的结论，"
                        "严禁声称平台没有对应查询能力。如果没有查到数据，请如实说明查询结果为空。不得输出密码、密钥、token、cookie、API Key。"
                    ),
                },
                {
                    "role": "user",
                    "content": prompt["user"].format(
                        question=question,
                        tool_results=json.dumps(tool_results, ensure_ascii=False),
                    ),
                },
                {"role": "user", "content": f"Planner 查询计划：\n{json.dumps(plan or {}, ensure_ascii=False)}"},
            ],
            ai_settings,
            temperature=0.3,
            timeout=60,
        )
        return reflect_chat_answer(db, user, question, draft, tool_results, plan or {})
    except HTTPException as exc:
        return deterministic_tool_answer(question, tool_results, f"AI 调用失败：{exc.detail}")
