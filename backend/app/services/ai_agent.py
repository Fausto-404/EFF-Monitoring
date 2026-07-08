from __future__ import annotations

import json
import re
from typing import Any, AsyncGenerator, Sequence, TypedDict, Annotated, Literal
import asyncio
import operator
from datetime import datetime

import ipaddress


from sqlalchemy.orm import Session
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage, SystemMessage

from app.models.entities import User, AiMessage, AiConversation
from app.services.ai_gateway import chat_completion, async_chat_stream, parse_json_object
from app.models.bootstrap import get_effective_setting
from app.services.ai_service import get_prompt
from app.services.ai_tools.registry import execute_tool, get_tool_schemas, _evidence, EVIDENCE_TYPES, TOOL_REGISTRY

def safe_sse_event(event: str, data: Any) -> str | None:
    """
    统一构造安全的 SSE 事件 JSON 字符串。
    如果 event 为 token 且 data 为空/None，返回 None 以便调用方忽略。
    """
    if event == "token":
        if data is None or data == "":
            return None
        # 强制转为字符串，确保不为 null
        data = str(data)
        if data.lower() == "null" or data.lower() == "undefined":
            return None
            
    payload = {"event": event, "data": data}
    return json.dumps(payload, ensure_ascii=False)

# --- Task Archetypes & Evidence Roles ---

TASK_ARCHETYPES = [
    "entity_lookup", "ownership_lookup", "entity_risk_assessment", "decision_support",
    "incident_investigation", "metric_count", "metric_groupby", "metric_trend",
    "metric_topn", "duration_analysis", "capability_discovery", "schema_discovery",
    "report_generation", "similar_case_retrieval"
]

EVIDENCE_ROLES = [
    "subject_identity", "ownership", "risk_signals", "external_intel",
    "internal_context", "policy_or_constraint", "timeline", "raw_observations",
    "historical_cases", "tabular_data", "aggregation", "grouping", "trend",
    "ranking", "duration", "capability_scope", "schema_scope", "permission_scope",
    "decision_boundary", "template_variable_catalog", "template_examples", "import_contract"
]

ROLE_TO_EVIDENCE_TYPES = {
    "subject_identity": {"ip": ["ip_classification", "asset_profile"], "alert_hash": ["alert_detail"], "asset": ["asset_profile"], "user": ["user_public_profile", "user_profile"], "*": ["tabular_dataset"]},
    "ownership": {"ip": ["asset_ownership"], "asset": ["asset_ownership"], "alert_hash": ["alert_detail", "alert_status_context"], "*": ["tabular_dataset"]},
    "risk_signals": {"ip": ["alert_list", "similar_alerts", "raw_log_match", "threat_event", "ip_reputation"], "alert_hash": ["alert_detail", "alert_timeline"], "asset": ["alert_list", "asset_risk_context"], "*": ["alert_list"]},
    "external_intel": {"ip": ["ip_reputation", "ip_intel_report", "threat_intelligence", "threat_event"], "*": ["ip_reputation"]},
    "internal_context": {"*": ["asset_profile", "device_profile", "project_list", "module_catalog", "tool_catalog", "field_schema"]},
    "policy_or_constraint": {"*": ["safe_setting_summary", "permission_scope"]},
    "timeline": {"alert_hash": ["alert_timeline", "audit_timeline"], "*": ["audit_timeline"]},
    "historical_cases": {"*": ["ste_experience", "similar_case", "experience_search"]},
    "tabular_data": {"alert": ["alert_list"], "audit": ["audit_timeline", "tabular_dataset"], "task": ["task_status"], "*": ["tabular_dataset", "alert_list"]},
    "aggregation": {"*": ["aggregation_result"]},
    "grouping": {"*": ["groupby_result"]},
    "trend": {"*": ["timeseries_result", "metric_trend"]},
    "ranking": {"*": ["topn_result"]},
    "duration": {"*": ["duration_metric"]},
    "capability_scope": {"*": ["tool_catalog", "module_catalog", "data_domain_catalog", "template_import_contract"]},
    "schema_scope": {"*": ["field_schema", "template_variable_schema"]},
    "permission_scope": {"*": ["permission_scope"]},
    "decision_boundary": {"*": ["safe_setting_summary", "permission_scope"]},
    "template_variable_catalog": {"*": ["template_variable_schema"]},
    "template_examples": {"*": ["template_definition"]},
    "import_contract": {"*": ["template_import_contract"]}
}

EVIDENCE_TYPE_TOOLS = {
    "ip_reputation": ["ti.lookup_ip", "intel.ip_report"],
    "ip_intel_report": ["intel.ip_report", "ti.lookup_ip"],
    "threat_intelligence": ["ti.lookup_ip", "intel.ip_report"],
    "threat_event": ["ti.lookup_ip", "intel.ip_report"],
    "alert_list": ["alert.search", "alert.similar_by_ip"],
    "alert_detail": ["alert.detail"],
    "alert_timeline": ["alert.timeline", "audit.search"],
    "alert_status_context": ["alert.detail"],
    "audit_timeline": ["audit.search", "alert.timeline"],
    "asset_profile": ["asset.get_by_ip", "asset.search", "intel.ip_report"],
    "asset_ownership": ["asset.get_by_ip", "asset.get_by_domain"],
    "rule_definition": ["rule.search"],
    "template_definition": ["template.search", "template.generate_importable"],
    "ste_experience": ["experience.search"],
    "similar_case": ["experience.search"],
    "safe_setting_summary": ["settings.safe"],
    "permission_scope": ["system.permissions"],
    "module_catalog": ["system.modules"],
    "tool_catalog": ["agent.tool_registry"],
    "field_schema": ["system.data_dictionary", "template.variable_catalog"]
}



# --- Analysis Calculation Engine ---

def extract_tabular_rows(data: Any) -> list[dict]:
    """从 evidence 数据中提取表格行"""
    if not data:
        return []
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        # 尝试常见结构
        for key in ["rows", "items", "results", "alerts", "assets", "messages", "records", "data"]:
            if isinstance(data.get(key), list):
                return [item for item in data[key] if isinstance(item, dict)]
        # 如果 data 本身就是 dict 列表的包装
        if "total" in data and any(isinstance(data.get(k), list) for k in data):
            for k, v in data.items():
                if isinstance(v, list) and v:
                    return [item for item in v if isinstance(item, dict)]
    return []


def find_dataset_for_analysis(dataset_ref: str | None, evidence_packs: list[dict]) -> tuple[list[dict], dict | None, list[str]]:
    """寻找最合适的分析数据集"""
    warnings = []
    source_ev = None
    
    if dataset_ref:
        # 匹配 evidence_id 或 tool name
        for ev in evidence_packs:
            if ev.get("evidence_id") == dataset_ref or ev.get("tool") == dataset_ref:
                source_ev = ev
                break
        if not source_ev:
            warnings.append(f"未找到引用的数据集: {dataset_ref}，将尝试使用最近的数据。")
    
    if not source_ev:
        # 倒序查找最近的有数据的 evidence
        for ev in reversed(evidence_packs):
            rows = extract_tabular_rows(ev.get("data"))
            if rows:
                source_ev = ev
                break
                
    if not source_ev:
        return [], None, ["未找到包含可提取表格数据的证据包。"]
        
    rows = extract_tabular_rows(source_ev.get("data"))
    if not rows:
        return [], source_ev, ["数据集中不包含有效的表格行记录。"]
        
    if source_ev.get("row_count", 0) >= 20: # 假设 20 是分页阈值
        warnings.append(f"注意：当前计算仅基于最近返回的 {len(rows)} 条记录（证据 ID: {source_ev.get('evidence_id')}）。")
        
    return rows, source_ev, warnings


def get_field_value(row: dict, field: str) -> Any:
    """获取字段值，支持嵌套"""
    if "." not in field:
        return row.get(field)
    parts = field.split(".")
    curr = row
    for p in parts:
        if isinstance(curr, dict):
            curr = curr.get(p)
        else:
            return None
    return curr


def apply_filters(rows: list[dict], filters: dict | None) -> tuple[list[dict], list[str]]:
    """应用过滤条件"""
    if not filters:
        return rows, []
    
    filtered = []
    warnings = []
    
    for row in rows:
        match = True
        for f_key, f_val in filters.items():
            # 处理特殊操作符
            actual_val = None
            op = "eq"
            
            if "__" in f_key:
                field, op = f_key.split("__", 1)
                actual_val = get_field_value(row, field)
            else:
                actual_val = get_field_value(row, f_key)
            
            try:
                if op == "eq":
                    if isinstance(f_val, list):
                        if actual_val not in f_val: match = False
                    elif actual_val != f_val: match = False
                elif op == "contains":
                    if str(f_val).lower() not in str(actual_val or "").lower(): match = False
                elif op == "gte":
                    if not (actual_val is not None and str(actual_val) >= str(f_val)): match = False
                elif op == "lte":
                    if not (actual_val is not None and str(actual_val) <= str(f_val)): match = False
                else:
                    warnings.append(f"暂不支持过滤操作符: {op}")
            except Exception:
                match = False
                
            if not match: break
        if match:
            filtered.append(row)
            
    return filtered, list(set(warnings))


def aggregate_rows(rows: list[dict], operation: str, field: str | None = None, distinct: bool = False) -> Any:
    """执行聚合计算"""
    if not rows and operation != "count":
        return 0
    
    if operation == "count":
        return len(rows)
    
    vals = []
    for r in rows:
        v = get_field_value(r, field) if field else None
        if v is not None:
            vals.append(v)
            
    if not vals:
        return 0
        
    if operation == "count_distinct":
        return len(set(str(v) for v in vals))
        
    # 数值类计算
    num_vals = []
    for v in vals:
        try:
            num_vals.append(float(v))
        except (ValueError, TypeError):
            continue
            
    if not num_vals: return 0
    
    if operation == "sum": return sum(num_vals)
    if operation == "avg": return sum(num_vals) / len(num_vals)
    if operation == "min": return min(num_vals)
    if operation == "max": return max(num_vals)
    
    return 0


def groupby_rows(rows: list[dict], group_by: list[str], metrics: list[dict], order_by: str | None = None, order: str = "desc", limit: int | None = None) -> dict:
    """执行分组统计"""
    groups = {}
    warnings = []
    
    for r in rows:
        key_parts = []
        for g in group_by:
            val = get_field_value(r, g)
            key_parts.append(str(val) if val is not None else "Unknown")
        key = tuple(key_parts)
        
        if key not in groups:
            groups[key] = []
        groups[key].append(r)
        
    result_rows = []
    columns = group_by + [m["name"] for m in metrics]
    
    for key, group_rows in groups.items():
        res_row = {}
        for i, g in enumerate(group_by):
            res_row[g] = key[i]
            
        for m in metrics:
            res_row[m["name"]] = aggregate_rows(group_rows, m["operation"], m.get("field"))
            
        result_rows.append(res_row)
        
    if order_by:
        result_rows.sort(key=lambda x: x.get(order_by, 0), reverse=(order == "desc"))
        
    if limit:
        result_rows = result_rows[:limit]
        
    return {
        "columns": columns,
        "rows": result_rows,
        "total_groups": len(groups),
        "warnings": warnings
    }


def timeseries_rows(rows: list[dict], time_field: str, interval: str, metrics: list[dict]) -> dict:
    """执行时间序列分析"""
    buckets = {}
    warnings = []
    
    for r in rows:
        val = get_field_value(r, time_field)
        if not val:
            continue
        try:
            # 兼容多种时间格式
            if isinstance(val, str):
                dt = datetime.fromisoformat(val.replace(" ", "T"))
            elif isinstance(val, datetime):
                dt = val
            else:
                continue
                
            if interval == "hour":
                bucket = dt.strftime("%Y-%m-%d %H:00")
            elif interval == "day":
                bucket = dt.strftime("%Y-%m-%d")
            elif interval == "week":
                bucket = dt.strftime("%Y-W%W")
            elif interval == "month":
                bucket = dt.strftime("%Y-%m")
            else:
                bucket = dt.strftime("%Y-%m-%d")
                
            if bucket not in buckets:
                buckets[bucket] = []
            buckets[bucket].append(r)
        except Exception:
            continue
            
    result_rows = []
    sorted_buckets = sorted(buckets.keys())
    
    for b in sorted_buckets:
        res_row = {"bucket": b}
        for m in metrics:
            res_row[m["name"]] = aggregate_rows(buckets[b], m["operation"], m.get("field"))
        result_rows.append(res_row)
        
    return {
        "rows": result_rows,
        "warnings": warnings
    }


def execute_analysis_tool(tool_name: str, params: dict[str, Any], evidence_packs: list[dict]) -> dict[str, Any]:
    """执行分析工具逻辑"""
    dataset_ref = params.get("dataset_ref")
    rows, source_ev, warnings = find_dataset_for_analysis(dataset_ref, evidence_packs)
    
    if not source_ev:
        return _evidence(tool_name, "L1", "error", "未找到可用于分析的数据源", {}, warnings=warnings)
        
    # 应用过滤
    rows, filter_warnings = apply_filters(rows, params.get("filters"))
    warnings.extend(filter_warnings)
    
    data = {}
    summary = ""
    evidence_types = []
    
    try:
        if tool_name == "analysis.aggregate":
            res = aggregate_rows(rows, params.get("operation", "count"), params.get("field"))
            data = {"result": res, "operation": params.get("operation"), "field": params.get("field")}
            summary = f"基于 {source_ev['tool']} 计算 {params.get('operation')} 结果为 {res}"
            evidence_types = ["aggregation_result", "derived_metric"]
            
        elif tool_name == "analysis.groupby":
            data = groupby_rows(rows, params.get("group_by", []), params.get("metrics", []))
            summary = f"基于 {source_ev['tool']} 完成 {len(data['rows'])} 组统计"
            evidence_types = ["groupby_result", "aggregation_result"]
            
        elif tool_name == "analysis.timeseries":
            data = timeseries_rows(rows, params.get("time_field", "created_at"), params.get("interval", "day"), params.get("metrics", []))
            summary = f"基于 {source_ev['tool']} 完成时间趋势分析"
            evidence_types = ["timeseries_result", "aggregation_result"]
            
        elif tool_name == "analysis.topn":
            metrics = [params.get("metric", {"operation": "count", "name": "count"})]
            if "name" not in metrics[0]: metrics[0]["name"] = "value"
            gb = groupby_rows(rows, [params.get("group_by")], metrics, order_by=metrics[0]["name"], limit=params.get("limit", 10))
            data = gb
            summary = f"基于 {source_ev['tool']} 获取 Top {len(gb['rows'])} 排名"
            evidence_types = ["topn_result", "groupby_result"]
            
        elif tool_name == "analysis.duration":
            # 耗时统计特殊处理
            durations = []
            start_f = params.get("start_field", "created_at")
            end_f = params.get("end_field", "closed_at")
            for r in rows:
                s = get_field_value(r, start_f)
                e = get_field_value(r, end_f)
                try:
                    if isinstance(s, str): s = datetime.fromisoformat(s.replace(" ", "T"))
                    if isinstance(e, str): e = datetime.fromisoformat(e.replace(" ", "T"))
                    if s and e:
                        durations.append((e - s).total_seconds() / 60) # minutes
                except Exception: continue
            
            if not durations:
                data = {"avg": 0, "min": 0, "max": 0, "count": 0}
            else:
                data = {
                    "avg": sum(durations) / len(durations),
                    "min": min(durations),
                    "max": max(durations),
                    "count": len(durations),
                    "unit": "minutes"
                }
            summary = f"基于 {source_ev['tool']} 完成耗时统计，平均 {data['avg']:.1f} 分钟"
            evidence_types = ["duration_metric", "aggregation_result"]
    except Exception as e:
        return _evidence(tool_name, "L1", "error", f"分析计算失败: {str(e)}", {}, warnings=warnings)

    return _evidence(
        tool_name, 
        "L1", 
        "success", 
        summary, 
        data, 
        evidence_types=evidence_types,
        source=f"{source_ev['tool']}:{source_ev['evidence_id']}",
        warnings=warnings,
        lineage={
            "derived_from": [source_ev["evidence_id"]],
            "params": params,
            "operation": tool_name
        }
    )


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
    task_model: dict[str, Any]
    plan: dict[str, Any]
    evidences: list[dict[str, Any]]
    final_answer: str
    trace: list[str]
    iteration: int
    tool_repair_rounds: int
    answer_repair_rounds: int
    error_context: str
    status: Literal["continue", "end"]
    required_evidence_types: list[str]
    missing_evidence_types: list[str]
    repair_actions: list[dict[str, Any]]
    already_called_tools: set[str]
    ti_queried_ips: set[str]


# --- 1. Entity Normalizer (线索抽取) ---

def enrich_entities(entities: dict[str, Any]) -> dict[str, Any]:
    enriched = entities.copy()
    ip_details = {}
    for ip in entities.get("ips", []):
        try:
            ip_obj = ipaddress.ip_address(ip)
            ip_details[ip] = {
                "version": ip_obj.version,
                "is_private": ip_obj.is_private,
                "is_loopback": ip_obj.is_loopback,
                "is_link_local": ip_obj.is_link_local,
                "is_multicast": ip_obj.is_multicast,
                "is_reserved": ip_obj.is_reserved,
                "is_documentation": False,
                "category": "private" if ip_obj.is_private else "public",
                "warnings": []
            }
            if getattr(ip_obj, "is_global", not ip_obj.is_private):
                ip_details[ip]["category"] = "public"
            # Explicitly check for documentation/test-net
            if any(ipaddress.ip_address(ip) in ipaddress.ip_network(net) for net in ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"]):
                ip_details[ip]["is_documentation"] = True
                ip_details[ip]["category"] = "documentation/test-net"
                ip_details[ip]["warnings"].append(f"{ip} 是文档/测试保留地址，非真实公网 IP。")
        except Exception:
            pass
    enriched["ip_details"] = ip_details
    return enriched

def classify_task_archetype(question: str, entities: dict[str, Any], llm_understanding: dict[str, Any]) -> dict:
    archetype = "entity_lookup"
    operations = ["lookup"]
    subject_type = "unknown"
    subject_value = ""

    if entities.get("ips"):
        subject_type = "ip"
        subject_value = entities["ips"][0]
    elif entities.get("hashes"):
        subject_type = "alert_hash"
        subject_value = entities["hashes"][0]
    elif "项目" in question:
        subject_type = "project"
    elif "设备" in question:
        subject_type = "device"
    elif "模板" in question:
        subject_type = "template"
    elif "规则" in question:
        subject_type = "rule"
        
    intent = llm_understanding.get("intent", "")
    calc_intents = llm_understanding.get("calculation_intents", [])
    
    if "duration" in calc_intents or "时长" in question or "多久" in question:
        archetype = "duration_analysis"
        operations = ["aggregate", "duration"]
    elif "topn" in calc_intents or "top" in question.lower() or "最多" in question:
        archetype = "metric_topn"
        operations = ["aggregate", "groupby", "topn"]
    elif "timeseries" in calc_intents or "趋势" in question or "每天" in question:
        archetype = "metric_trend"
        operations = ["aggregate", "trend"]
    elif "groupby" in calc_intents or "每个" in question or "各" in question:
        archetype = "metric_groupby"
        operations = ["aggregate", "groupby"]
    elif ("模板" in question or "改写" in question or "编写" in question) and not ("变量" in question and "?" in question):
        archetype = "template_generation"
        operations = ["lookup", "generation"]
    elif "变量" in question or "字段" in question or "字典" in question or "支持哪些查" in question:
        archetype = "schema_discovery"
        operations = ["discovery"]
    elif "能力" in question or "能查" in question or "目录" in question or "权限" in question or "模块" in question or "支持" in question:
        archetype = "capability_discovery"
        operations = ["discovery"]
    elif llm_understanding.get("calculation_required") or "多少" in question or "总数" in question:
        archetype = "metric_count"
        operations = ["aggregate"]
    elif "封" in question or "隔离" in question or "闭环" in question or "白名单" in question or "下线" in question or "决策" in intent:
        archetype = "decision_support"
        operations = ["lookup", "decision"]
    elif "相似" in question or "历史" in question or "经验" in question:
        archetype = "similar_case_retrieval"
        operations = ["lookup"]
    elif "风险" in question or "失陷" in question or "异常" in question or "怎么样" in question or "研判" in question or "误报" in question:
        archetype = "entity_risk_assessment"
        operations = ["lookup", "risk_assessment"]
    elif "链路" in question or "调查" in question or "路径" in question or "转" in question:
        archetype = "incident_investigation"
        operations = ["lookup"]
    elif "谁" in question or "负责" in question or "归属" in question:
        archetype = "ownership_lookup"
        operations = ["lookup"]

    return {
        "task_archetype": archetype,
        "answer_shape": llm_understanding.get("answer_shape", "text"),
        "subject": {"type": subject_type, "value": subject_value},
        "operations": operations,
        "confidence": 0.9
    }

def build_evidence_roles(task_archetype: str, subject: dict, operations: list[str], llm_understanding: dict) -> list[str]:
    roles = []
    if task_archetype == "entity_lookup":
        roles = ["subject_identity", "internal_context"]
    elif task_archetype == "ownership_lookup":
        roles = ["subject_identity", "ownership"]
    elif task_archetype == "entity_risk_assessment":
        roles = ["subject_identity", "ownership", "risk_signals", "external_intel", "decision_boundary"]
    elif task_archetype == "decision_support":
        roles = ["subject_identity", "ownership", "risk_signals", "external_intel", "policy_or_constraint", "decision_boundary"]
    elif task_archetype == "incident_investigation":
        roles = ["subject_identity", "risk_signals", "timeline", "historical_cases"]
    elif task_archetype == "metric_count":
        roles = ["tabular_data", "aggregation"]
    elif task_archetype == "metric_groupby":
        roles = ["tabular_data", "grouping"]
    elif task_archetype == "metric_trend":
        roles = ["tabular_data", "trend"]
    elif task_archetype == "metric_topn":
        roles = ["tabular_data", "ranking"]
    elif task_archetype == "duration_analysis":
        roles = ["tabular_data", "duration"]
    elif task_archetype == "capability_discovery":
        roles = ["capability_scope", "schema_scope", "permission_scope"]
    elif task_archetype == "schema_discovery":
        roles = ["schema_scope"]
    elif task_archetype == "similar_case_retrieval":
        roles = ["subject_identity", "historical_cases", "risk_signals"]
    elif task_archetype == "template_generation":
        roles = ["schema_scope", "template_variable_catalog", "template_examples", "import_contract"]
    else:
        roles = ["subject_identity"]
    return roles

def expand_roles_to_evidence_types(roles: list[str], subject_type: str, domain_hint: str = None) -> list[str]:
    types = set()
    for role in roles:
        mapping = ROLE_TO_EVIDENCE_TYPES.get(role, {})
        matched_types = mapping.get(subject_type)
        if not matched_types:
            matched_types = mapping.get("*", [])
        types.update(matched_types)
    return list(types)

def score_tool_candidate(tool_schema: dict, required_evidence_types: list[str], evidence_roles: list[str], entities: dict, params: dict, state: dict) -> dict:
    t_name = tool_schema["tool"]
    provides = tool_schema.get("output_evidence_types", [])
    
    score = 0.0
    reasons = []
    blocked = False
    block_reason = ""
    
    # 实体一致性检查
    if t_name == "alert.detail" and not entities.get("hashes") and not params.get("alert_hash") and not params.get("alert_id"):
        blocked = True
        block_reason = "缺少 alert_hash/alert_id"
    elif t_name == "alert.timeline" and not entities.get("hashes") and not params.get("alert_hash") and not params.get("alert_id"):
        blocked = True
        block_reason = "缺少 alert_hash/alert_id"
    elif t_name == "asset.get_by_ip" and not entities.get("ips") and not params.get("ip"):
        blocked = True
        block_reason = "缺少 IP"
    elif t_name in ("ti.lookup_ip", "intel.ip_report") and not entities.get("ips") and not params.get("ip"):
        # 如果是 asset_risk_assessment，且已经有 alert.search 结果，可能还没提取出 IP，先不完全 block
        if not state.get("task_model", {}).get("task_archetype") == "entity_risk_assessment":
            blocked = True
            block_reason = "缺少 IP"
        
    has_data_source = False
    for ev in state.get("evidences", []):
        if extract_tabular_rows(ev.get("data")):
            has_data_source = True
            break
            
    if t_name.startswith("analysis.") and not has_data_source:
        pass 
        
    subject_type = state.get("task_model", {}).get("subject", {}).get("type")
    if subject_type == "ip" and t_name == "alert.detail":
        blocked = True
        block_reason = "IP 粒度不应该直接调 alert.detail，请先用 alert.search"

    if blocked:
        return {"tool": t_name, "score": -1.0, "reasons": [block_reason], "blocked": True, "block_reason": block_reason}
        
    gain = set(provides).intersection(set(required_evidence_types))
    if gain:
        score += len(gain) * 10
        reasons.append(f"覆盖所需证据: {', '.join(gain)}")
        
        # 针对特定 Evidence Type 的工具优先级加分
        for g in gain:
            if g in EVIDENCE_TYPE_TOOLS and t_name in EVIDENCE_TYPE_TOOLS[g]:
                score += 5
                reasons.append(f"该工具是 {g} 的推荐工具")
                # 进一步细化：ip_intel_report 优先用 intel.ip_report
                if g == "ip_intel_report" and t_name == "intel.ip_report":
                    score += 5
                if g == "ip_reputation" and t_name == "ti.lookup_ip":
                    score += 5
        
    # 针对任务原型的特定加分
    archetype = state.get("task_model", {}).get("task_archetype")
    if archetype in ("entity_risk_assessment", "asset_risk_assessment", "decision_support", "compromise_assessment"):
        if t_name in ("ti.lookup_ip", "intel.ip_report"):
            score += 15
            reasons.append(f"风险评估任务优先考虑情报工具")
        if t_name == "alert.search":
            score += 10
            reasons.append(f"风险评估任务需要检索相关告警上下文")
            
    if archetype == "incident_investigation":
        if t_name in ("alert.timeline", "alert.detail"):
            score += 10
            reasons.append("事件调查优先查看详情和时间轴")
        if t_name == "log.raw_grep":
            score += 5
            reasons.append("事件调查辅助使用报文检索")
            
    if archetype == "similar_case_retrieval":
        if t_name == "experience.search":
            score += 15
            reasons.append("相似经验检索优先查看经验库")
        if t_name == "alert.similar_by_ip":
            score += 10
            reasons.append("相似经验检索优先查看历史同 IP 告警")

    if tool_schema.get("level") == "L1":
        score += 2
        
    if archetype == "schema_discovery" and t_name == "system.data_dictionary":
        score += 5
    if archetype == "capability_discovery" and t_name in ("system.modules", "agent.tool_registry", "system.permissions"):
        score += 5
    if archetype == "template_generation" and t_name == "template.variable_catalog":
        score += 5

    # 惩罚项：如果工具不在 EVIDENCE_TYPE_TOOLS 中且没有增益
    if not gain and t_name not in ["alert.search", "asset.search"]:
        score -= 5
        reasons.append("没有覆盖必须的证据且非基础搜索工具")
        
    return {"tool": t_name, "score": score, "reasons": reasons, "blocked": False, "block_reason": ""}

def select_tools_by_evidence_advanced(task_model: dict, required_evidence_types: list[str], tool_schemas: list[dict], state: dict) -> list[dict]:
    candidate_scores = []
    already_called = state.get("already_called_tools", set())
    
    for tool in tool_schemas:
        # 允许重复调用 TI 工具，如果发现了新 IP
        if tool["tool"] in already_called and tool["tool"] not in ("ti.lookup_ip", "intel.ip_report"):
            continue
        score_res = score_tool_candidate(tool, required_evidence_types, [], state["entities"], {}, state)
        if not score_res["blocked"] and score_res["score"] > 0:
            candidate_scores.append((score_res["score"], tool["tool"], score_res["reasons"]))
            
    candidate_scores.sort(reverse=True, key=lambda x: x[0])
    
    selected_tools = []
    missing_ev = set(required_evidence_types)
    has_data_source = any(extract_tabular_rows(e.get("data")) for e in state.get("evidences", []))
    
    for score, tool_name, reasons in candidate_scores:
        if len(selected_tools) >= 8:
            break
            
        tool_meta = next(t for t in tool_schemas if t["tool"] == tool_name)
        provides = set(tool_meta.get("output_evidence_types", []))
        
        # 如果已经有 TI 数据了，且不是为了新发现的 IP，可以跳过
        if tool_name in already_called and tool_name in ("ti.lookup_ip", "intel.ip_report"):
             # 检查是否有新 IP 还没查过
             new_ips = state["entities"].get("ips", [])
             queried_ips = state.get("ti_queried_ips", set())
             if not any(ip not in queried_ips for ip in new_ips):
                 continue

        if provides.intersection(missing_ev) or tool_name.startswith("analysis.") or tool_name in ("alert.search", "ti.lookup_ip", "intel.ip_report"): 
            selected_tools.append(tool_name)
            missing_ev -= provides
            if "tabular_dataset" in provides or "alert_list" in provides:
                has_data_source = True
                
    return selected_tools

def build_default_tool_params(tool_name: str, task_model: dict, entities: dict, state: dict, evidence_packs: list[dict]) -> dict:
    params = {}
    ips = entities.get("ips", [])
    hashes = entities.get("hashes", [])
    question = state.get("question", "")
    
    if tool_name in ("asset.get_by_ip", "asset.segment_match", "ti.lookup_ip", "intel.ip_report", "alert.similar_by_ip"):
        if ips:
            # 如果是 TI 工具，优先查询尚未查询过的 IP
            if tool_name in ("ti.lookup_ip", "intel.ip_report"):
                queried = state.get("ti_queried_ips", set())
                unqueried = [ip for ip in ips if ip not in queried]
                target_ip = unqueried[0] if unqueried else ips[0]
                
                params["ip"] = target_ip
                
                # 计算角色
                subject_ip = task_model.get("subject", {}).get("value")
                if target_ip == subject_ip:
                    params["ip_role"] = "subject"
                else:
                    is_attacker = False
                    for ev in state.get("evidences", []):
                        if ev["tool"] == "alert.search":
                            items = extract_tabular_rows(ev["data"])
                            if any(item.get("src_ip") == target_ip for item in items):
                                is_attacker = True
                                break
                    params["ip_role"] = "attacker_source" if is_attacker else "related_endpoint"
                
                # 记录即将查询的 IP
                state.setdefault("ti_queried_ips", set()).add(target_ip)
            else:
                params["ip"] = ips[0]
    elif tool_name in ("alert.detail", "alert.timeline"):
        if hashes: params["alert_hash"] = hashes[0]
    elif tool_name == "alert.search":
        subject = task_model.get("subject", {})
        if subject.get("type") == "ip":
            params["ip"] = subject.get("value")
            params["ip_match"] = "either"
        elif ips:
            params["ip"] = ips[0]
            params["ip_match"] = "either"
        elif hashes:
            params["q"] = hashes[0]
    elif tool_name == "asset.search":
        if ips: params["ip"] = ips[0]
    elif tool_name == "experience.search":
        if hashes: params["alert_hash"] = hashes[0]
        elif ips: params["q"] = ips[0]
    elif tool_name == "log.raw_grep":
        if ips: params["q"] = ips[0]
        elif hashes: params["q"] = hashes[0]
    elif tool_name == "rule.history_stats":
        # 尝试从问题中提取规则名，通常在“xxx 规则的误报率”中
        match = re.search(r"['\"‘“]?([\w\u4e00-\u9fa5]+)['\"’”]?\s*规则", question)
        if match:
            params["rule_name"] = match.group(1)
    elif tool_name == "system.data_dictionary":
        if "告警" in question: params["domain"] = "alert"
        elif "资产" in question: params["domain"] = "asset"
        elif "审计" in question: params["domain"] = "audit"
    elif tool_name == "settings.safe":
        archetype = state.get("task_model", {}).get("task_archetype")
        if archetype in ("entity_risk_assessment", "decision_support"):
            params["key"] = "ip_lists"
        else:
            params["key"] = "ai"
    # ... (rest of analysis tool logic)
    elif tool_name == "analysis.groupby":
        # ... (unchanged)
        pass
    
    # 补全分析工具逻辑 (确保不丢失)
    if tool_name == "analysis.groupby":
        question = state.get("question", "")
        if "每个人" in question or "谁" in question:
            params["group_by"] = ["assignee"]
        elif "目的 IP" in question:
            params["group_by"] = ["dst_ip"]
        elif "源 IP" in question:
            params["group_by"] = ["src_ip"]
        elif "级别" in question or "严重程度" in question:
            params["group_by"] = ["severity"]
        elif "状态" in question:
            params["group_by"] = ["status"]
        else:
            params["group_by"] = ["event_type"]
            
        params["metrics"] = [{"name": "count", "operation": "count"}]
    
    return params

def discover_entities(state: AgentState):
    """从证据中发现新实体（如从告警中提取攻击源 IP）"""
    new_ips = set(state["entities"].get("ips", []))
    new_hashes = set(state["entities"].get("hashes", []))
    
    subject_ip = None
    if state["task_model"].get("subject", {}).get("type") == "ip":
        subject_ip = state["task_model"]["subject"]["value"]

    for ev in state["evidences"]:
        if ev["tool"] == "alert.search":
            items = extract_tabular_rows(ev["data"])
            # 提取所有相关的 IP
            for item in items:
                src = item.get("src_ip")
                dst = item.get("dst_ip")
                if src: new_ips.add(src)
                if dst: new_ips.add(dst)
                if item.get("alert_hash"): new_hashes.add(item["alert_hash"])
        
        elif ev["tool"] == "evidence.extract_ioc":
            data = ev.get("data", {})
            for ip in data.get("ips", []): new_ips.add(ip)
            for h in data.get("hashes", []): new_hashes.add(h)

    # 更新实体列表
    state["entities"]["ips"] = sorted(list(new_ips))
    state["entities"]["hashes"] = sorted(list(new_hashes))
    
    # 特殊逻辑：针对资产风险评估，如果 subject 是 IP，且发现了多个 IP，
    # 我们可能需要对攻击源 IP 进行 TI 查询
    if state["task_model"]["task_archetype"] in ("entity_risk_assessment", "asset_risk_assessment"):
        # 已经在 build_default_tool_params 中处理了按顺序查询 unqueried IP 的逻辑
        pass

def normalize_entities(text: str) -> dict[str, Any]:
    entities = {
        "ips": sorted(list(set(IP_RE.findall(text)))),
        "hashes": sorted(list(set(HASH_RE.findall(text)))),
        "dates": sorted(list(set(DATE_RE.findall(text)))),
        "cves": sorted(list(set(CVE_RE.findall(text))))
    }
    return enrich_entities(entities)


# --- 2. Task Understanding (意图理解与证据需求推导) ---
async def understand_task(db: Session, user: User, question: str, entities: dict[str, Any], ai_settings: dict[str, Any]) -> dict[str, Any]:
    prompt = (
        "你是安全运营专家。你的任务是分析用户的自然语言提问，并进行【任务建模】与【证据需求推导】。\n"
        "### 核心准则：\n"
        "1. **任务建模**：判断用户的最终目标，是需要事实核查、列表检索、统计分析、趋势观察、还是能力咨询。\n"
        "2. **证据需求推导**：根据目标推导需要的 evidence_types。如果是统计类任务，必须包含 analysis 类 evidence 类型。\n"
        "3. **计算识别**：如果任务涉及 count, group by, top n, timeseries, duration, percentage，必须设置 calculation_required=true，并在 calculation_intents 中注明。\n"
        "4. **禁止心算**：明确任何统计数字必须由工具产出，不能由 LLM 自己心算。\n"
        "### 候选 Evidence Types:\n"
        f"{', '.join(sorted(list(EVIDENCE_TYPES)))}\n"
        "### 输出 JSON 格式：\n"
        "{\n"
        "  \"intent\": \"意图编码\",\n"
        "  \"user_goal\": \"用户核心诉求总结\",\n"
        "  \"required_resources\": [\"需要调用的数据分类\"],\n"
        "  \"required_evidence_types\": [\"必须具备的证据类型\"],\n"
        "  \"optional_evidence_types\": [\"可选的辅助证据类型\"],\n"
        "  \"calculation_required\": true/false,\n"
        "  \"calculation_intents\": [\"aggregate\", \"groupby\", \"timeseries\", \"topn\", \"duration\", \"percentage\"],\n"
        "  \"answer_shape\": \"回答的结构形式 (list/table/metric/text/trend/capability_catalog)\",\n"
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
        return parse_json_object(content) or {"intent": "unknown", "need_user_input": False}
    except Exception:
        return {"intent": "unknown", "need_user_input": False}


def select_tools_by_evidence(required_evidence_types: list[str], tool_schemas: list[dict[str, Any]], already_called: set[str] | None = None, evidence_packs: list[dict] | None = None) -> list[str]:
    """根据证据缺口选择工具"""
    if not required_evidence_types:
        return []
    
    selected_tools = []
    missing = set(required_evidence_types)
    called = already_called or set()
    
    # 特殊映射：Analysis 工具
    analysis_map = {
        "aggregation_result": "analysis.aggregate",
        "derived_metric": "analysis.aggregate",
        "groupby_result": "analysis.groupby",
        "timeseries_result": "analysis.timeseries",
        "topn_result": "analysis.topn",
        "duration_metric": "analysis.duration"
    }
    
    # 1. 优先处理 Analysis 工具，但它们依赖前置数据
    has_data_source = False
    if evidence_packs:
        for ev in evidence_packs:
            if extract_tabular_rows(ev.get("data")):
                has_data_source = True
                break
                
    # 2. 贪婪算法选择能覆盖最多 missing evidence 的工具
    iteration = 0
    while missing and iteration < 5:
        iteration += 1
        best_tool = None
        best_gain = set()
        
        for tool in tool_schemas:
            t_name = tool["tool"]
            if t_name in selected_tools or t_name in called:
                continue
                
            # Analysis 工具特殊检查
            if t_name.startswith("analysis.") and not has_data_source:
                # 检查当前 selected_tools 里是否已经有了能提供数据的工具
                will_have_data = False
                for s_t in selected_tools:
                    s_meta = next((m for m in tool_schemas if m["tool"] == s_t), {})
                    if "tabular_dataset" in s_meta.get("output_evidence_types", []) or "alert_list" in s_meta.get("output_evidence_types", []):
                        will_have_data = True
                        break
                if not will_have_data:
                    continue

            provides = set(tool.get("output_evidence_types", []))
            gain = provides.intersection(missing)
            
            if len(gain) > len(best_gain):
                best_tool = t_name
                best_gain = gain
            elif len(gain) == len(best_gain) and best_tool:
                # 同等增益下，优先 L1
                if tool["level"] == "L1":
                    best_tool = t_name
        
        if best_tool:
            selected_tools.append(best_tool)
            missing -= best_gain
        else:
            break
            
    return selected_tools[:8]


# --- 3. AI Planner (路径规划) ---
async def generate_plan(db: Session, user: User, state: AgentState, tool_schemas: list[dict[str, Any]], ai_settings: dict[str, Any]) -> dict[str, Any]:
    # 1. 自动选择候选工具
    candidate_tool_names = select_tools_by_evidence_advanced(
        state.get("task_model", {}),
        state.get("missing_evidence_types") or state.get("required_evidence_types", []),
        tool_schemas,
        state
    )
    
    if not candidate_tool_names and not state.get("repair_actions"):
        return {"tool_calls": []}

    candidate_schemas = [t for t in tool_schemas if t["tool"] in candidate_tool_names]
    
    prompt = (
        "你是安全运营查询规划专家。你的任务是为【候选工具】补充精准的调用参数和理由。\n"
        "### 规划准则：\n"
        "1. **精准参数**：基于识别到的实体（IP, Hash, 时间）为工具补充参数。不要臆造不存在的数据。\n"
        "2. **分析工具处理**：如果是 analysis.* 工具，必须根据问题推导 group_by, metrics, time_field, interval, operation 等参数。严禁空参数调用分析工具。\n"
        "3. **定向修复**：如果存在 repair_actions，请优先确保修复动作被执行。\n"
        "4. **安全红线**：严禁请求敏感字段。\n"
        "### 输出 JSON 格式：\n"
        "{\"objective\":\"规划目标描述\", \"tool_calls\":[{\"tool\":\"工具名\", \"params\":{}, \"reason\":\"为什么要调用这个工具\"}]}"
    )
    
    ctx = {
        "question": state["question"],
        "understanding": state["understanding"],
        "entities": state["entities"],
        "candidate_tools": candidate_schemas,
        "missing_evidence_types": state.get("missing_evidence_types", []),
        "repair_actions": state.get("repair_actions", []),
        "existing_evidence_summary": [f"{e['tool']}({e['evidence_id']}): {e['summary']}" for e in state["evidences"]]
    }
    
    try:
        content = await asyncio.to_thread(chat_completion, [
            {"role": "system", "content": prompt},
            {"role": "user", "content": json.dumps(ctx, ensure_ascii=False)}
        ], ai_settings, temperature=0)
        plan = parse_json_object(content) or {"tool_calls": []}
        
        # 兜底：确保 LLM 产出的工具确实在候选名单中，或者在 repair_actions 中
        allowed_tools = set(candidate_tool_names)
        for ra in state.get("repair_actions", []):
            if ra.get("tool"): allowed_tools.add(ra["tool"])
            
        validated_calls = []
        for call in plan.get("tool_calls", []):
            if call.get("tool") in allowed_tools:
                # 智能默认参数补充
                t_name = call["tool"]
                params = call.get("params", {})
                default_params = build_default_tool_params(t_name, state.get("task_model", {}), state.get("entities", {}), state, state.get("evidences", []))
                for k, v in default_params.items():
                    if k not in params:
                        params[k] = v
                call["params"] = params
                validated_calls.append(call)
        
        plan["tool_calls"] = validated_calls
        return plan
    except Exception:
        return {"tool_calls": []}


# --- 4. Plan Validator (确定性校准) ---
def validate_plan(plan: dict[str, Any], tool_schemas: list[dict[str, Any]]) -> dict[str, Any]:
    valid_names = {t["tool"] for t in tool_schemas}
    validated_calls = []
    for call in plan.get("tool_calls", []):
        if call.get("tool") in valid_names:
            validated_calls.append(call)
    plan["tool_calls"] = validated_calls
    return plan


# --- 5. Tool Executor (证据提取) ---
async def execute_plan(db: Session, user: User, plan: dict[str, Any], evidence_packs: list[dict]) -> list[dict[str, Any]]:
    new_evidences = []
    for call in plan.get("tool_calls", [])[:8]:
        tool_name = call["tool"]
        params = call.get("params", {})
        
        if tool_name.startswith("analysis."):
            # Analysis 工具特殊处理
            result = execute_analysis_tool(tool_name, params, evidence_packs + new_evidences)
        else:
            # 业务工具调用原始 execute_tool
            result = await asyncio.to_thread(execute_tool, db, user, tool_name, params)
            
        new_evidences.append(result)
    return new_evidences


# --- 6. Quality Control (质量控制与反思) ---

def extract_collected_evidence_types(evidences: list[dict]) -> set[str]:
    types = set()
    for ev in evidences:
        for t in ev.get("evidence_types", []):
            types.add(t)
    return types


def check_evidence_coverage(required_evidence_types: list[str], evidences: list[dict]) -> dict:
    if not required_evidence_types:
        return {"sufficient": True, "covered": [], "missing": [], "risks": []}
        
    collected = extract_collected_evidence_types(evidences)
    
    # 增强检查：如果证据包里已经有 TI 数据，即使 evidence_types 里没写，也认为覆盖了
    for ev in evidences:
        data = ev.get("data", {})
        # 检查 ti.lookup_ip 或 intel.ip_report 的返回结构
        if ev["tool"] in ("ti.lookup_ip", "intel.ip_report"):
            ti_data = data.get("result") or data.get("threat_intelligence") or data
            if isinstance(ti_data, dict) and (ti_data.get("is_malicious") is not None or ti_data.get("severity")):
                collected.add("ip_reputation")
                collected.add("threat_intelligence")
            if isinstance(ti_data, dict) and ti_data.get("threat_events"):
                collected.add("threat_event")
        if ev["tool"] == "intel.ip_report":
            collected.add("ip_intel_report")

    required = set(required_evidence_types)
    
    covered = list(required.intersection(collected))
    missing = list(required - collected)
    
    risks = []
    for ev in evidences:
        if ev.get("status") in ("error", "denied"):
            risks.append(f"工具 {ev['tool']} 执行受限: {ev['summary']}")
        if ev.get("warnings"):
            risks.extend(ev["warnings"])
            
    # 特殊逻辑：如果有分析需求但没数据源
    analysis_needs = {"aggregation_result", "groupby_result", "timeseries_result", "topn_result", "duration_metric"}
    if required.intersection(analysis_needs) and not any(extract_tabular_rows(e.get("data")) for e in evidences):
        risks.append("需要执行分析计算，但尚未获取到可用的原始数据列表。")
        
    return {
        "sufficient": len(missing) == 0,
        "coverage_score": len(covered) / len(required) if required else 1.0,
        "covered": covered,
        "missing": missing,
        "risks": risks,
        "replan_needed": len(missing) > 0
    }


async def structured_reflector(db: Session, user: User, state: AgentState, ai_settings: dict[str, Any]) -> dict[str, Any]:
    """结构化反思器"""
    
    # 阶段 1: Coverage Check (代码实现)
    coverage = check_evidence_coverage(state["understanding"].get("required_evidence_types", []), state["evidences"])
    
    # 阶段 2 & 3: Groundedness & Computation Check (LLM 实现)
    prompt = (
        "你是安全对话核验专家（Reflector）。你的任务是严审 AI 的回答草稿，输出结构化 issue 和 repair_actions。\n"
        "### 核验阶段：\n"
        "1. **Groundedness**：检查每一项事实或指标是否有 evidence 支撑。严禁脑补。\n"
        "2. **Computation**：检查统计数字是否来自 analysis.* 工具的证据。如果是 LLM 自己数出来的，必须判为 issue。\n"
        "3. **Style**：检查是否暴露了敏感字段，是否回答太绝对。\n"
        "### 输出 JSON 格式：\n"
        "{\n"
        "  \"pass\": true/false,\n"
        "  \"quality_score\": 0.0-1.0,\n"
        "  \"failure_stage\": \"groundedness | computation | answer_style | none\",\n"
        "  \"issues\": [{\"type\": \"...\", \"severity\": \"low/medium/high\", \"message\": \"...\"}],\n"
        "  \"repair_actions\": [\n"
        "    {\"action\": \"run_tool | run_analysis | revise_answer | ask_user\", \"tool\": \"可选\", \"params_hint\": {}, \"instruction\": \"针对改写的建议\"}\n"
        "  ],\n"
        "  \"can_repair_without_tools\": true/false,\n"
        "  \"final_answer_allowed\": true/false\n"
        "}"
    )
    
    ctx = {
        "question": state["question"],
        "evidences": [{"id": e["evidence_id"], "tool": e["tool"], "types": e["evidence_types"], "summary": e["summary"], "data": e["data"]} for e in state["evidences"]],
        "draft": state["final_answer"],
        "coverage_result": coverage,
        "is_template_task": state["task_model"].get("task_archetype") == "template_generation"
    }
    
    try:
        content = await asyncio.to_thread(chat_completion, [
            {"role": "system", "content": prompt + "\n### Template Task Rules:\n1. 如果是模板生成任务，严禁向用户索要变量列表，除非 variable_catalog 为空。\n2. 生成的模板必须包含可导入的 JSON 结构。\n3. 必须核对变量是否在 catalog 中。"},
            {"role": "user", "content": json.dumps(ctx, ensure_ascii=False)}
        ], ai_settings, temperature=0)
        
        result = parse_json_object(content) or {"pass": True}
        
        # 合并代码检查的 coverage 结果
        if not coverage["sufficient"]:
            result["pass"] = False
            result["failure_stage"] = "coverage"
            for m in coverage["missing"]:
                result.setdefault("issues", []).append({
                    "type": "coverage_missing",
                    "severity": "high",
                    "message": f"缺失必要证据类型: {m}"
                })
                # 尝试推断补救工具
                if m.startswith("analysis.") or m in ("groupby_result", "timeseries_result", "topn_result", "aggregation_result", "duration_metric"):
                    result.setdefault("repair_actions", []).append({"action": "run_analysis", "depends_on_evidence_type": m})
                else:
                    result.setdefault("repair_actions", []).append({"action": "run_tool", "depends_on_evidence_type": m})
        
        return result
    except Exception:
        return {"pass": True, "final_answer_allowed": True}


async def stream_chat_agent(db: Session, user: User, conversation_id: int, question: str) -> AsyncGenerator[str, None]:
    """
    全量重构的 Agent 循环：任务建模 -> 证据提取 -> 计算分析 -> 覆盖检查 -> 结构化反思 -> 定向修复
    """
    ev = safe_sse_event("trace", "Agent 启动：正在加载上下文...")
    if ev: yield ev
    
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
        "tool_repair_rounds": 0,
        "answer_repair_rounds": 0,
        "error_context": "",
        "status": "continue",
        "required_evidence_types": [],
        "missing_evidence_types": [],
        "repair_actions": [],
        "already_called_tools": set(),
        "ti_queried_ips": set()
    }

    ai_settings = get_effective_setting(db, user.workspace_id, user.id, "ai")
    if not ai_settings:
        ev = safe_sse_event("final_answer", "AI 网关未配置，请先在系统设置中配置。")
        if ev: yield ev
        return

    # 步骤 1：Task Modeling
    yield json.dumps({"event": "trace", "data": "AI 正在建立任务模型与证据需求..."})
    state["understanding"] = await understand_task(db, user, question, entities, ai_settings)
    state["task_model"] = classify_task_archetype(question, entities, state["understanding"])
    evidence_roles = build_evidence_roles(state["task_model"]["task_archetype"], state["task_model"]["subject"], state["task_model"]["operations"], state["understanding"])
    state["required_evidence_types"] = list(set(state["understanding"].get("required_evidence_types", []) + expand_roles_to_evidence_types(evidence_roles, state["task_model"]["subject"]["type"])))
    
    if state["understanding"].get("need_user_input"):
        yield json.dumps({"event": "final_answer", "data": state["understanding"].get("user_question") or "需要更多信息才能回答。"})
        return

    if state["required_evidence_types"]:
        yield json.dumps({"event": "trace", "data": f"需要证据类型：{', '.join(state['required_evidence_types'])}"})

    tool_schemas = get_tool_schemas(user)
    
    # 主循环 (工具修复轮次上限 2)
    while state["tool_repair_rounds"] <= 2:
        state["iteration"] += 1
        
        # 步骤 2：Planning
        yield json.dumps({"event": "trace", "data": f"第 {state['iteration']} 轮规划：正在根据证据缺口选择工具..."})
        plan = await generate_plan(db, user, state, tool_schemas, ai_settings)
        state["plan"] = validate_plan(plan, tool_schemas)
        
        if not state["plan"].get("tool_calls"):
            yield json.dumps({"event": "trace", "data": "未规划出有效工具，尝试根据已有信息回答..."})
            break
        else:
            # 步骤 3：Executing
            for call in state["plan"]["tool_calls"]:
                yield json.dumps({"event": "trace", "data": f"正在执行：{call['tool']} ({call.get('reason','')})"})
                state["already_called_tools"].add(call["tool"])
            
            new_evidences = await execute_plan(db, user, state["plan"], state["evidences"])
            state["evidences"].extend(new_evidences)
            
            # 关键：实体发现（从结果中提取新 IP 等）
            discover_entities(state)
        
        # 步骤 4：Coverage Checking
        yield json.dumps({"event": "trace", "data": "正在检查证据覆盖度..."})
        coverage = check_evidence_coverage(state["required_evidence_types"], state["evidences"])
        state["missing_evidence_types"] = coverage["missing"]
        
        if coverage["sufficient"]:
            yield json.dumps({"event": "trace", "data": f"证据覆盖度：{coverage['coverage_score']:.1%}，证据充足。"})
            break
        else:
            state["tool_repair_rounds"] += 1
            if state["tool_repair_rounds"] > 2:
                yield json.dumps({"event": "trace", "data": f"达到修复上限，当前覆盖度：{coverage['coverage_score']:.1%}, 缺失：{', '.join(coverage['missing'])}"})
                break
            yield json.dumps({"event": "trace", "data": f"证据不足，缺失：{', '.join(coverage['missing'])}，准备第 {state['tool_repair_rounds']} 轮补足..."})

    # 步骤 5：Answering
    yield json.dumps({"event": "trace", "data": "正在基于计算结果生成回答..."})
    
    prompt_config = get_prompt(db, user.workspace_id, "chat")
    
    # 构造回答生成上下文
    coverage_info = check_evidence_coverage(state["required_evidence_types"], state["evidences"])
    
    answer_context = {
        "question": question,
        "task_understanding": state["understanding"],
        "coverage_result": coverage_info,
        "evidences": [{"id": e["evidence_id"], "tool": e["tool"], "types": e["evidence_types"], "summary": e["summary"], "data": e["data"]} for e in state["evidences"]]
    }
    
    llm_messages = [
        {
            "role": "system", 
            "content": (
                f"{prompt_config['system']}\n"
                "### 回答准则：\n"
                "1. **证据驱动**：必须且仅能基于提供的 Evidence Pack 回答。严禁编造数据或结论。\n"
                "2. **统计一致性**：所有 count, percentage, average, top n, groupby 等统计数据必须取自 analysis.* 证据或聚合工具。严禁 LLM 自己数原始列表。\n"
                "3. **Claim-First**：在脑海中先建立 [Claim -> Evidence ID] 的映射关系。如果某个断言没有证据 ID 支持，请不要说出来。\n"
                "4. **透明性**：如果证据不充分或受到分页限制，必须在回答中如实说明限制。\n"
                "5. **脱敏**：继续遵守敏感字段脱敏规则，不要输出未脱敏的敏感信息。\n"
                "6. **专业语气**：保持安全运营专家的专业、简洁、客观语气。"
            )
        },
        {"role": "user", "content": f"上下文及证据：{json.dumps(answer_context, ensure_ascii=False)}"}
    ]
    
    # 步骤 6：Verification & Repair
    while state["answer_repair_rounds"] <= 1:
        # 生成草稿
        state["final_answer"] = await asyncio.to_thread(chat_completion, llm_messages, ai_settings, temperature=0.3)
        
        yield json.dumps({"event": "trace", "data": "正在进行事实一致性与计算结果检查..."})
        reflection = await structured_reflector(db, user, state, ai_settings)
        
        if reflection.get("pass") or state["answer_repair_rounds"] >= 1:
            if not reflection.get("pass"):
                yield json.dumps({"event": "trace", "data": "已达到修复上限，将输出带限制说明的答案。"})
            else:
                yield json.dumps({"event": "trace", "data": "回答已通过核验，正在输出..."})
            
            # 最终输出
            async for token in async_chat_stream(llm_messages, ai_settings, temperature=0.3):
                ev = safe_sse_event("token", token)
                if ev:
                    yield ev
            break
        else:
            state["answer_repair_rounds"] += 1
            state["repair_actions"] = reflection.get("repair_actions", [])
            yield json.dumps({"event": "trace", "data": f"核验发现问题：{reflection.get('failure_stage')}，正在执行定向修复..."})
            
            # 补丁：支持从反思跳回工具执行
            needs_more_tools = any(ra.get("action") in ("run_tool", "run_analysis") for ra in state["repair_actions"])
            if needs_more_tools and state["tool_repair_rounds"] <= 2:
                yield json.dumps({"event": "trace", "data": "根据反思反馈，需要补查更多数据..."})
                state["iteration"] += 1
                state["tool_repair_rounds"] += 1
                # 重新规划并执行
                plan = await generate_plan(db, user, state, tool_schemas, ai_settings)
                state["plan"] = validate_plan(plan, tool_schemas)
                if state["plan"].get("tool_calls"):
                    for call in state["plan"]["tool_calls"]:
                        yield json.dumps({"event": "trace", "data": f"定向补查：{call['tool']}"})
                    new_evidences = await execute_plan(db, user, state["plan"], state["evidences"])
                    state["evidences"].extend(new_evidences)
                    # 更新上下文准备重新生成草稿
                    answer_context["evidences"] = [{"id": e["evidence_id"], "tool": e["tool"], "types": e["evidence_types"], "summary": e["summary"], "data": e["data"]} for e in state["evidences"]]
                    llm_messages[-1]["content"] = f"上下文及证据：{json.dumps(answer_context, ensure_ascii=False)}"
                    continue

            if reflection.get("can_repair_without_tools"):
                llm_messages.append({"role": "assistant", "content": state["final_answer"]})
                llm_messages.append({"role": "user", "content": f"核验反馈：{json.dumps(reflection['issues'], ensure_ascii=False)}\n请根据反馈修正回答。"})
            else:
                # 这种复杂情况本版暂不跳回最外层 while，只做文案修正提示
                llm_messages.append({"role": "user", "content": f"注意：核验发现由于缺失部分证据，回答可能不完整。请在回答中明确说明限制。"})

    for ev_type, ev_data in [
        ("evidences", state["evidences"]),
        ("final_answer", state["final_answer"]),
        ("completion", "done")
    ]:
        ev = safe_sse_event(ev_type, ev_data)
        if ev:
            yield ev
