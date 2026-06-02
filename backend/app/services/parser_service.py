from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any
from datetime import datetime

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models.entities import Device, ParseRule, Template, User
from app.models.entities import Setting
from app.services.asset_service import asset_summary_fields, build_asset_context, lookup_asset_by_ip
from app.services.template_service import render_template
from app.services.stats_service import get_aggregate_stats
from app.services.workflow_constants import DISPOSAL_TARGET_LABELS, DISPOSAL_ACTION_LABELS

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.config import get_default_config  # noqa: E402
from core.parser import parse_log, parse_text  # noqa: E402
from core.lists import is_ip_in_list  # noqa: E402
from output.formatter import render_chat, render_excel  # noqa: E402


def _base_config() -> dict[str, Any]:
    return get_default_config()


def _rules_to_config(rules: list[ParseRule]) -> dict[str, Any]:
    cfg = _base_config()
    five: dict[str, list[str]] = {}
    extra: dict[str, dict[str, Any]] = {}
    static: dict[str, str] = {}
    known = {"src_ip", "dst_ip", "event_type", "request", "response", "payload", "protocol", "src_port", "dst_port"}
    for rule in sorted(rules, key=lambda item: item.priority):
        if not rule.enabled:
            continue
        if rule.match_type == "builtin":
            static[rule.field_key] = rule.pattern
        elif rule.field_key in known:
            five.setdefault(rule.field_key, []).append(rule.pattern)
        else:
            extra.setdefault(rule.field_key, {"enabled": True, "patterns": []})["patterns"].append(rule.pattern)
    if five:
        cfg["regex"]["five_tuple"] = five
    if extra:
        cfg["regex"]["extra_fields"] = extra
    cfg["static_fields"] = static
    return cfg


def _builtin_value(rule: ParseRule, user: User, device: Device | None = None) -> str:
    key = (rule.pattern or "").strip()
    now = datetime.now()
    values = {
        "current_time": now.strftime("%Y-%m-%d %H:%M:%S"),
        "current_date": now.strftime("%Y-%m-%d"),
        "current_user": user.display_name or user.username,
        "current_username": user.username,
        "workspace_id": str(user.workspace_id),
        "current_device": device.name if device else "",
        "current_device_vendor": device.vendor if device else "",
        "current_device_product": device.product if device else "",
        "current_device_version": device.version if device else "",
    }
    return values.get(key, "")


def _normalize_ip(value: Any) -> str:
    match = re.search(r"(?:\d{1,3}\.){3}\d{1,3}", str(value or ""))
    return match.group(0) if match else str(value or "")


def _extract_value(rule: ParseRule, text: str, user: User, device: Device | None) -> str | None:
    if rule.match_type == "fixed":
        return rule.pattern
    if rule.match_type == "builtin":
        return _builtin_value(rule, user, device)
    if rule.match_type == "regex":
        try:
            reg = re.compile(rule.pattern, re.S)
            if getattr(rule, "match_all", False):
                matches = list(reg.finditer(text))
                if matches:
                    results = []
                    for m in matches:
                        results.append(m.group(1) if m.groups() else m.group(0))
                    return ", ".join(results)
            else:
                m = reg.search(text)
                if m:
                    return m.group(1) if m.groups() else m.group(0)
        except re.error:
            pass
    return None


def _regex_matches(rule: ParseRule, text: str) -> bool:
    if rule.match_type != "regex":
        return False
    try:
        return bool(re.search(rule.pattern, text, re.S))
    except re.error:
        return False


def _get_workspace_device(db: Session, user: User, device_id: int | None) -> Device | None:
    if not device_id:
        return None
    device = db.get(Device, device_id)
    if not device or device.workspace_id != user.workspace_id:
        raise HTTPException(status_code=400, detail="设备不存在")
    return device


def _get_compatible_template(
    db: Session,
    user: User,
    template_id: int | None,
    device_id: int | None,
) -> Template | None:
    if not template_id:
        return None
    template = db.get(Template, template_id)
    if not template or template.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="模板不存在")
    if template.device_id and template.device_id != device_id:
        raise HTTPException(status_code=400, detail="模板不适用于当前设备")
    return template


def parse_text_for_user(
    db: Session,
    user: User,
    text: str,
    device_id: int | None = None,
    message_template_id: int | None = None,
    excel_template_id: int | None = None,
) -> dict[str, Any]:
    query = db.query(ParseRule).filter(ParseRule.workspace_id == user.workspace_id, ParseRule.enabled.is_(True))
    if device_id:
        query = query.filter((ParseRule.device_id == device_id) | (ParseRule.device_id.is_(None)))
    
    device = _get_workspace_device(db, user, device_id)
    all_rules = query.all()
    
    # 1. 规则优先级校验与分组
    rules_by_key: dict[str, list[ParseRule]] = {}
    for r in all_rules:
        rules_by_key.setdefault(r.field_key, []).append(r)
    
    data: dict[str, Any] = {}
    semantic_data: dict[str, Any] = {}
    
    # 注入基础环境变量
    base_values = {
        "current_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "current_date": datetime.now().strftime("%Y-%m-%d"),
        "current_user": user.display_name or user.username,
        "current_username": user.username,
        "workspace_id": str(user.workspace_id),
        "current_device": device.name if device else "通用设备",
        "device_name": device.name if device else "通用设备",
        "current_device_vendor": device.vendor if device else "Generic",
        "current_device_product": device.product if device else "Security Device",
        "current_device_version": device.version if device else "v1.0",
        "assignee_name": "未分配",
        "status_label": "研判中",
        "raw_text": text,
        "alert_code": "",
        "alert_hash": "",
        "ti_result": "",
        "ai_result": "",
        "src_ip_location": "",
        "dst_ip_location": "",
        "project_name": "",
        "created_by_name": user.display_name or user.username,
        "last_updated_by_name": user.display_name or user.username,
    }
    data.update(base_values)
    
    # 语义化映射系统字段
    semantic_builtins = {
        "告警ID": data["alert_code"],
        "告警Hash": data["alert_hash"],
        "创建人": data["created_by_name"],
        "最后更新人": data["last_updated_by_name"],
        "负责人": data["assignee_name"],
        "状态": data["status_label"],
        "当前时间": data["current_time"],
        "当前日期": data["current_date"],
        "设备名称": data["device_name"],
        "设备厂商": data["current_device_vendor"],
        "设备产品": data["current_device_product"],
        "设备版本": data["current_device_version"],
        "登录用户名称": data["current_user"],
        "登录用户名": data["current_username"],
        "项目名称": data["project_name"],
        "原始日志": data["raw_text"],
        "AI 研判结果": data["ai_result"],
        "威胁情报结果": data["ti_result"],
    }
    semantic_data.update(semantic_builtins)
    
    # 注入全局统计信息
    try:
        stats = get_aggregate_stats(db, user.workspace_id)
        semantic_data.update(stats)
    except Exception:
        pass

    # 2. 字段提取逻辑
    meta_keys = {"event_type", "alert_time", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "request", "response", "payload", "domain"}
    
    for field_key, rules in rules_by_key.items():
        sorted_rules = sorted(rules, key=lambda x: (x.is_meta, x.priority))
        
        if field_key == "other":
            for r in rules:
                val = _extract_value(r, text, user, device)
                if val:
                    data[f"other_{r.id}"] = val
                    semantic_data[r.name] = val
            continue

        for rule in sorted_rules:
            value = _extract_value(rule, text, user, device)
            if value:
                # 只在主字典存入优先级最高的一个值
                if field_key not in data:
                    data[field_key] = value
                # 语义化字典存入所有命中的规则名，方便不同命名的模板引用
                semantic_data[rule.name] = value

    # 确保 10 种元字段即使没匹配到也存在（空字符串）
    for mk in meta_keys:
        if mk not in data:
            data[mk] = ""

    # 3. IP 归一化与情报检测
    for ip_key in ("src_ip", "dst_ip"):
        if data.get(ip_key):
            data[ip_key] = _normalize_ip(data[ip_key])
            
    ip_list_setting = db.query(Setting).filter_by(workspace_id=user.workspace_id, key="ip_lists").first()
    ip_lists = ip_list_setting.value if ip_list_setting else {"whitelist": [], "blacklist": []}
    ip_list_alerts = []
    for key, label in (("src_ip", "源IP"), ("dst_ip", "目的IP")):
        val = data.get(key)
        if val and is_ip_in_list(str(val), ip_lists.get("whitelist", [])):
            ip_list_alerts.append({"field": key, "label": label, "ip": str(val), "list": "whitelist", "message": f"{label} {val} 命中白名单"})
        if val and is_ip_in_list(str(val), ip_lists.get("blacklist", [])):
            ip_list_alerts.append({"field": key, "label": label, "ip": str(val), "list": "blacklist", "message": f"{label} {val} 命中黑名单"})

    # 4. 资产关联：个体优先，网段兜底，最后域名
    def _find_asset(ip_val: str | None, domain_val: str | None) -> dict[str, Any]:
        from app.services.asset_service import lookup_asset_by_ip, lookup_asset_by_domain, lookup_asset_by_segment, build_asset_context, build_segment_context
        
        ip_val = (ip_val or "").strip()
        domain_val = (domain_val or "").strip()
        
        # 1. 尝试按 IP 匹配个体资产
        if ip_val:
            asset_obj = lookup_asset_by_ip(db, user.workspace_id, ip_val)
            if asset_obj:
                return build_asset_context(asset_obj)
        
        # 2. 尝试按域名匹配个体资产
        if domain_val:
            asset_obj = lookup_asset_by_domain(db, user.workspace_id, domain_val)
            if asset_obj:
                return build_asset_context(asset_obj)
        
        # 3. 尝试按 IP 匹配网段资产（兜底）
        if ip_val:
            seg_obj = lookup_asset_by_segment(db, user.workspace_id, ip_val)
            if seg_obj:
                return build_segment_context(seg_obj)
        
        return {}

    final_domain = str(data.get("domain") or "").strip()

    src_asset = _find_asset(str(data.get("src_ip") or ""), None)
    dst_asset = _find_asset(str(data.get("dst_ip") or ""), final_domain)

    asset_context = {"src_asset": src_asset, "dst_asset": dst_asset}
    data["asset_context"] = asset_context
    data["src_asset_context"] = src_asset
    data["dst_asset_context"] = dst_asset
    data.update(asset_summary_fields("src", src_asset))
    data.update(asset_summary_fields("dst", dst_asset))

    # 注入语义化资产信息
    semantic_data.update({
        "源资产名称": src_asset.get("name", ""),
        "源资产区域": src_asset.get("area", ""),
        "源资产负责人": src_asset.get("owner", ""),
        "源资产重要性": src_asset.get("criticality", ""),
        "源资产环境": src_asset.get("environment", ""),
        "源资产指纹": json.dumps(src_asset.get("fingerprints", {}), ensure_ascii=False),
        "目的资产名称": dst_asset.get("name", ""),
        "目的资产区域": dst_asset.get("area", ""),
        "目的资产负责人": dst_asset.get("owner", ""),
        "目的资产重要性": dst_asset.get("criticality", ""),
        "目的资产环境": dst_asset.get("environment", ""),
        "目的资产指纹": json.dumps(dst_asset.get("fingerprints", {}), ensure_ascii=False),
        "源IP地理位置": data.get("src_ip_location", ""),
        "目的IP地理位置": data.get("dst_ip_location", ""),
        "处置对象": DISPOSAL_TARGET_LABELS.get(data.get("disposal_target", ""), data.get("disposal_target", "")),
        "处置动作": DISPOSAL_ACTION_LABELS.get(data.get("disposal_action", ""), data.get("disposal_action", "")),
    })

    # 4. 可选的渲染模板
    # 注入字段名称映射
    field_labels = {r.field_key: r.field_label for r in all_rules if r.field_label}
    cfg = _base_config()
    cfg["fields"] = field_labels

    template_query = db.query(Template).filter_by(workspace_id=user.workspace_id)
    if device_id:
        template_query = template_query.filter((Template.device_id == device_id) | (Template.device_id.is_(None)))
    else:
        template_query = template_query.filter(Template.device_id.is_(None))
    
    db_templates = template_query.all()
    for item in db_templates:
        data[f"template_{item.id}"] = render_template(item.content, semantic_data)

    message_template = _get_compatible_template(db, user, message_template_id, device_id)
    excel_template = _get_compatible_template(db, user, excel_template_id, device_id)

    formatted_chat = render_template(message_template.content, semantic_data) if message_template else render_chat(data, cfg)
    formatted_excel = render_template(excel_template.content, semantic_data) if excel_template else render_excel(data, cfg)
    
    return {
        "parsed_fields": data,
        "matched_rules": [{"id": r.id, "name": r.name, "field_key": r.field_key} for r in all_rules if _regex_matches(r, text)],
        "formatted_chat": formatted_chat,
        "formatted_excel": formatted_excel,
        "ip_list_alerts": ip_list_alerts,
        "asset_context": asset_context,
        "warnings": []
    }


def generate_candidate_rules(sample_log: str) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    patterns = {
        "src_ip": [r"源IP[:：]?\s*((?:\d{1,3}\.){3}\d{1,3})", r"src[_ -]?ip[=:：]\s*((?:\d{1,3}\.){3}\d{1,3})"],
        "dst_ip": [r"目的IP[:：]?\s*((?:\d{1,3}\.){3}\d{1,3})", r"dst[_ -]?ip[=:：]\s*((?:\d{1,3}\.){3}\d{1,3})"],
        "event_type": [r"事件(?:类型|名称|分类)[:：]\s*([^\n]+)", r"attack[_ -]?type[=:：]\s*([^\n]+)"],
        "request": [r"请求(?:内容|体)?[:：]\s*([\s\S]+?)(?:\n\s*响应|$)"],
        "response": [r"响应(?:内容|体)?[:：]\s*([\s\S]+?)(?:\n{2,}|$)"],
        "payload": [r"载荷[:：]?\s*([\s\S]+?)(?:\n{2,}|$)"],
    }
    for field, pats in patterns.items():
        for pattern in pats:
            try:
                if re.search(pattern, sample_log, re.S | re.I):
                    candidates.append(
                        {
                            "name": f"自动生成-{field}",
                            "field_key": field,
                            "field_label": field,
                            "match_type": "regex",
                            "pattern": pattern,
                            "priority": 100,
                            "enabled": True,
                            "sample_log": sample_log,
                        }
                    )
                    break
            except re.error:
                continue
    return candidates
