from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timedelta
from typing import Any, Callable

from sqlalchemy import String, or_
from sqlalchemy.orm import Session

from app.models.bootstrap import get_effective_setting
from app.models.entities import (
    AiExperience,
    Alert,
    Asset,
    AssetSegment,
    AuditLog,
    Device,
    Message,
    ParseRule,
    Project,
    Setting,
    TaskRecord,
    Template,
    User,
)
from app.services.asset_service import lookup_asset_by_segment
from app.services.workflow_constants import GROUP_LABELS, ROLE_LABELS, STATUS_LABELS, DISPOSAL_ACTION_LABELS, DISPOSAL_TARGET_LABELS, CLOSURE_ACTION_LABELS


SENSITIVE_RE = re.compile(r"(password|passwd|api[_-]?key|secret|token|cookie|authorization|webhook|private[_-]?key|credential|jwt)", re.I)
ALL_ROLES = {"admin", "monitor", "analyst", "disposer", "viewer"}


def _like(column: Any, q: str) -> Any:
    return column.ilike(f"%{q}%")


def _safe_int(value: Any) -> int | None:
    try:
        if value in (None, ""):
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_dt(value: Any, end_of_day: bool = False) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(text, fmt)
            if fmt == "%Y-%m-%d" and end_of_day:
                return dt + timedelta(days=1)
            return dt
        except ValueError:
            continue
    return None


def _truncate(value: Any, limit: int = 1800) -> str:
    text = str(value or "")
    return text if len(text) <= limit else text[:limit] + "...[已截断]"


def _clean(value: Any) -> Any:
    if isinstance(value, dict):
        result = {}
        for key, val in value.items():
            if SENSITIVE_RE.search(str(key)):
                result[key] = "***已脱敏***"
            else:
                result[key] = _clean(val)
        return result
    if isinstance(value, list):
        return [_clean(item) for item in value[:100]]
    if isinstance(value, datetime):
        return value.isoformat(sep=" ", timespec="seconds")
    return value


def _evidence(tool: str, level: str, status: str, summary: str, data: Any, confidence: str = "high") -> dict[str, Any]:
    return {
        "tool": tool,
        "level": level,
        "status": status,
        "confidence": confidence,
        "summary": summary,
        "data": _clean(data),
        "sensitive_filtered": True,
        "created_at": datetime.utcnow().isoformat(sep=" ", timespec="seconds"),
    }


def _resolve_user_name(db: Session, user_id: int | None) -> str:
    if not user_id:
        return "未分配"
    u = db.get(User, user_id)
    return u.display_name if u else f"未知用户({user_id})"


def _resolve_project_name(db: Session, project_id: int | None) -> str:
    if not project_id:
        return "无"
    p = db.get(Project, project_id)
    return p.name if p else f"未知项目({project_id})"


def _resolve_device_name(db: Session, device_id: int | None) -> str:
    if not device_id:
        return "通用设备"
    d = db.get(Device, device_id)
    return d.name if d else f"未知设备({device_id})"


def _asset_payload(db: Session, row: Asset | None) -> dict[str, Any] | None:
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
        "updated_at": row.updated_at,
    }


def _segment_payload(row: AssetSegment | None) -> dict[str, Any] | None:
    if not row:
        return None
    return {
        "id": row.id,
        "segment": row.segment,
        "name": row.name,
        "area": row.area,
        "owner": row.owner,
        "department": row.department,
        "criticality": row.criticality,
        "environment": row.environment,
        "description": row.description,
        "updated_at": row.updated_at,
    }


def _alert_payload(db: Session, row: Alert | None, detail: bool = False) -> dict[str, Any] | None:
    if not row:
        return None
    data = {
        "alert_code": getattr(row, "alert_code", row.id),
        "alert_hash": row.alert_hash,
        "event_type": row.event_type,
        "src_ip": row.source_ip,
        "dst_ip": row.destination_ip,
        "severity": row.severity,
        "status": STATUS_LABELS.get(row.status, row.status),
        "current_group": GROUP_LABELS.get(row.current_group, row.current_group),
        "assignee_name": _resolve_user_name(db, row.assignee_id),
        "analysis_owner": _resolve_user_name(db, row.analysis_owner_id),
        "disposal_owner": _resolve_user_name(db, row.disposal_owner_id),
        "project_name": _resolve_project_name(db, row.project_id),
        "device_name": _resolve_device_name(db, row.device_id),
        "disposal_target": row.disposal_target,
        "disposal_action": row.disposal_action,
        "disposal_ip": row.disposal_ip,
        "closure_action": row.closure_action,
        "false_positive_reason": row.false_positive_reason,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }
    if detail:
        data.update(
            {
                "parsed_fields": row.parsed_fields or {},
                "src_asset_context": row.src_asset_context or {},
                "dst_asset_context": row.dst_asset_context or {},
                "ti_result": row.ti_result or {},
                "ai_result": row.ai_result,
                "raw_text": _truncate(row.raw_text, 3000),
            }
        )
    return data


def _query_alerts(db: Session, workspace_id: int, q: str | None = None):
    rows = db.query(Alert).filter(Alert.workspace_id == workspace_id)
    if q:
        rows = rows.filter(
            or_(
                _like(Alert.alert_hash, q),
                _like(Alert.event_type, q),
                _like(Alert.source_ip, q),
                _like(Alert.destination_ip, q),
                _like(Alert.status, q),
                _like(Alert.severity, q),
            )
        )
    return rows


def asset_get_by_ip(db: Session, user: User, params: dict[str, Any]) -> dict[str, Any]:
    ip = str(params.get("ip") or "").strip()
    row = db.query(Asset).filter(Asset.workspace_id == user.workspace_id, Asset.ip == ip).order_by(Asset.updated_at.desc()).first()
    return _evidence("asset.get_by_ip", "L1", "success" if row else "empty", "命中资产 1 条" if row else f"未命中资产：{ip}", _asset_payload(db, row))


def asset_get_by_domain(db: Session, user: User, params: dict[str, Any]) -> dict[str, Any]:
    domain = str(params.get("domain") or "").strip()
    row = db.query(Asset).filter(Asset.workspace_id == user.workspace_id, Asset.domain == domain).order_by(Asset.updated_at.desc()).first()
    return _evidence("asset.get_by_domain", "L1", "success" if row else "empty", "命中资产 1 条" if row else f"未命中资产：{domain}", _asset_payload(db, row))


def asset_search(db: Session, user: User, params: dict[str, Any]) -> dict[str, Any]:
    q = str(params.get("q") or "").strip()
    ip = str(params.get("ip") or "").strip()
    domain = str(params.get("domain") or "").strip()
    name = str(params.get("name") or "").strip()
    owner = str(params.get("owner") or "").strip()
    area = str(params.get("area") or "").strip()
    department = str(params.get("department") or "").strip()
    criticality = str(params.get("criticality") or "").strip()
    environment = str(params.get("environment") or "").strip()
    tag = str(params.get("tag") or "").strip()
    rows = db.query(Asset).filter(Asset.workspace_id == user.workspace_id)
    if ip:
        rows = rows.filter(Asset.ip == ip)
    if domain:
        rows = rows.filter(Asset.domain == domain)
    if name:
        rows = rows.filter(_like(Asset.name, name))
    if owner:
        rows = rows.filter(Asset.owner == owner)
    if area:
        rows = rows.filter(Asset.area == area)
    if department:
        rows = rows.filter(Asset.department == department)
    if criticality:
        rows = rows.filter(Asset.criticality == criticality)
    if environment:
        rows = rows.filter(Asset.environment == environment)
    if tag:
        rows = rows.filter(Asset.tags.cast(String).ilike(f"%{tag}%"))
    if q:
        rows = rows.filter(or_(_like(Asset.ip, q), _like(Asset.domain, q), _like(Asset.name, q), _like(Asset.area, q), _like(Asset.owner, q), _like(Asset.department, q)))
    items = [_asset_payload(db, row) for row in rows.order_by(Asset.updated_at.desc()).limit(20).all()]
    filters = "，".join(
        [
            part
            for part in [
                f"IP={ip}" if ip else "",
                f"域名={domain}" if domain else "",
                f"资产名包含={name}" if name else "",
                f"负责人={owner}" if owner else "",
                f"区域={area}" if area else "",
                f"部门={department}" if department else "",
                f"重要性={criticality}" if criticality else "",
                f"环境={environment}" if environment else "",
                f"标签包含={tag}" if tag else "",
                f"关键词={q}" if q else "",
            ]
            if part
        ]
    )
    summary = f"返回资产 {len(items)} 条" + (f"（{filters}）" if filters else "")
    data = {"filters": {k: v for k, v in {"ip": ip, "domain": domain, "name": name, "owner": owner, "area": area, "department": department, "criticality": criticality, "environment": environment, "tag": tag, "q": q}.items() if v}, "items": items}
    return _evidence("asset.search", "L1", "success", summary, data)


def asset_segment_match(db: Session, user: User, params: dict[str, Any]) -> dict[str, Any]:
    ip = str(params.get("ip") or "").strip()
    row = lookup_asset_by_segment(db, user.workspace_id, ip)
    return _evidence("asset.segment_match", "L1", "success" if row else "empty", "命中网段资产 1 条" if row else f"未命中网段资产：{ip}", _segment_payload(row))


def asset_stats(db: Session, user: User, params: dict[str, Any]) -> dict[str, Any]:
    rows = db.query(Asset).filter(Asset.workspace_id == user.workspace_id).all()
    by_area: dict[str, int] = {}
    by_criticality: dict[str, int] = {}
    by_env: dict[str, int] = {}
    for row in rows:
        by_area[row.area or "未填写"] = by_area.get(row.area or "未填写", 0) + 1
        by_criticality[row.criticality or "medium"] = by_criticality.get(row.criticality or "medium", 0) + 1
        by_env[row.environment or "未填写"] = by_env.get(row.environment or "未填写", 0) + 1
    return _evidence("asset.stats", "L1", "success", f"资产总数 {len(rows)}", {"total": len(rows), "by_area": by_area, "by_criticality": by_criticality, "by_environment": by_env})


def alert_search(db: Session, user: User, params: dict[str, Any]) -> dict[str, Any]:
    q = str(params.get("q") or "").strip()
    src_ip = str(params.get("src_ip") or "").strip()
    dst_ip = str(params.get("dst_ip") or "").strip()
    status = str(params.get("status") or "").strip()
    severity = str(params.get("severity") or "").strip()
    event_type = str(params.get("event_type") or "").strip()
    date_from = _parse_dt(params.get("date_from"))
    date_to = _parse_dt(params.get("date_to"), end_of_day=True)
    rows = _query_alerts(db, user.workspace_id, q)
    if src_ip:
        rows = rows.filter(Alert.source_ip == src_ip)
    if dst_ip:
        rows = rows.filter(Alert.destination_ip == dst_ip)
    if status:
        rows = rows.filter(Alert.status == status)
    if severity:
        rows = rows.filter(Alert.severity == severity)
    if event_type:
        rows = rows.filter(_like(Alert.event_type, event_type))
    if date_from:
        rows = rows.filter(Alert.created_at >= date_from)
    if date_to:
        rows = rows.filter(Alert.created_at < date_to)
    results = rows.order_by(Alert.updated_at.desc()).limit(20).all()
    filters = {k: v for k, v in {"q": q, "src_ip": src_ip, "dst_ip": dst_ip, "status": status, "severity": severity, "event_type": event_type, "date_from": params.get("date_from"), "date_to": params.get("date_to")}.items() if v}
    total = rows.count()
    return _evidence("alert.search", "L1", "success", f"返回告警 {len(results)} 条，总计 {total} 条" + (f"（过滤：{filters}）" if filters else ""), {"filters": filters, "total": total, "items": [_alert_payload(db, row) for row in results]})


def alert_detail(db: Session, user: User, params: dict[str, Any]) -> dict[str, Any]:
    alert_hash = str(params.get("alert_hash") or "").strip()
    row = db.query(Alert).filter(Alert.workspace_id == user.workspace_id, Alert.alert_hash == alert_hash).first()
    return _evidence("alert.detail", "L1", "success" if row else "empty", "命中告警 1 条" if row else f"未命中告警：{alert_hash}", _alert_payload(db, row, detail=True))


def alert_timeline(db: Session, user: User, params: dict[str, Any]) -> dict[str, Any]:
    alert_hash = str(params.get("alert_hash") or "").strip()
    alert = db.query(Alert).filter(Alert.workspace_id == user.workspace_id, Alert.alert_hash == alert_hash).first()
    rows = []
    if alert:
        rows = (
            db.query(AuditLog)
            .filter(AuditLog.workspace_id == user.workspace_id, AuditLog.target_type == "alert", AuditLog.target_id == str(alert.id))
            .order_by(AuditLog.created_at.asc())
            .limit(100)
            .all()
        )
    data = [{"time": row.created_at, "action": row.action, "actor_name": _resolve_user_name(db, row.actor_id), "detail": row.detail or {}} for row in rows]
    return _evidence("alert.timeline", "L1", "success" if data else "empty", f"返回流转记录 {len(data)} 条", data)


def alert_stats(db: Session, user: User, params: dict[str, Any]) -> dict[str, Any]:
    query = db.query(Alert).filter(Alert.workspace_id == user.workspace_id)
    date_from = _parse_dt(params.get("date_from"))
    date_to = _parse_dt(params.get("date_to"), end_of_day=True)
    if date_from:
        query = query.filter(Alert.created_at >= date_from)
    if date_to:
        query = query.filter(Alert.created_at < date_to)
    rows = query.all()
    by_status: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for row in rows:
        by_status[STATUS_LABELS.get(row.status, row.status)] = by_status.get(STATUS_LABELS.get(row.status, row.status), 0) + 1
        by_severity[row.severity or "unknown"] = by_severity.get(row.severity or "unknown", 0) + 1
    filters = {k: v for k, v in {"date_from": params.get("date_from"), "date_to": params.get("date_to")}.items() if v}
    return _evidence("alert.stats", "L1", "success", f"告警总数 {len(rows)}" + (f"（过滤：{filters}）" if filters else ""), {"filters": filters, "total": len(rows), "by_status": by_status, "by_severity": by_severity})


def rule_search(db: Session, user: User, params: dict[str, Any]) -> dict[str, Any]:
    q = str(params.get("q") or "").strip()
    field_key = str(params.get("field_key") or "").strip()
    device_id = _safe_int(params.get("device_id"))
    rows = db.query(ParseRule).filter(ParseRule.workspace_id == user.workspace_id, ParseRule.enabled.is_(True))
    if field_key:
        rows = rows.filter(ParseRule.field_key == field_key)
    if device_id is not None:
        rows = rows.filter(ParseRule.device_id == device_id)
    if q:
        rows = rows.filter(or_(_like(ParseRule.name, q), _like(ParseRule.field_key, q), _like(ParseRule.field_label, q)))
    items = [{"id": r.id, "name": r.name, "field_key": r.field_key, "field_label": r.field_label, "device_name": _resolve_device_name(db, r.device_id), "match_type": r.match_type, "priority": r.priority, "is_meta": r.is_meta} for r in rows.order_by(ParseRule.priority.asc()).limit(50).all()]
    return _evidence("rule.search", "L1", "success", f"返回规则 {len(items)} 条", {"filters": {k: v for k, v in {"q": q, "field_key": field_key, "device_id": device_id}.items() if v not in (None, "")}, "items": items})


def template_search(db: Session, user: User, params: dict[str, Any]) -> dict[str, Any]:
    q = str(params.get("q") or "").strip()
    template_type = str(params.get("type") or "").strip()
    device_id = _safe_int(params.get("device_id"))
    rows = db.query(Template).filter(Template.workspace_id == user.workspace_id)
    if template_type:
        rows = rows.filter(Template.type == template_type)
    if device_id is not None:
        rows = rows.filter(Template.device_id == device_id)
    if q:
        rows = rows.filter(or_(_like(Template.name, q), _like(Template.type, q)))
    items = [{"id": r.id, "name": r.name, "type": r.type, "scope": r.scope, "device_name": _resolve_device_name(db, r.device_id), "variables": r.variables or [], "is_default": r.is_default} for r in rows.order_by(Template.updated_at.desc()).limit(30).all()]
    return _evidence("template.search", "L1", "success", f"返回模板 {len(items)} 条", {"filters": {k: v for k, v in {"q": q, "type": template_type, "device_id": device_id}.items() if v not in (None, "")}, "items": items})


def device_search(db: Session, user: User, params: dict[str, Any]) -> dict[str, Any]:
    q = str(params.get("q") or "").strip()
    vendor = str(params.get("vendor") or "").strip()
    product = str(params.get("product") or "").strip()
    rows = db.query(Device).filter(Device.workspace_id == user.workspace_id)
    if vendor:
        rows = rows.filter(_like(Device.vendor, vendor))
    if product:
        rows = rows.filter(_like(Device.product, product))
    if q:
        rows = rows.filter(or_(_like(Device.name, q), _like(Device.vendor, q), _like(Device.product, q)))
    items = [{"id": r.id, "name": r.name, "vendor": r.vendor, "product": r.product, "version": r.version} for r in rows.order_by(Device.updated_at.desc()).limit(30).all()]
    return _evidence("device.search", "L1", "success", f"返回设备 {len(items)} 条", {"filters": {k: v for k, v in {"q": q, "vendor": vendor, "product": product}.items() if v}, "items": items})


def project_search(db: Session, user: User, params: dict[str, Any]) -> dict[str, Any]:
    q = str(params.get("q") or "").strip()
    rows = db.query(Project).filter(Project.workspace_id == user.workspace_id)
    if q:
        rows = rows.filter(_like(Project.name, q))
    items = [{"id": r.id, "name": r.name, "description": r.description} for r in rows.order_by(Project.updated_at.desc()).limit(30).all()]
    return _evidence("project.search", "L1", "success", f"返回项目 {len(items)} 条", {"filters": {"q": q} if q else {}, "items": items})


def user_public_search(db: Session, user: User, params: dict[str, Any]) -> dict[str, Any]:
    q = str(params.get("q") or "").strip()
    role = str(params.get("role") or "").strip()
    rows = db.query(User).filter(User.workspace_id == user.workspace_id)
    if role:
        rows = rows.filter(User.role == role)
    if q:
        rows = rows.filter(or_(_like(User.username, q), _like(User.display_name, q), _like(User.role, q)))
    items = [{"id": r.id, "username": r.username, "display_name": r.display_name, "role": ROLE_LABELS.get(r.role, r.role), "is_active": r.is_active} for r in rows.order_by(User.updated_at.desc()).limit(50).all()]
    return _evidence("user.public_search", "L1", "success", f"返回用户 {len(items)} 条", {"filters": {k: v for k, v in {"q": q, "role": role}.items() if v}, "items": items})


def message_search(db: Session, user: User, params: dict[str, Any]) -> dict[str, Any]:
    q = str(params.get("q") or "").strip()
    rows_query = db.query(Message).filter(Message.workspace_id == user.workspace_id)
    if user.role != "admin":
        rows_query = rows_query.filter(Message.recipient_id == user.id)
    if q:
        rows_query = rows_query.filter(or_(_like(Message.title, q), _like(Message.content, q), _like(Message.alert_hash, q)))
    
    rows = rows_query.order_by(Message.created_at.desc()).limit(30).all()
    
    # 批量获取关联的用户姓名以提升性能
    u_ids = {r.recipient_id for r in rows} | {r.actor_id for r in rows if r.actor_id}
    u_map = {u.id: u.display_name for u in db.query(User).filter(User.id.in_(u_ids)).all()}
    
    items = []
    for r in rows:
        items.append({
            "id": r.id,
            "title": r.title,
            "content": _truncate(r.content, 240),
            "alert_hash": r.alert_hash,
            "is_read": r.is_read,
            "recipient_name": u_map.get(r.recipient_id, "未知用户"),
            "actor_name": u_map.get(r.actor_id, "系统") if r.actor_id else "系统",
            "created_at": r.created_at
        })
    return _evidence("message.search", "L1", "success", f"返回消息 {len(items)} 条", items)


def audit_search(db: Session, user: User, params: dict[str, Any]) -> dict[str, Any]:
    if user.role != "admin":
        return _evidence("audit.search", "L1", "denied", "仅管理员可查询审计日志", [])
    q = str(params.get("q") or "").strip()
    rows = db.query(AuditLog).filter(AuditLog.workspace_id == user.workspace_id)
    if q:
        rows = rows.filter(or_(_like(AuditLog.action, q), _like(AuditLog.target_type, q)))
    items = [{"id": r.id, "time": r.created_at, "actor_name": _resolve_user_name(db, r.actor_id), "action": r.action, "target_type": r.target_type, "target_id": r.target_id, "detail": r.detail or {}} for r in rows.order_by(AuditLog.created_at.desc()).limit(50).all()]
    return _evidence("audit.search", "L1", "success", f"返回审计日志 {len(items)} 条", items)


def task_search(db: Session, user: User, params: dict[str, Any]) -> dict[str, Any]:
    q = str(params.get("q") or "").strip()
    rows = db.query(TaskRecord).filter(TaskRecord.workspace_id == user.workspace_id)
    if user.role != "admin":
        rows = rows.filter(TaskRecord.actor_id == user.id)
    if q:
        rows = rows.filter(_like(TaskRecord.task_type, q))
    items = [{"id": r.id, "task_type": r.task_type, "status": r.status, "target_type": r.target_type, "target_id": r.target_id, "actor_name": _resolve_user_name(db, r.actor_id), "error": _truncate(r.error, 240), "created_at": r.created_at} for r in rows.order_by(TaskRecord.created_at.desc()).limit(30).all()]
    return _evidence("task.search", "L1", "success", f"返回任务 {len(items)} 条", items)


def settings_safe(db: Session, user: User, params: dict[str, Any]) -> dict[str, Any]:
    key = str(params.get("key") or "ai").strip()
    if key not in {"ai", "ti", "webhook", "ip_lists"}:
        return _evidence("settings.safe", "L1", "denied", "不支持查询该配置类型", {})
    val = get_effective_setting(db, user.workspace_id, user.id, key)
    if key == "ip_lists":
        return _evidence("settings.ip_list_summary", "L1", "success", "返回 IP 名单计数", {"whitelist_count": len(val.get("whitelist", [])), "blacklist_count": len(val.get("blacklist", []))})
    safe = {k: ("***已配置***" if SENSITIVE_RE.search(k) and v else v) for k, v in (val or {}).items()}
    return _evidence(f"settings.{key}_safe", "L1", "success", f"返回 {key} 脱敏配置", safe)


def ops_summary(db: Session, user: User, params: dict[str, Any]) -> dict[str, Any]:
    since = datetime.utcnow() - timedelta(days=7)
    total_alerts = db.query(Alert).filter(Alert.workspace_id == user.workspace_id).count()
    recent_alerts = db.query(Alert).filter(Alert.workspace_id == user.workspace_id, Alert.created_at >= since).count()
    open_alerts = db.query(Alert).filter(Alert.workspace_id == user.workspace_id, Alert.status.in_(["analysis", "disposal"])).count()
    total_assets = db.query(Asset).filter(Asset.workspace_id == user.workspace_id).count()
    unread = db.query(Message).filter(Message.workspace_id == user.workspace_id, Message.recipient_id == user.id, Message.is_read.is_(False)).count()
    return _evidence("ops.summary", "L1", "success", "返回运营摘要", {"告警总数": total_alerts, "近7天告警": recent_alerts, "未闭环告警": open_alerts, "资产总数": total_assets, "我的未读消息": unread})


def experience_search(db: Session, user: User, params: dict[str, Any]) -> dict[str, Any]:
    q = str(params.get("q") or "").strip()
    rows = db.query(AiExperience).filter(AiExperience.workspace_id == user.workspace_id)
    if user.role in {"monitor", "viewer"}:
        rows = rows.filter(AiExperience.status == "published")
    if q:
        rows = rows.filter(or_(_like(AiExperience.knowledge_id, q), _like(AiExperience.title, q), _like(AiExperience.alert_hash, q)))
    items = [{"knowledge_id": r.knowledge_id, "title": r.title, "alert_hash": r.alert_hash, "tags": r.tags or [], "index_data": r.index_data or {}, "ste": r.ste or {}, "status": r.status} for r in rows.order_by(AiExperience.updated_at.desc()).limit(20).all()]
    return _evidence("experience.search", "L2", "success", f"返回经验 {len(items)} 条", items)


def alert_similar_by_ip(db: Session, user: User, params: dict[str, Any]) -> dict[str, Any]:
    ip = str(params.get("ip") or "").strip()
    rows = db.query(Alert).filter(Alert.workspace_id == user.workspace_id, or_(Alert.source_ip == ip, Alert.destination_ip == ip)).order_by(Alert.updated_at.desc()).limit(20).all()
    return _evidence("alert.similar_by_ip", "L2", "success", f"返回相关告警 {len(rows)} 条", [_alert_payload(db, row) for row in rows])


def evidence_extract_ioc(db: Session, user: User, params: dict[str, Any]) -> dict[str, Any]:
    text = str(params.get("text") or "")
    ips = sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)))
    cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.I)))
    paths = sorted(set(path.split("?")[0] for _method, path in re.findall(r"\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s]+)", text, flags=re.I) if path.startswith("/")))
    codes = sorted(set(re.findall(r"(?:响应码\s*[:：]\s*|HTTP/\d(?:\.\d)?\s+|\bstatus\s*[:=]\s*)(\d{3})", text, flags=re.I)))
    return _evidence("evidence.extract_ioc", "L2", "success", "完成日志证据提取", {"ips": ips, "cves": cves, "request_paths": paths, "response_codes": codes})


def ti_lookup_ip(db: Session, user: User, params: dict[str, Any]) -> dict[str, Any]:
    ip = str(params.get("ip") or "").strip()
    cfg = get_effective_setting(db, user.workspace_id, user.id, "ti")
    if not cfg:
        return _evidence("ti.lookup_ip", "L2", "empty", "威胁情报未配置", {"ip": ip})
    try:
        from core.ti_service import _query_ip

        result = _query_ip(ip, cfg)
        return _evidence("ti.lookup_ip", "L2", "success" if result else "empty", "完成威胁情报查询" if result else "威胁情报无结果", {"ip": ip, "result": result or {}})
    except Exception as exc:
        return _evidence("ti.lookup_ip", "L2", "error", f"威胁情报查询失败：{exc}", {"ip": ip})


def intel_ip_report(db: Session, user: User, params: dict[str, Any]) -> dict[str, Any]:
    ip = str(params.get("ip") or "").strip()
    if not ip:
        return _evidence("intel.ip_report", "L2", "error", "请提供 IP 地址", {})
    
    # 1. 资产信息
    asset = db.query(Asset).filter(Asset.workspace_id == user.workspace_id, Asset.ip == ip).first()
    # 2. 最近告警 (5条)
    alerts = db.query(Alert).filter(Alert.workspace_id == user.workspace_id, or_(Alert.source_ip == ip, Alert.destination_ip == ip)).order_by(Alert.created_at.desc()).limit(5).all()
    # 3. 最近审计 (5条)
    audits = db.query(AuditLog).filter(AuditLog.workspace_id == user.workspace_id, AuditLog.detail.cast(String).ilike(f"%{ip}%")).order_by(AuditLog.created_at.desc()).limit(5).all()
    # 4. 威胁情报
    ti = {}
    cfg = get_effective_setting(db, user.workspace_id, user.id, "ti")
    if cfg:
        try:
            from core.ti_service import _query_ip
            ti = _query_ip(ip, cfg) or {}
        except Exception: pass

    report = {
        "asset": _asset_payload(db, asset),
        "recent_alerts": [_alert_payload(db, r) for r in alerts],
        "recent_activity": [{"time": r.created_at, "action": r.action, "detail": r.detail} for r in audits],
        "threat_intelligence": ti
    }
    return _evidence("intel.ip_report", "L2", "success", f"生成 IP {ip} 的全维度档案", report)


def intel_user_profile(db: Session, user: User, params: dict[str, Any]) -> dict[str, Any]:
    target_user_id = _safe_int(params.get("user_id"))
    username = str(params.get("username") or "").strip()
    
    query = db.query(User).filter(User.workspace_id == user.workspace_id)
    if target_user_id:
        query = query.filter(User.id == target_user_id)
    elif username:
        query = query.filter(User.username == username)
    else:
        # 默认查自己
        query = query.filter(User.id == user.id)
        
    target = query.first()
    if not target:
        return _evidence("intel.user_profile", "L2", "empty", "未找到指定用户", {})
        
    # 1. 当前负载 (正在领取的告警)
    active_claims = db.query(Alert).filter(Alert.workspace_id == user.workspace_id, Alert.assignee_id == target.id, Alert.status.in_(["analysis", "disposal"])).count()
    # 2. 最近操作
    recent_audits = db.query(AuditLog).filter(AuditLog.workspace_id == user.workspace_id, AuditLog.actor_id == target.id).order_by(AuditLog.created_at.desc()).limit(10).all()
    # 3. 历史贡献 (已闭环)
    total_closed = db.query(Alert).filter(Alert.workspace_id == user.workspace_id, Alert.assignee_id == target.id, Alert.status.in_(["disposed", "false_positive", "ignored"])).count()

    profile = {
        "user": {"id": target.id, "username": target.username, "display_name": target.display_name, "role": target.role},
        "workload": {"active_claims": active_claims, "total_closed": total_closed},
        "recent_activity": [{"time": r.created_at, "action": r.action, "target": f"{r.target_type}:{r.target_id}"} for r in recent_audits]
    }
    return _evidence("intel.user_profile", "L2", "success", f"生成用户 {target.display_name} 的能力与负载画像", profile)


def log_raw_grep(db: Session, user: User, params: dict[str, Any]) -> dict[str, Any]:
    q = str(params.get("q") or "").strip()
    if not q or len(q) < 3:
        return _evidence("log.raw_grep", "L2", "error", "搜索词过短（至少3个字符）", {})
    
    rows = db.query(Alert).filter(Alert.workspace_id == user.workspace_id, Alert.raw_text.ilike(f"%{q}%")).order_by(Alert.created_at.desc()).limit(10).all()
    items = []
    for r in rows:
        items.append({
            "alert_code": r.alert_code,
            "created_at": r.created_at,
            "raw_text_match": _truncate(r.raw_text, 1000)
        })
    return _evidence("log.raw_grep", "L2", "success", f"在原始报文中搜索 '{q}'，找到 {len(items)} 条匹配", items)


def evidence_decode_payload(db: Session, user: User, params: dict[str, Any]) -> dict[str, Any]:
    import base64
    import urllib.parse
    text = str(params.get("payload") or "").strip()
    if not text:
        return _evidence("evidence.decode_payload", "L2", "error", "空载荷", {})
    
    results = {"original": text}
    # 尝试 URL 解码
    try:
        decoded_url = urllib.parse.unquote(text)
        if decoded_url != text: results["url_decoded"] = decoded_url
    except Exception: pass
    
    # 尝试 Base64 解码
    try:
        # 简单清洗 B64
        b64_clean = re.sub(r"[^A-Za-z0-9+/=]", "", text)
        if len(b64_clean) % 4 == 0:
            decoded_b64 = base64.b64decode(b64_clean).decode("utf-8", errors="ignore")
            if len(decoded_b64) > 3: results["base64_decoded"] = decoded_b64
    except Exception: pass
    
    return _evidence("evidence.decode_payload", "L2", "success", "尝试对载荷进行多重解码", results)


def rule_history_stats(db: Session, user: User, params: dict[str, Any]) -> dict[str, Any]:
    rule_name = str(params.get("rule_name") or "").strip()
    if not rule_name:
        return _evidence("rule.history_stats", "L2", "error", "请提供规则名称", {})
        
    rows = db.query(Alert).filter(Alert.workspace_id == user.workspace_id, Alert.event_type == rule_name).all()
    if not rows:
        return _evidence("rule.history_stats", "L2", "empty", "该规则暂无历史告警记录", {})
        
    total = len(rows)
    by_status = {}
    for r in rows:
        label = STATUS_LABELS.get(r.status, r.status)
        by_status[label] = by_status.get(label, 0) + 1
    
    fp_count = by_status.get("误报", 0)
    fp_rate = f"{(fp_count / total * 100):.1f}%" if total > 0 else "0%"
    
    return _evidence("rule.history_stats", "L2", "success", f"规则 '{rule_name}' historical 统计：总数 {total}，误报率 {fp_rate}", {
        "total": total,
        "fp_rate": fp_rate,
        "status_distribution": by_status
    })


def ops_efficiency_drilldown(db: Session, user: User, params: dict[str, Any]) -> dict[str, Any]:
    # 拆解 MTTR：从创建到认领（响应），从认领到处置（处理），从处置到闭环（完成）
    rows = db.query(Alert).filter(Alert.workspace_id == user.workspace_id, Alert.status.in_(["disposed", "false_positive", "ignored"])).all()
    if not rows:
        return _evidence("ops.efficiency_drilldown", "L2", "empty", "暂无足够的闭环样本进行效能拆解", {})
        
    response_times = [] # created -> claimed
    handling_times = [] # claimed -> updated_at (approx)
    
    for r in rows:
        if r.claimed_at and r.created_at:
            response_times.append((r.claimed_at - r.created_at).total_seconds())
        if r.updated_at and r.claimed_at:
            handling_times.append((r.updated_at - r.claimed_at).total_seconds())
            
    def avg(l): return sum(l) / len(l) if l else 0
    
    return _evidence("ops.efficiency_drilldown", "L2", "success", "完成运营效能阶段性拆解", {
        "avg_response_seconds": avg(response_times),
        "avg_handling_seconds": avg(handling_times),
        "sample_count": len(rows)
    })


def asset_shadow_detection(db: Session, user: User, params: dict[str, Any]) -> dict[str, Any]:
    # 找出有告警但不在资产表的 IP
    alert_ips = db.query(Alert.source_ip).filter(Alert.workspace_id == user.workspace_id).distinct().all()
    alert_ips = {r[0] for r in alert_ips if r[0]}
    
    asset_ips = db.query(Asset.ip).filter(Asset.workspace_id == user.workspace_id).all()
    asset_ips = {r[0] for r in asset_ips if r[0]}
    
    shadow_ips = sorted(list(alert_ips - asset_ips))[:50]
    return _evidence("asset.shadow_detection", "L2", "success", f"发现 {len(shadow_ips)} 个影子资产（未备案但有告警）", shadow_ips)


ToolHandler = Callable[[Session, User, dict[str, Any]], dict[str, Any]]

TOOL_REGISTRY: dict[str, dict[str, Any]] = {
    "asset.get_by_ip": {"level": "L1", "description": "按 IP 精确查询资产负责人、区域、标签和指纹", "roles": ALL_ROLES, "handler": asset_get_by_ip},
    "asset.get_by_domain": {"level": "L1", "description": "按域名精确查询资产", "roles": ALL_ROLES, "handler": asset_get_by_domain},
    "asset.search": {"level": "L1", "description": "搜索资产库；支持 ip/domain/name/owner/area/department/criticality/environment/tag/q；ip/domain/owner/area/department/criticality/environment 为精确过滤，q 为兜底关键词", "roles": ALL_ROLES, "handler": asset_search},
    "asset.segment_match": {"level": "L1", "description": "查询 IP 是否命中网段资产", "roles": ALL_ROLES, "handler": asset_segment_match},
    "asset.stats": {"level": "L1", "description": "资产统计", "roles": ALL_ROLES, "handler": asset_stats},
    "asset.shadow_detection": {"level": "L2", "description": "影子资产发现（有告警但未备案的 IP）", "roles": ALL_ROLES, "handler": asset_shadow_detection},
    "alert.search": {"level": "L1", "description": "搜索告警；支持 q/src_ip/dst_ip/status/severity/event_type 过滤", "roles": ALL_ROLES, "handler": alert_search},
    "alert.detail": {"level": "L1", "description": "按告警 Hash 查询告警详情", "roles": ALL_ROLES, "handler": alert_detail},
    "alert.timeline": {"level": "L1", "description": "查询告警流转历史", "roles": ALL_ROLES, "handler": alert_timeline},
    "alert.stats": {"level": "L1", "description": "告警统计", "roles": ALL_ROLES, "handler": alert_stats},
    "alert.similar_by_ip": {"level": "L2", "description": "按 IP 查询历史相似/相关告警", "roles": ALL_ROLES, "handler": alert_similar_by_ip},
    "rule.search": {"level": "L1", "description": "查询解析规则；支持 q/field_key/device_id 过滤", "roles": ALL_ROLES, "handler": rule_search},
    "rule.history_stats": {"level": "L2", "description": "分析某条解析规则的历史误报率和状态分布", "roles": ALL_ROLES, "handler": rule_history_stats},
    "template.search": {"level": "L1", "description": "查询模板；支持 q/type/device_id 过滤", "roles": ALL_ROLES, "handler": template_search},
    "device.search": {"level": "L1", "description": "查询设备；支持 q/vendor/product 过滤", "roles": ALL_ROLES, "handler": device_search},
    "project.search": {"level": "L1", "description": "查询项目；支持 q 过滤", "roles": ALL_ROLES, "handler": project_search},
    "user.public_search": {"level": "L1", "description": "查询用户公开信息，不返回密码或密钥；支持 q/role 过滤", "roles": ALL_ROLES, "handler": user_public_search},
    "message.search": {"level": "L1", "description": "查询消息，普通用户只查自己的消息", "roles": ALL_ROLES, "handler": message_search},
    "audit.search": {"level": "L1", "description": "查询审计日志，管理员可用", "roles": {"admin"}, "handler": audit_search},
    "task.search": {"level": "L1", "description": "查询任务状态", "roles": ALL_ROLES, "handler": task_search},
    "settings.safe": {"level": "L1", "description": "查询脱敏后的配置状态", "roles": ALL_ROLES, "handler": settings_safe},
    "ops.summary": {"level": "L1", "description": "查询运营摘要", "roles": ALL_ROLES, "handler": ops_summary},
    "ops.efficiency_drilldown": {"level": "L2", "description": "运营效能深度拆解（响应/处理时间分析）", "roles": ALL_ROLES, "handler": ops_efficiency_drilldown},
    "experience.search": {"level": "L2", "description": "查询 AI STE 经验库", "roles": ALL_ROLES, "handler": experience_search},
    "evidence.extract_ioc": {"level": "L2", "description": "从文本中提取 IP、CVE、请求路径、响应码", "roles": ALL_ROLES, "handler": evidence_extract_ioc},
    "evidence.decode_payload": {"level": "L2", "description": "对混淆载荷执行 Base64/URL 多重解码分析", "roles": ALL_ROLES, "handler": evidence_decode_payload},
    "ti.lookup_ip": {"level": "L2", "description": "查询单个 IP 威胁情报", "roles": {"admin", "monitor", "analyst", "disposer"}, "handler": ti_lookup_ip},
    "intel.ip_report": {"level": "L2", "description": "IP 全维度档案（资产+告警轨迹+情报+审计）", "roles": ALL_ROLES, "handler": intel_ip_report},
    "intel.user_profile": {"level": "L2", "description": "用户画像（负载、角色、近期活跃度）", "roles": ALL_ROLES, "handler": intel_user_profile},
    "log.raw_grep": {"level": "L2", "description": "在千万级告警原始报文中进行关键字/正则全文检索", "roles": ALL_ROLES, "handler": log_raw_grep},
}


def get_tool_schemas(user: User) -> list[dict[str, Any]]:
    return [
        {"tool": name, "level": meta["level"], "description": meta["description"]}
        for name, meta in TOOL_REGISTRY.items()
        if user.role in meta["roles"]
    ]


def execute_tool(db: Session, user: User, tool_name: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    meta = TOOL_REGISTRY.get(tool_name)
    if not meta:
        return _evidence(tool_name, "unknown", "denied", "工具不存在或未开放", {})
    if user.role not in meta["roles"]:
        return _evidence(tool_name, meta["level"], "denied", "当前角色无权使用该工具", {})
    try:
        return meta["handler"](db, user, params or {})
    except Exception as exc:
        return _evidence(tool_name, meta["level"], "error", f"工具执行失败：{exc}", {})
