import csv
import io
import json
from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import current_user, require_admin, require_not_viewer
from app.core.timezone import today_end, today_start
from app.models.database import get_db
from app.models.entities import Alert, AuditLog, Device, ParseRule, Project, Setting, TaskRecord, Template, User
from app.schemas.common import TaskRecordOut, WebhookTestRequest
from app.services.audit_service import write_audit
from app.services.ip_list_service import (
    add_ip_list_item,
    delete_ip_list_items,
    detect_value_type,
    get_ip_list_setting,
    normalize_value,
    save_ip_lists,
    set_ip_list_value,
    update_ip_list_item,
)
from app.services.template_service import render_template
from app.services.stats_service import get_aggregate_stats
from app.services.task_service import create_task, fail_task, finish_task
from app.services.workflow_constants import (
    CLOSURE_ACTION_LABELS,
    DISPOSAL_ACTION_LABELS,
    DISPOSAL_TARGET_LABELS,
    GROUP_LABELS,
    STATUS_LABELS,
    TERMINAL_STATUSES,
    normalize_status,
)
from core.lists import is_ip_in_list
from integration.webhook import send_record

router = APIRouter(tags=["operations"])

COMPACT_STATUS_LABELS = STATUS_LABELS


from app.core.utils import parse_day


def _compact_status(status: str | None) -> str:
    return normalize_status(status)


def _audit_new_status(detail: dict[str, Any] | None) -> str | None:
    changes = (detail or {}).get("changes", {})
    status_change = changes.get("status") if isinstance(changes, dict) else None
    if isinstance(status_change, dict):
        return status_change.get("new")
    if isinstance(status_change, str):
        return status_change
    return None


def _setting(db: Session, workspace_id: int, key: str, default: dict[str, Any] | None = None) -> Setting:
    row = db.query(Setting).filter_by(workspace_id=workspace_id, key=key).first()
    if row:
        return row
    row = Setting(workspace_id=workspace_id, key=key, value=default or {})
    db.add(row)
    db.flush()
    return row


def _parse_alert_time(val: Any) -> datetime | None:
    if not val: return None
    if isinstance(val, datetime): return val
    s = str(val).strip()
    # 尝试常见的日志时间格式
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


@router.get("/dashboard/summary")
def dashboard_summary(
    start_date: str | None = None,
    end_date: str | None = None,
    db: Session = Depends(get_db), 
    user: User = Depends(current_user)
):
    if not start_date:
        start_dt = today_start(db, user.workspace_id)
    else:
        start_dt = parse_day(start_date)
    
    if not end_date:
        end_dt = today_end(db, user.workspace_id)
    else:
        end_dt = parse_day(end_date, end_of_day=True)

    base = db.query(Alert).filter(Alert.workspace_id == user.workspace_id)
    filtered = base.filter(Alert.created_at >= start_dt, Alert.created_at < end_dt)

    total = filtered.count()
    # 获取审计日志用于计算 MTTR，仅当前处于终态的告警参与统计。
    all_alerts = filtered.all()
    pending = sum(1 for a in all_alerts if _compact_status(a.status) not in TERMINAL_STATUSES)
    confirmed = sum(1 for a in all_alerts if _compact_status(a.status) in TERMINAL_STATUSES)
    alert_ids = [a.id for a in all_alerts]
    
    terminal_logs = {}
    if alert_ids:
        # 批量查询涉及这些告警的状态变更审计日志
        audit_rows = db.query(AuditLog).filter(
            AuditLog.workspace_id == user.workspace_id,
            AuditLog.target_type == "alert",
            AuditLog.target_id.in_([str(id) for id in alert_ids]),
            AuditLog.action.in_(["alert.update", "alert.batch_update", "alert.transition"])
        ).order_by(AuditLog.created_at.asc()).all()
        
        for row in audit_rows:
            new_status = _audit_new_status(row.detail)
            new_status = _compact_status(new_status)
            if new_status in TERMINAL_STATUSES and row.target_id not in terminal_logs:
                terminal_logs[row.target_id] = row.created_at

    # 计算整体 MTTR (秒)
    mttr_samples = []
    
    for a in all_alerts:
        if _compact_status(a.status) not in TERMINAL_STATUSES:
            continue
        # MTTR: terminal_time - created_at
        t_time = terminal_logs.get(str(a.id))
        if not t_time:
            t_time = a.updated_at
        if t_time:
            diff = (t_time - a.created_at).total_seconds()
            if diff >= 0:
                mttr_samples.append(diff)

    avg_mttr = sum(mttr_samples) / len(mttr_samples) if mttr_samples else None

    by_status = dict(filtered.with_entities(Alert.status, func.count(Alert.id)).group_by(Alert.status).all())

    # 增长趋势图逻辑
    days_diff = (end_dt - start_dt).days
    if days_diff <= 2:
        fmt = "%Y-%m-%d %H:00"
        delta = timedelta(hours=1)
    else:
        fmt = "%Y-%m-%d"
        delta = timedelta(days=1)

    trend_data = []
    curr = start_dt
    while curr < end_dt:
        step_end = curr + delta
        step_label = curr.strftime(fmt)
        
        step_alerts = [a for a in all_alerts if curr <= a.created_at < step_end]
        
        counts = {s: 0 for s in COMPACT_STATUS_LABELS.keys()}
        for a in step_alerts:
            status = _compact_status(a.status)
            if status in counts:
                counts[status] += 1
        
        # 该步长内的效能指标：按完成处置时间归桶，而不是按告警创建时间归桶。
        s_mttr = []
        for a in all_alerts:
            if _compact_status(a.status) not in TERMINAL_STATUSES:
                continue
            tt = terminal_logs.get(str(a.id))
            if not tt:
                tt = a.updated_at
            if tt and curr <= tt < step_end:
                diff = (tt - a.created_at).total_seconds()
                if diff >= 0: s_mttr.append(diff)
        
        trend_data.append({
            "time": step_label,
            "total": len(step_alerts),
            **{s: counts[s] for s in COMPACT_STATUS_LABELS.keys()},
            "mttr": sum(s_mttr) / len(s_mttr) if s_mttr else None,
            "mttr_count": len(s_mttr),
        })
        curr = step_end

    latest = [
        {
            "id": row.id,
            "alert_code": _alert_code_map(db, user, [row]).get(row.id, ""),
            "alert_hash": row.alert_hash,
            "source_ip": row.source_ip,
            "destination_ip": row.destination_ip,
            "event_type": row.event_type,
            "status": row.status,
            "created_at": row.created_at,
        }
        for row in base.order_by(Alert.created_at.desc()).limit(8).all()
    ]

    return {
        "total": total,
        "pending": pending,
        "confirmed": confirmed,
        "avg_mttr": avg_mttr,
        "mttr_count": len(mttr_samples),
        "by_status": by_status,
        "trend": trend_data,
        "latest": latest,
    }


@router.get("/dashboard/report")
def dashboard_report(
    template_id: int | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(current_user)
):
    """根据选定模板生成运营报告文本"""
    stats = get_aggregate_stats(db, user.workspace_id)
    
    template = None
    if template_id:
        template = db.get(Template, template_id)
        if template and template.workspace_id != user.workspace_id:
            template = None

    if not template:
        # 如果未指定模板或找不到模板，使用硬编码的默认格式作为回退
        report = (
            f"【安全运营日报 - {stats.get('当前日期')}】\n\n"
            f"一、 运行概况\n"
            f"今日共监测到告警 {stats.get('当前总数')} 条，其中高危/极高告警占比 {stats.get('高危告警占比')}。\n"
            f"当前已完成处置 {stats.get('已办结数')} 条，整体处置率为 {stats.get('当前处置率')}。\n"
            f"平均处置耗时：{stats.get('平均处置耗时')}。\n\n"
            f"二、 风险分布\n"
            f"【活跃攻击源 Top 5】\n{stats.get('Top5_攻击源排行')}\n\n"
            f"【受攻击资产 Top 5】\n{stats.get('Top5_受攻击资产排行')}\n\n"
            f"资产信息命中率：{stats.get('资产命中率')}\n\n"
            f"三、 待办提示\n"
            f"目前仍有 {stats.get('待处理数')} 条告警处于待处理状态，请各位研判员及时关注。"
        )
    else:
        # 使用模板服务进行渲染
        report = render_template(template.content, stats)
    
    return {"report": report}


@router.get("/ip-lists")
def get_ip_lists(db: Session = Depends(get_db), user: User = Depends(current_user)):
    row = get_ip_list_setting(db, user.workspace_id)
    set_ip_list_value(db, row, row.value or {})
    db.commit()
    db.refresh(row)
    res = dict(row.value or {"whitelist": [], "blacklist": [], "items": []})
    res["updated_at"] = row.updated_at
    return res


@router.put("/ip-lists")
def update_ip_lists(payload: dict[str, Any], db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    # 乐观锁检查
    provided_updated_at = payload.get("updated_at")
    row = get_ip_list_setting(db, user.workspace_id)
    
    if provided_updated_at and row.updated_at:
        from datetime import datetime
        try:
            # 解析前端传来的 ISO 格式字符串
            if isinstance(provided_updated_at, str):
                provided_dt = datetime.fromisoformat(provided_updated_at.replace('Z', '+00:00'))
            else:
                provided_dt = provided_updated_at
            
            if row.updated_at.replace(microsecond=0) > provided_dt.replace(microsecond=0):
                raise HTTPException(status_code=409, detail="名单已被他人修改，请刷新页面后再试")
        except (ValueError, TypeError):
            pass

    if isinstance(payload.get("items"), list):
        row = get_ip_list_setting(db, user.workspace_id)
        set_ip_list_value(db, row, {"items": payload.get("items", [])})
        write_audit(
            db,
            user,
            "ip_lists.update",
            "setting",
            "ip_lists",
            {"items": len((row.value or {}).get("items", []))},
        )
    else:
        row = save_ip_lists(db, user, payload.get("whitelist", []), payload.get("blacklist", []))
    db.commit()
    db.refresh(row)
    res = dict(row.value)
    res["updated_at"] = row.updated_at
    return res


@router.post("/ip-lists/items")
def create_ip_list_item(payload: dict[str, Any], db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    try:
        row, item, created = add_ip_list_item(db, user, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    write_audit(db, user, "ip_lists.item_create", "setting", "ip_lists", {"item": item, "created": created})
    db.commit()
    db.refresh(row)
    res = dict(row.value)
    res["updated_at"] = row.updated_at
    res["created"] = created
    return res


@router.patch("/ip-lists/items/{item_id}")
def patch_ip_list_item(item_id: str, payload: dict[str, Any], db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    try:
        row, item = update_ip_list_item(db, user, item_id, payload)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    write_audit(db, user, "ip_lists.item_update", "setting", "ip_lists", {"item": item})
    db.commit()
    db.refresh(row)
    res = dict(row.value)
    res["updated_at"] = row.updated_at
    return res


@router.delete("/ip-lists/items/{item_id}")
def remove_ip_list_item(item_id: str, db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    row, deleted = delete_ip_list_items(db, user, [item_id])
    if not deleted:
        raise HTTPException(status_code=404, detail="名单项不存在")
    write_audit(db, user, "ip_lists.item_delete", "setting", "ip_lists", {"ids": [item_id], "deleted": deleted})
    db.commit()
    db.refresh(row)
    res = dict(row.value)
    res["updated_at"] = row.updated_at
    res["deleted"] = deleted
    return res


@router.post("/ip-lists/batch-delete")
def batch_remove_ip_list_items(payload: dict[str, Any], db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    ids = payload.get("ids") or []
    if not isinstance(ids, list) or not ids:
        raise HTTPException(status_code=400, detail="请选择要删除的名单项")
    row, deleted = delete_ip_list_items(db, user, [str(item) for item in ids])
    write_audit(db, user, "ip_lists.batch_delete", "setting", "ip_lists", {"ids": ids, "deleted": deleted})
    db.commit()
    db.refresh(row)
    res = dict(row.value)
    res["updated_at"] = row.updated_at
    res["deleted"] = deleted
    return res


def _parse_import_values(payload: dict[str, Any]) -> list[str]:
    raw_values = payload.get("values")
    if isinstance(raw_values, list):
        return [str(item).strip() for item in raw_values if str(item).strip()]
    text = str(payload.get("text") or "")
    values = []
    for line in text.replace(",", "\n").replace(";", "\n").splitlines():
        item = line.strip()
        if item and not item.startswith("#"):
            values.append(item)
    return values


@router.post("/ip-lists/import")
def import_ip_list_items(payload: dict[str, Any], db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    list_type = payload.get("list_type")
    if list_type not in {"whitelist", "blacklist"}:
        raise HTTPException(status_code=400, detail="请选择白名单或黑名单")
    description = str(payload.get("description") or "")
    values = _parse_import_values(payload)
    if not values:
        raise HTTPException(status_code=400, detail="请输入要导入的 IP")

    row = get_ip_list_setting(db, user.workspace_id)
    current = normalize_value(row.value)
    existing = {(item["list_type"], item["value"]) for item in current["items"]}
    added = 0
    skipped = 0
    invalid: list[dict[str, str]] = []

    for value in values:
        try:
            value_type = detect_value_type(value)
            key = (list_type, value)
            if key in existing:
                skipped += 1
                continue
            item = {
                "list_type": list_type,
                "value": value,
                "value_type": value_type,
                "description": description,
                "source": "import",
            }
            _, created_item, _ = add_ip_list_item(db, user, item)
            existing.add(key)
            added += 1
        except ValueError as exc:
            invalid.append({"value": value, "error": str(exc)})

    row = get_ip_list_setting(db, user.workspace_id)
    write_audit(
        db,
        user,
        "ip_lists.import",
        "setting",
        "ip_lists",
        {"list_type": list_type, "added": added, "skipped": skipped, "invalid": len(invalid)},
    )
    db.commit()
    db.refresh(row)
    res = dict(row.value)
    res["updated_at"] = row.updated_at
    res["import_result"] = {"added": added, "skipped": skipped, "invalid": invalid}
    return res


@router.post("/ip-lists/check")
def check_ip_list(payload: dict[str, str], db: Session = Depends(get_db), user: User = Depends(current_user)):
    ip = (payload.get("ip") or "").strip()
    if not ip:
        raise HTTPException(status_code=400, detail="请输入 IP")
    row = get_ip_list_setting(db, user.workspace_id)
    value = row.value or {"whitelist": [], "blacklist": []}
    matches = []
    for list_name, label in (("whitelist", "白名单"), ("blacklist", "黑名单")):
        for item in value.get(list_name, []):
            if is_ip_in_list(ip, [item]):
                matches.append({"list": list_name, "label": label, "range": item})
    return {"ip": ip, "matched": bool(matches), "matches": matches}


@router.get("/ip-lists/export.txt")
def export_ip_lists(type: str = "all", db: Session = Depends(get_db), user: User = Depends(current_user)):
    row = get_ip_list_setting(db, user.workspace_id)
    value = row.value or {"whitelist": [], "blacklist": []}
    whitelist = [str(item).strip() for item in value.get("whitelist", []) if str(item).strip()]
    blacklist = [str(item).strip() for item in value.get("blacklist", []) if str(item).strip()]

    if type == "whitelist":
        filename = "whitelist.txt"
        lines = whitelist
    elif type == "blacklist":
        filename = "blacklist.txt"
        lines = blacklist
    elif type == "all":
        filename = "ip-lists.txt"
        lines = ["# 白名单", *whitelist, "", "# 黑名单", *blacklist]
    else:
        raise HTTPException(status_code=400, detail="type 仅支持 whitelist、blacklist 或 all")

    content = "\n".join(lines).rstrip() + "\n"
    return StreamingResponse(
        iter([content.encode("utf-8-sig")]),
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _alert_code_map(db: Session, user: User, alerts: list[Alert]) -> dict[int, str]:
    days = {alert.created_at.date() for alert in alerts if alert.created_at}
    codes: dict[int, str] = {}
    for day in days:
        start = datetime.combine(day, datetime.min.time())
        end = start + timedelta(days=1)
        rows = (
            db.query(Alert.id, Alert.created_at)
            .filter(Alert.workspace_id == user.workspace_id, Alert.created_at >= start, Alert.created_at < end)
            .order_by(Alert.created_at.asc(), Alert.id.asc())
            .all()
        )
        prefix = day.strftime("%Y%m%d")
        for index, row in enumerate(rows, start=1):
            codes[row.id] = f"{prefix}{index:04d}"
    return codes


def _csv_columns(template: Template | None) -> list[tuple[str, str]]:
    if not template:
        return [
            ("创建时间", "created_at"),
            ("告警ID", "alert_code"),
            ("告警Hash", "alert_hash"),
            ("源IP", "source_ip"),
            ("目的IP", "destination_ip"),
            ("事件类型", "event_type"),
            ("状态", "status_label"),
            ("AI研判", "ai_result"),
            ("原始日志", "raw_text"),
        ]
    columns = []
    for part in re_split_template_columns(template.content):
        match = re_template_column(part)
        if match:
            columns.append(match)
    return columns or [(key, key) for key in template.variables or []]


def re_split_template_columns(content: str) -> list[str]:
    return [item.strip() for item in (content or "").replace("\t", "\n").splitlines() if item.strip()]


def re_template_column(part: str) -> tuple[str, str] | None:
    import re

    labelled = re.match(r"^\s*(.+?)[:：]\s*\{\{\s*([^{}]+)\s*\}\}\s*$", part)
    if labelled:
        return labelled.group(1).strip(), labelled.group(2).strip()
    bare = re.match(r"^\s*\{\{\s*([^{}]+)\s*\}\}\s*$", part)
    if bare:
        key = bare.group(1).strip()
        return key, key
    return None


def _alert_export_context(
    db: Session,
    alert: Alert,
    alert_code: str,
    users: dict[int, User],
    projects: dict[int, Project],
    devices: dict[int, Device],
    all_rules: list[ParseRule],
) -> dict[str, Any]:
    data = dict(alert.parsed_fields or {})
    block_device_names = [devices[item].name for item in (alert.block_device_ids or []) if item in devices]
    response_owner_name = users.get(alert.response_owner_id).display_name if users.get(alert.response_owner_id) else ""
    reported_by_name = alert.reported_by_name or (users.get(alert.created_by_id).display_name if users.get(alert.created_by_id) else "")
    alert_time = str(data.get("告警时间") or data.get("alert_time") or (alert.created_at.isoformat(sep=" ", timespec="seconds") if alert.created_at else ""))
    device_name = devices.get(alert.device_id).name if devices.get(alert.device_id) else "通用设备"
    device_ip = str(data.get("告警设备IP地址") or data.get("device_ip") or "")
    alert_name = str(data.get("告警名称") or data.get("event_name") or alert.event_type or "")
    analysis_owner_name = users.get(alert.analysis_owner_id).display_name if users.get(alert.analysis_owner_id) else ""
    disposal_owner_name = users.get(alert.disposal_owner_id).display_name if users.get(alert.disposal_owner_id) else ""
    event_id = str(data.get("事件ID") or data.get("isop_event_id") or data.get("event_id") or alert.alert_hash or "")
    source_ip = str(alert.source_ip or data.get("攻击源IP") or data.get("源IP") or data.get("src_ip") or "")
    destination_ip = str(alert.destination_ip or data.get("攻击目的IP") or data.get("目的IP") or data.get("dst_ip") or "")
    
    # 建立语义化映射
    semantic_data = {}
    for rule in all_rules:
        # 只处理与该告警设备匹配或通用的规则
        if not rule.device_id or rule.device_id == alert.device_id:
            val = data.get(rule.field_key)
            if val is not None:
                semantic_data[rule.name] = val

    data.update(
        {
            "id": alert.id,
            "alert_code": alert_code or alert.alert_code or alert.id,
            "告警ID": alert_code or alert.alert_code or alert.id,
            "alert_hash": alert.alert_hash,
            "告警Hash": alert.alert_hash,
            "created_at": alert.created_at.isoformat(sep=" ", timespec="seconds") if alert.created_at else "",
            "创建时间": alert.created_at.isoformat(sep=" ", timespec="seconds") if alert.created_at else "",
            "updated_at": alert.updated_at.isoformat(sep=" ", timespec="seconds") if alert.updated_at else "",
            "更新时间": alert.updated_at.isoformat(sep=" ", timespec="seconds") if alert.updated_at else "",
            "source_ip": source_ip,
            "源IP": source_ip,
            "destination_ip": destination_ip,
            "目的IP": destination_ip,
            "event_type": alert.event_type,
            "事件类型": alert.event_type,
            "status": alert.status,
            "current_group": alert.current_group,
            "所属组": GROUP_LABELS.get(alert.current_group, alert.current_group),
            "created_by": users.get(alert.created_by_id).display_name if users.get(alert.created_by_id) else "",
            "created_by_name": users.get(alert.created_by_id).display_name if users.get(alert.created_by_id) else "",
            "last_updated_by": users.get(alert.last_updated_by_id).display_name if users.get(alert.last_updated_by_id) else "",
            "last_updated_by_name": users.get(alert.last_updated_by_id).display_name if users.get(alert.last_updated_by_id) else "",
            "assignee": users.get(alert.assignee_id).display_name if users.get(alert.assignee_id) else "",
            "assignee_name": users.get(alert.assignee_id).display_name if users.get(alert.assignee_id) else "",
            "负责人": users.get(alert.assignee_id).display_name if users.get(alert.assignee_id) else "未分配",
            "analysis_owner": analysis_owner_name,
            "研判负责人": analysis_owner_name,
            "研判人员": analysis_owner_name,
            "disposal_owner": disposal_owner_name,
            "处置负责人": disposal_owner_name,
            "封禁人员": disposal_owner_name,
            "reported_by_name": reported_by_name,
            "监测上报人员": reported_by_name,
            "analysis_result": alert.analysis_result,
            "研判结果": alert.analysis_result,
            "is_emergency": "是" if alert.is_emergency else "否",
            "是否应急": "是" if alert.is_emergency else "否",
            "block_device_names": block_device_names,
            "封禁位置": "、".join(block_device_names),
            "block_at": alert.block_at.isoformat(sep=" ", timespec="seconds") if alert.block_at else "",
            "封禁时间": alert.block_at.isoformat(sep=" ", timespec="seconds") if alert.block_at else "",
            "response_note": alert.response_note if alert.disposal_action == "emergency" else "",
            "处置描述": alert.response_note if alert.disposal_action == "emergency" else "",
            "response_owner": response_owner_name if alert.disposal_action == "emergency" else "",
            "应急人员": response_owner_name if alert.disposal_action == "emergency" else "",
            "disposal_target": alert.disposal_target,
            "处置对象": DISPOSAL_TARGET_LABELS.get(alert.disposal_target, alert.disposal_target),
            "disposal_action": alert.disposal_action,
            "处置动作": DISPOSAL_ACTION_LABELS.get(alert.disposal_action, alert.disposal_action),
            "disposal_ip": alert.disposal_ip,
            "处置IP": alert.disposal_ip,
            "closure_target": alert.closure_target,
            "闭环对象": DISPOSAL_TARGET_LABELS.get(alert.closure_target, alert.closure_target),
            "closure_action": alert.closure_action,
            "闭环动作": CLOSURE_ACTION_LABELS.get(alert.closure_action, alert.closure_action),
            "false_positive_reason": alert.false_positive_reason,
            "误报原因": alert.false_positive_reason,
            "project_name": projects.get(alert.project_id).name if projects.get(alert.project_id) else "",
            "项目名称": projects.get(alert.project_id).name if projects.get(alert.project_id) else "",
            "device_name": device_name,
            "设备名称": device_name,
            "status_label": STATUS_LABELS.get(alert.status, alert.status),
            "状态": STATUS_LABELS.get(alert.status, alert.status),
            "当前日期": alert.created_at.strftime("%Y-%m-%d") if alert.created_at else "",
            "当前时间": alert.created_at.strftime("%Y-%m-%d %H:%M:%S") if alert.created_at else "",
            "ai_result": alert.ai_result,
            "AI 研判结果": alert.ai_result,
            "raw_text": alert.raw_text,
            "原始日志": alert.raw_text,
            "告警编号": alert_code or alert.id,
            "事件ID": event_id,
            "告警时间": alert_time,
            "告警设备": device_name,
            "告警设备IP地址": device_ip,
            "告警名称": alert_name,
            "攻击源IP": source_ip,
            "攻击目的IP": destination_ip,
        }
    )
    # 合并语义化数据
    data.update(semantic_data)
    data.update(
        {
            "告警编号": alert_code or alert.id,
            "事件ID": event_id,
            "告警时间": alert_time,
            "告警设备": device_name,
            "告警设备IP地址": device_ip,
            "告警名称": alert_name,
            "攻击源IP": source_ip,
            "攻击目的IP": destination_ip,
        }
    )
    
    # 注入全局统计信息
    try:
        stats = get_aggregate_stats(db, alert.workspace_id)
        data.update(stats)
    except Exception:
        pass
    
    src_asset = alert.src_asset_context or data.get("src_asset_context") or {}
    dst_asset = alert.dst_asset_context or data.get("dst_asset_context") or {}
    data.update(
        {
            "src_asset_name": src_asset.get("name", ""),
            "源资产名称": src_asset.get("name", ""),
            "src_asset_area": src_asset.get("area", ""),
            "源资产区域": src_asset.get("area", ""),
            "src_asset_owner": src_asset.get("owner", ""),
            "源资产负责人": src_asset.get("owner", ""),
            "dst_asset_name": dst_asset.get("name", ""),
            "目的资产名称": dst_asset.get("name", ""),
            "dst_asset_area": dst_asset.get("area", ""),
            "目的资产区域": dst_asset.get("area", ""),
            "dst_asset_owner": dst_asset.get("owner", ""),
            "目的资产负责人": dst_asset.get("owner", ""),
            "dst_asset_criticality": dst_asset.get("criticality", ""),
            "目的资产重要性": dst_asset.get("criticality", ""),
        }
    )
    return data


@router.get("/exports/alerts.csv")
def export_alerts_csv(
    start_date: str | None = None,
    end_date: str | None = None,
    status: str | None = None,
    current_group: str | None = None,
    project_id: int | None = None,
    assignee_id: int | None = None,
    q: str | None = None,
    template_id: int | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    query = db.query(Alert).filter(Alert.workspace_id == user.workspace_id)
    if status:
        query = query.filter(Alert.status == status)
    if current_group:
        query = query.filter(Alert.current_group == current_group)
    if project_id:
        query = query.filter(Alert.project_id == project_id)
    if assignee_id:
        query = query.filter(Alert.assignee_id == assignee_id)
    if start_date:
        query = query.filter(Alert.created_at >= parse_day(start_date))
    if end_date:
        query = query.filter(Alert.created_at < parse_day(end_date, end_of_day=True))
    if q:
        like = f"%{q}%"
        query = query.filter(
            (Alert.alert_hash.like(like)) | (Alert.source_ip.like(like)) | (Alert.destination_ip.like(like)) | (Alert.event_type.like(like))
        )
    rows = query.order_by(Alert.created_at.desc()).limit(5000).all()
    template = db.get(Template, template_id) if template_id else None
    if template and (template.workspace_id != user.workspace_id or template.type != "csv"):
        raise HTTPException(status_code=400, detail="CSV 模板不存在")
    if template is None:
        template = db.query(Template).filter_by(workspace_id=user.workspace_id, type="csv", is_default=True).first()
    columns = _csv_columns(template)
    codes = _alert_code_map(db, user, rows)
    user_ids = (
        {row.created_by_id for row in rows if row.created_by_id}
        | {row.last_updated_by_id for row in rows if row.last_updated_by_id}
        | {row.assignee_id for row in rows if row.assignee_id}
        | {row.analysis_owner_id for row in rows if row.analysis_owner_id}
        | {row.disposal_owner_id for row in rows if row.disposal_owner_id}
        | {row.response_owner_id for row in rows if row.response_owner_id}
    )
    users = {row.id: row for row in db.query(User).filter(User.id.in_(user_ids)).all()} if user_ids else {}
    project_ids = {row.project_id for row in rows if row.project_id}
    projects = {row.id: row for row in db.query(Project).filter(Project.id.in_(project_ids)).all()} if project_ids else {}
    device_ids = {row.device_id for row in rows if row.device_id} | {device_id for row in rows for device_id in (row.block_device_ids or []) if device_id}
    devices = {row.id: row for row in db.query(Device).filter(Device.id.in_(device_ids)).all()} if device_ids else {}
    
    # 预先获取所有规则，用于语义化映射
    all_workspace_rules = db.query(ParseRule).filter_by(workspace_id=user.workspace_id, enabled=True).all()
    
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow([label for label, _ in columns])
    for row in rows:
        context = _alert_export_context(db, row, codes.get(row.id, ""), users, projects, devices, all_workspace_rules)
        writer.writerow([render_template(f"{{{{{key}}}}}", context) for _, key in columns])
    buffer.seek(0)
    return StreamingResponse(
        iter([buffer.getvalue().encode("utf-8-sig")]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=alerts.csv"},
    )


@router.post("/webhook/test")
def test_webhook(payload: WebhookTestRequest, db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    return _send_webhook_text(payload, db, user, "webhook.test")


@router.post("/webhook/send")
def send_webhook(payload: WebhookTestRequest, db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    return _send_webhook_text(payload, db, user, "webhook.send")


def _send_webhook_text(payload: WebhookTestRequest, db: Session, user: User, action: str):
    setting = db.query(Setting).filter_by(workspace_id=user.workspace_id, key="webhook").first()
    if not setting:
        raise HTTPException(status_code=400, detail="Webhook 未配置")
    webhook_value = setting.value or {}
    if not webhook_value.get("enabled", True):
        raise HTTPException(status_code=400, detail="消息推送已关闭")
    provider = webhook_value.get("provider")
    enabled_targets = []
    if provider in {"dingtalk", "wecom", "feishu"}:
        if webhook_value.get(provider, {}).get("url") or webhook_value.get("url"):
            enabled_targets.append(provider)
    else:
        enabled_targets = [
            name for name in ("dingtalk", "wecom", "feishu")
            if webhook_value.get(name, {}).get("enabled") and webhook_value.get(name, {}).get("url")
        ]
    if not enabled_targets:
        raise HTTPException(status_code=400, detail="请先在系统配置中启用并填写 Webhook URL")
    task = create_task(db, user, action, "setting", "webhook", {"text_length": len(payload.text)})
    cfg = {"webhook": webhook_value}
    try:
        result = send_record(payload.text, cfg)
        if not result.get("success"):
            raise HTTPException(status_code=502, detail=result)
        finish_task(db, task, {"result": result})
    except Exception as exc:
        fail_task(db, task, exc)
        raise
    write_audit(db, user, action, "setting", "webhook", {"ok": bool(result), "task_id": task.id})
    db.commit()
    return {"task_id": task.id, "result": result}


@router.get("/tasks", response_model=list[TaskRecordOut])
def list_tasks(
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    status: str | None = None,
    task_type: str | None = None,
    actor_id: int | None = None,
    limit: int = 100,
):
    query = db.query(TaskRecord).filter_by(workspace_id=user.workspace_id)
    if status:
        query = query.filter(TaskRecord.status == status)
    if task_type:
        query = query.filter(TaskRecord.task_type.like(f"%{task_type}%"))
    if actor_id:
        query = query.filter(TaskRecord.actor_id == actor_id)
    rows = query.order_by(TaskRecord.created_at.desc()).limit(min(max(limit, 1), 500)).all()
    users = _task_user_map(db, [row.actor_id for row in rows if row.actor_id])
    return [_task_out(row, users) for row in rows]


@router.get("/exports/tasks.csv")
def export_tasks_csv(
    status: str | None = None,
    task_type: str | None = None,
    actor_id: int | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    query = db.query(TaskRecord).filter_by(workspace_id=user.workspace_id)
    if status:
        query = query.filter(TaskRecord.status == status)
    if task_type:
        query = query.filter(TaskRecord.task_type.like(f"%{task_type}%"))
    if actor_id:
        query = query.filter(TaskRecord.actor_id == actor_id)
    rows = query.order_by(TaskRecord.created_at.desc()).limit(10000).all()
    users = _task_user_map(db, [row.actor_id for row in rows if row.actor_id])
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["创建时间", "更新时间", "操作账号", "操作人", "任务类型", "状态", "对象类型", "对象ID", "输入", "输出", "错误"])
    for row in rows:
        actor = users.get(row.actor_id)
        writer.writerow([
            row.created_at.isoformat(sep=" ", timespec="seconds"),
            row.updated_at.isoformat(sep=" ", timespec="seconds"),
            actor.username if actor else "",
            actor.display_name if actor else "",
            row.task_type,
            row.status,
            row.target_type,
            row.target_id,
            json.dumps(row.input or {}, ensure_ascii=False),
            json.dumps(row.output or {}, ensure_ascii=False),
            row.error,
        ])
    buffer.seek(0)
    return StreamingResponse(iter([buffer.getvalue().encode("utf-8-sig")]), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=tasks.csv"})


def _task_user_map(db: Session, ids: list[int]) -> dict[int, User]:
    if not ids:
        return {}
    return {row.id: row for row in db.query(User).filter(User.id.in_(set(ids))).all()}


def _task_out(row: TaskRecord, users: dict[int, User]) -> dict[str, Any]:
    actor = users.get(row.actor_id)
    return {
        "id": row.id,
        "actor_id": row.actor_id,
        "actor_username": actor.username if actor else "",
        "actor_name": actor.display_name if actor else "",
        "task_type": row.task_type,
        "status": row.status,
        "target_type": row.target_type,
        "target_id": row.target_id,
        "input": row.input,
        "output": row.output,
        "error": row.error,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


@router.get("/messages/unread-count")
def get_unread_count(db: Session = Depends(get_db), user: User = Depends(current_user)):
    count = db.query(Alert).filter(Alert.workspace_id == user.workspace_id, Alert.status == "pending").count()
    return {"count": count}
