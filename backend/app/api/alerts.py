from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import current_user, require_admin, require_not_viewer
from app.models.database import get_db
from app.models.entities import Alert, AuditLog, Device, ParseRule, Setting, User, TaskRecord
from app.schemas.common import (
    AlertAssignRequest,
    AlertBatchTransitionRequest,
    AlertClaimRequest,
    AlertCreate,
    AlertOut,
    AlertTransitionRequest,
    AlertUpdate,
    AuditLogOut,
    ParseRequest,
    ParseResponse,
)
from app.services.ai_service import analyze_alert_with_experience
from app.services.alert_service import create_alert, find_duplicate_alert, normalize_alert_fields
from app.services.audit_service import write_audit
from app.services.task_service import create_task, fail_task, finish_task
from app.services.workflow_constants import STATUS_ANALYSIS, STATUS_LABELS
from app.services.workflow_service import (
    assign_alert,
    claim_alert,
    notify_alert_reaches_group,
    release_claim,
    transition_alert,
)
from output.formatter import render_chat
from integration.webhook import send_record
from app.services.parser_service import parse_text_for_user
from app.models.bootstrap import get_effective_setting
from app.core.utils import parse_day

router = APIRouter(prefix="/alerts", tags=["alerts"])
parse_router = APIRouter(prefix="/logs", tags=["logs"])


def _alert_to_dict(alert: Alert, code: str = "") -> dict[str, Any]:
    return {
        "id": alert.id,
        "alert_code": code,
        "alert_hash": alert.alert_hash,
        "project_id": alert.project_id,
        "device_id": alert.device_id,
        "raw_text": alert.raw_text,
        "parsed_fields": alert.parsed_fields,
        "src_asset_context": alert.src_asset_context,
        "dst_asset_context": alert.dst_asset_context,
        "ti_result": alert.ti_result,
        "ai_result": alert.ai_result,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "event_type": alert.event_type,
        "severity": alert.severity,
        "status": alert.status,
        "current_group": alert.current_group,
        "assignee_id": alert.assignee_id,
        "claimed_at": alert.claimed_at,
        "analysis_owner_id": alert.analysis_owner_id,
        "disposal_owner_id": alert.disposal_owner_id,
        "disposal_target": alert.disposal_target,
        "disposal_action": alert.disposal_action,
        "disposal_ip": alert.disposal_ip,
        "closure_target": alert.closure_target,
        "closure_action": alert.closure_action,
        "false_positive_reason": alert.false_positive_reason,
        "tags": alert.tags,
        "comments": alert.comments,
        "created_by_id": alert.created_by_id,
        "last_updated_by_id": alert.last_updated_by_id,
        "created_at": alert.created_at,
        "updated_at": alert.updated_at,
    }


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


def _enrich_alert(db: Session, user: User, alert: Alert) -> dict[str, Any]:
    codes = _alert_code_map(db, user, [alert])
    return _alert_to_dict(alert, codes.get(alert.id, ""))


def _get_rendering_data(db: Session, user: User, alert: Alert) -> dict[str, Any]:
    """获取用于模板渲染的完整数据集，包含 TI 地理位置等虚拟字段"""
    data = (alert.parsed_fields or {}).copy()
    
    # 注入告警编码
    codes = _alert_code_map(db, user, [alert])
    data["alert_code"] = codes.get(alert.id, "")
    
    # 注入 TI 虚拟字段
    ti = alert.ti_result or {}
    data["src_ip_location"] = (ti.get("src_ip_ti") or {}).get("location_str") or ""
    data["dst_ip_location"] = (ti.get("dst_ip_ti") or {}).get("location_str") or ""
    
    # 注入状态标签
    from app.api.ops import STATUS_LABELS
    data["status_label"] = STATUS_LABELS.get(alert.status, alert.status)
    
    # 注入负责人
    if alert.assignee_id:
        assignee = db.get(User, alert.assignee_id)
        data["assignee_name"] = assignee.display_name if assignee else "未知"
    else:
        data["assignee_name"] = "未分配"
        
    return data


@parse_router.post("/parse", response_model=ParseResponse)
def parse_log(payload: ParseRequest, db: Session = Depends(get_db), user: User = Depends(current_user)):
    result = parse_text_for_user(
        db,
        user,
        payload.text,
        payload.device_id,
        payload.message_template_id or payload.template_id,
        payload.excel_template_id,
    )
    return ParseResponse(**result)


@parse_router.post("/reformat", response_model=ParseResponse)
def reformat_log(payload: dict[str, Any], db: Session = Depends(get_db), user: User = Depends(current_user)):
    # 允许手动修正解析结果后重新渲染模板
    parsed_fields = payload.get("parsed_fields", {})
    device_id = payload.get("device_id")
    message_template_id = payload.get("message_template_id")
    excel_template_id = payload.get("excel_template_id")

    from app.services.parser_service import _base_config, _get_compatible_template, _get_workspace_device
    from app.models.entities import ParseRule
    from app.services.template_service import render_template
    from output.formatter import render_chat, render_excel

    _get_workspace_device(db, user, device_id)

    # 获取字段标签映射以保持格式化一致
    query = db.query(ParseRule).filter(ParseRule.workspace_id == user.workspace_id, ParseRule.enabled.is_(True))
    if device_id:
        query = query.filter((ParseRule.device_id == device_id) | (ParseRule.device_id.is_(None)))
    rules = query.all()
    
    cfg = _base_config()
    cfg["fields"] = {r.field_key: r.field_label for r in rules if r.field_label}

    message_template = _get_compatible_template(db, user, message_template_id, device_id)
    excel_template = _get_compatible_template(db, user, excel_template_id, device_id)

    # 重新构建语义化字典
    semantic_data = {}
    # 注入基础环境变量
    base_values = {
        "current_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "current_date": datetime.now().strftime("%Y-%m-%d"),
        "current_user": user.display_name or user.username,
        "current_username": user.username,
        "device_name": db.get(Device, device_id).name if device_id else "通用设备",
    }
    semantic_data.update({
        "告警ID": "",
        "状态": STATUS_LABELS[STATUS_ANALYSIS],
        "当前时间": base_values["current_time"],
        "当前日期": base_values["current_date"],
        "设备名称": base_values["device_name"],
    })
    
    # 映射解析字段
    for r in rules:
        val = parsed_fields.get(r.field_key)
        if val:
            semantic_data[r.name] = val
    
    # 处理资产语义化
    from app.services.workflow_constants import DISPOSAL_TARGET_LABELS, DISPOSAL_ACTION_LABELS
    semantic_data.update({
        "源资产名称": parsed_fields.get("src_asset_name", ""),
        "目的资产名称": parsed_fields.get("dst_asset_name", ""),
        "处置对象": DISPOSAL_TARGET_LABELS.get(parsed_fields.get("disposal_target", ""), parsed_fields.get("disposal_target", "")),
        "处置动作": DISPOSAL_ACTION_LABELS.get(parsed_fields.get("disposal_action", ""), parsed_fields.get("disposal_action", "")),
    })

    formatted_chat = render_template(message_template.content, semantic_data) if message_template else render_chat(parsed_fields, cfg)
    formatted_excel = render_template(excel_template.content, semantic_data) if excel_template else render_excel(parsed_fields, cfg)
    
    return ParseResponse(
        parsed_fields=parsed_fields,
        formatted_chat=formatted_chat,
        formatted_excel=formatted_excel,
        matched_rules=[],
        ip_list_alerts=[],
        asset_context=parsed_fields.get("asset_context") or {
            "src_asset": parsed_fields.get("src_asset_context") or {},
            "dst_asset": parsed_fields.get("dst_asset_context") or {},
        },
        warnings=[],
    )


@router.post("", response_model=AlertOut)
def create(payload: AlertCreate, db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    duplicate = find_duplicate_alert(db, user, payload.parsed_fields, payload.device_id)
    if duplicate:
        duplicate_codes = _alert_code_map(db, user, [duplicate])
        raise HTTPException(
            status_code=409,
            detail={
                "message": "该解析结果已进入告警工作台，请勿重复添加",
                "alert_id": duplicate_codes.get(duplicate.id) or duplicate.id,
                "alert_hash": duplicate.alert_hash,
                "event_type": duplicate.event_type,
                "created_at": duplicate.created_at.isoformat() if duplicate.created_at else "",
            },
        )
    alert = create_alert(db, user, payload.raw_text, payload.parsed_fields, payload.project_id, payload.device_id, payload.tags, commit=False)
    write_audit(db, user, "alert.create", "alert", alert.id, {"alert_hash": alert.alert_hash, "event_type": alert.event_type})
    notify_alert_reaches_group(db, alert, alert.current_group, actor=user)
    db.commit()
    db.refresh(alert)
    return _enrich_alert(db, user, alert)


@router.get("", response_model=list[AlertOut])
def list_alerts(
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
    status: str | None = None,
    project_id: int | None = None,
    assignee_id: int | None = None,
    current_group: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
    q: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    query = db.query(Alert).filter(Alert.workspace_id == user.workspace_id)
    if status:
        query = query.filter(Alert.status == status)
    if project_id:
        query = query.filter(Alert.project_id == project_id)
    if assignee_id:
        query = query.filter(Alert.assignee_id == assignee_id)
    if current_group:
        query = query.filter(Alert.current_group == current_group)
    if start_date:
        query = query.filter(Alert.created_at >= parse_day(start_date))
    if end_date:
        query = query.filter(Alert.created_at < parse_day(end_date, end_of_day=True))
    if q:
        like = f"%{q}%"
        query = query.filter(
            (Alert.alert_hash.like(like)) | (Alert.source_ip.like(like)) | (Alert.destination_ip.like(like)) | (Alert.event_type.like(like))
        )
    rows = query.order_by(Alert.created_at.desc()).offset(offset).limit(limit).all()
    codes = _alert_code_map(db, user, rows)
    return [_alert_to_dict(row, codes.get(row.id, "")) for row in rows]


@router.get("/{alert_id}", response_model=AlertOut)
def get(alert_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    alert = db.get(Alert, alert_id)
    if not alert or alert.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="告警不存在")
    return _enrich_alert(db, user, alert)


@router.patch("/{alert_id}", response_model=AlertOut)
def update(alert_id: int, payload: AlertUpdate, db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    alert = db.get(Alert, alert_id)
    if not alert or alert.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="告警不存在")
    
    # 乐观锁检查
    if payload.updated_at and alert.updated_at:
        # 去掉微秒差异，进行基本的时间戳比较
        if alert.updated_at.replace(microsecond=0) > payload.updated_at.replace(microsecond=0):
            raise HTTPException(status_code=409, detail="告警已被他人修改，请刷新页面后再试")

    changes = {}
    payload_data = payload.model_dump(exclude_unset=True, exclude={"updated_at"})
    forbidden = {"status", "assignee_id"}
    if forbidden.intersection(payload_data):
        raise HTTPException(status_code=400, detail="状态和负责人请通过告警工作流操作修改")
    for key, value in payload_data.items():
        old_val = getattr(alert, key)
        if old_val != value:
            changes[key] = {"old": old_val, "new": value}
            setattr(alert, key, value)
    
    alert.last_updated_by_id = user.id
    normalize_alert_fields(alert)
    write_audit(db, user, "alert.update", "alert", alert.id, {"alert_hash": alert.alert_hash, "fields": list(payload_data.keys()), "changes": changes})
    db.commit()
    db.refresh(alert)
    return _enrich_alert(db, user, alert)


@router.post("/batch-update")
def batch_update_alerts(payload: dict[str, Any], db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    ids = [int(item) for item in payload.get("ids", []) if item]
    if not ids:
        raise HTTPException(status_code=400, detail="请选择告警")
    allowed = {"tags"}
    payload_changes = {key: value for key, value in payload.get("changes", {}).items() if key in allowed}
    if not payload_changes:
        raise HTTPException(status_code=400, detail="批量状态流转请使用工作流操作")
    
    rows = db.query(Alert).filter(Alert.workspace_id == user.workspace_id, Alert.id.in_(ids)).all()
    found_ids = {row.id for row in rows}
    missing_count = len(ids) - len(found_ids)
    changed_count = 0
    for alert in rows:
        changes = {}
        for key, value in payload_changes.items():
            old_val = getattr(alert, key)
            if old_val != value:
                changes[key] = {"old": old_val, "new": value}
                setattr(alert, key, value)
        if changes:
            changed_count += 1
            alert.last_updated_by_id = user.id
            normalize_alert_fields(alert)
            write_audit(db, user, "alert.batch_update", "alert", alert.id, {
                "alert_hash": alert.alert_hash,
                "fields": list(changes.keys()),
                "changes": changes,
                "batch_size": len(rows),
            })
    db.commit()
    return {"ok": True, "updated": changed_count, "missing": missing_count, "total": len(ids)}


@router.post("/{alert_id}/claim", response_model=AlertOut)
def claim(alert_id: int, payload: AlertClaimRequest | None = None, db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    alert = db.get(Alert, alert_id)
    if not alert or alert.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="告警不存在")
    claim_alert(db, user, alert, updated_at=payload.updated_at if payload else None)
    db.commit()
    db.refresh(alert)
    return _enrich_alert(db, user, alert)


@router.post("/{alert_id}/release-claim", response_model=AlertOut)
def release(alert_id: int, payload: AlertClaimRequest | None = None, db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    alert = db.get(Alert, alert_id)
    if not alert or alert.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="告警不存在")
    release_claim(db, user, alert, updated_at=payload.updated_at if payload else None)
    db.commit()
    db.refresh(alert)
    return _enrich_alert(db, user, alert)


@router.post("/{alert_id}/force-release", response_model=AlertOut)
def force_release(alert_id: int, payload: AlertClaimRequest | None = None, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    alert = db.get(Alert, alert_id)
    if not alert or alert.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="告警不存在")
    release_claim(db, user, alert, force=True, updated_at=payload.updated_at if payload else None)
    db.commit()
    db.refresh(alert)
    return _enrich_alert(db, user, alert)


@router.post("/{alert_id}/assign", response_model=AlertOut)
def assign(alert_id: int, payload: AlertAssignRequest, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    alert = db.get(Alert, alert_id)
    if not alert or alert.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="告警不存在")
    assignee = db.get(User, payload.assignee_id)
    if not assignee or assignee.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="成员不存在")
    assign_alert(db, user, alert, assignee, updated_at=payload.updated_at)
    db.commit()
    db.refresh(alert)
    return _enrich_alert(db, user, alert)


@router.post("/{alert_id}/transition", response_model=AlertOut)
def transition(alert_id: int, payload: AlertTransitionRequest, db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    alert = db.get(Alert, alert_id)
    if not alert or alert.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="告警不存在")
    transition_alert(
        db,
        user,
        alert,
        target_status=payload.status,
        disposal_target=payload.disposal_target,
        disposal_action=payload.disposal_action,
        closure_target=payload.closure_target,
        closure_action=payload.closure_action,
        false_positive_reason=payload.false_positive_reason,
        updated_at=payload.updated_at,
    )
    db.commit()
    db.refresh(alert)
    return _enrich_alert(db, user, alert)


@router.post("/batch-transition")
def batch_transition(payload: AlertBatchTransitionRequest, db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    ids = [int(item) for item in payload.ids if item]
    if not ids:
        raise HTTPException(status_code=400, detail="请选择告警")
    rows = db.query(Alert).filter(Alert.workspace_id == user.workspace_id, Alert.id.in_(ids)).all()
    found_ids = {row.id for row in rows}
    missing_count = len(ids) - len(found_ids)
    updated = 0
    errors: list[dict[str, Any]] = []
    for alert in rows:
        try:
            transition_alert(
                db,
                user,
                alert,
                target_status=payload.status,
                disposal_target=payload.disposal_target,
                disposal_action=payload.disposal_action,
                closure_target=payload.closure_target,
                closure_action=payload.closure_action,
                false_positive_reason=payload.false_positive_reason,
            )
            updated += 1
        except HTTPException as exc:
            errors.append({"id": alert.id, "alert_hash": alert.alert_hash, "detail": exc.detail})
    db.commit()
    return {"ok": True, "updated": updated, "missing": missing_count, "errors": errors, "total": len(ids)}


@router.post("/batch-delete")
def batch_delete_alerts(payload: dict[str, Any], db: Session = Depends(get_db), user: User = Depends(require_admin)):
    ids = [int(item) for item in payload.get("ids", []) if item]
    if not ids:
        raise HTTPException(status_code=400, detail="请选择告警")
    rows = db.query(Alert).filter(Alert.workspace_id == user.workspace_id, Alert.id.in_(ids)).all()
    found_ids = {row.id for row in rows}
    missing_count = len(ids) - len(found_ids)
    count = len(rows)
    for alert in rows:
        db.delete(alert)
    write_audit(db, user, "alert.batch_delete", "alert", ",".join(str(row.id) for row in rows), {"count": count, "alert_hashes": [row.alert_hash for row in rows]})
    db.commit()
    return {"ok": True, "deleted": count, "missing": missing_count, "total": len(ids)}


@router.delete("/{alert_id}")
def delete_alert(alert_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    alert = db.get(Alert, alert_id)
    if not alert or alert.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="告警不存在")
    write_audit(db, user, "alert.delete", "alert", alert.id, {"alert_hash": alert.alert_hash, "event_type": alert.event_type})
    db.delete(alert)
    db.commit()
    return {"ok": True}


@router.post("/{alert_id}/ai-analysis", response_model=AlertOut)
def run_ai(alert_id: int, db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    alert = db.get(Alert, alert_id)
    if not alert or alert.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="告警不存在")
    
    # 防止并发冲突：检查是否有正在运行的相同类型任务
    existing_task = db.query(TaskRecord).filter_by(
        workspace_id=user.workspace_id,
        target_type="alert",
        target_id=str(alert_id),
        task_type="alert.ai_analysis",
        status="running"
    ).first()
    if existing_task:
        raise HTTPException(status_code=409, detail="AI 研判任务正在运行中，请稍后再试")

    ai_settings = get_effective_setting(db, user.workspace_id, user.id, "ai")
    
    # 预先构建语义化数据用于 AI 研判上下文
    rules = db.query(ParseRule).filter_by(workspace_id=user.workspace_id, enabled=True).all()
    semantic_data = {}
    alert_code = _alert_code_map(db, user, [alert]).get(alert.id, "")
    # 系统字段
    semantic_data.update({
        "告警ID": alert_code,
        "告警Hash": alert.alert_hash,
        "状态": STATUS_LABELS.get(alert.status, alert.status),
        "所属组": alert.current_group,
        "设备名称": db.get(Device, alert.device_id).name if alert.device_id else "通用设备",
        "当前日期": alert.created_at.strftime("%Y-%m-%d"),
        "当前时间": alert.created_at.strftime("%Y-%m-%d %H:%M:%S"),
    })
    # 解析字段映射
    for r in rules:
        if not r.device_id or r.device_id == alert.device_id:
            val = alert.parsed_fields.get(r.field_key)
            if val:
                semantic_data[r.name] = val
    # 资产字段
    src_ctx = alert.src_asset_context or {}
    dst_ctx = alert.dst_asset_context or {}
    semantic_data.update({
        "源资产": f"{src_ctx.get('name', '')} ({src_ctx.get('area', '')})",
        "目的资产": f"{dst_ctx.get('name', '')} ({dst_ctx.get('area', '')})",
        "目的资产重要性": dst_ctx.get('criticality', ''),
    })

    task = create_task(db, user, "alert.ai_analysis", "alert", alert.id, {"alert_hash": alert.alert_hash, "model": ai_settings.get("model")})
    try:
        # 使用增强版研判逻辑，支持提示词管理和经验注入
        result, matched_ids = analyze_alert_with_experience(db, user, alert)
        alert.ai_result = result
        alert.last_updated_by_id = user.id
        finish_task(db, task, {"ai_result_length": len(alert.ai_result or ""), "matched_experiences": matched_ids})
    except Exception as exc:
        fail_task(db, task, exc)
        raise
    write_audit(db, user, "alert.ai_analysis", "alert", alert.id, {"alert_hash": alert.alert_hash, "task_id": task.id})
    db.commit()
    db.refresh(alert)
    return _enrich_alert(db, user, alert)


@router.post("/{alert_id}/ti-query", response_model=AlertOut)
def run_ti(alert_id: int, db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    from core.ti_service import query_pair

    alert = db.get(Alert, alert_id)
    if not alert or alert.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="告警不存在")
    
    # 防止并发冲突
    existing_task = db.query(TaskRecord).filter_by(
        workspace_id=user.workspace_id,
        target_type="alert",
        target_id=str(alert_id),
        task_type="alert.ti_query",
        status="running"
    ).first()
    if existing_task:
        raise HTTPException(status_code=409, detail="威胁情报查询任务正在运行中，请稍后再试")

    ti_config = get_effective_setting(db, user.workspace_id, user.id, "ti")
    # 直接将 ti_config 作为 providers 传给 query_pair，它包含了 active_provider 和各厂商 Key
    cfg = {"providers": ti_config or {}}
    
    task = create_task(db, user, "alert.ti_query", "alert", alert.id, {"alert_hash": alert.alert_hash, "src_ip": alert.source_ip, "dst_ip": alert.destination_ip})
    try:
        alert.ti_result = query_pair(alert.source_ip, alert.destination_ip, cfg)
        alert.last_updated_by_id = user.id
        finish_task(db, task, {"has_result": bool(alert.ti_result)})
    except Exception as exc:
        fail_task(db, task, exc)
        raise
    write_audit(db, user, "alert.ti_query", "alert", alert.id, {"alert_hash": alert.alert_hash, "task_id": task.id})
    db.commit()
    db.refresh(alert)
    return _enrich_alert(db, user, alert)


@router.post("/{alert_id}/send-webhook")
def send_alert_webhook(alert_id: int, db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    alert = db.get(Alert, alert_id)
    if not alert or alert.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="告警不存在")
    
    webhook_cfg = get_effective_setting(db, user.workspace_id, user.id, "webhook")
    if not webhook_cfg or webhook_cfg.get("enabled") is False:
        raise HTTPException(status_code=400, detail="Webhook 未配置或已禁用")
        
    task = create_task(db, user, "alert.webhook_send", "alert", alert.id, {"alert_hash": alert.alert_hash})
    
    # 使用增强后的渲染数据
    data = _get_rendering_data(db, user, alert)
    text = render_chat(data, {"fields": {"order": list(data.keys()), "auto_append_extra": True}})
    
    try:
        result = send_record(text, {"webhook": webhook_cfg})
        finish_task(db, task, {"result": result})
    except Exception as exc:
        fail_task(db, task, exc)
        raise
    write_audit(db, user, "alert.webhook_send", "alert", alert.id, {"alert_hash": alert.alert_hash, "result": result, "task_id": task.id})
    db.commit()
    return result


@router.get("/{alert_id}/history", response_model=list[AuditLogOut])
def get_alert_history(alert_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    # 查找直接关联该 alert_id 的日志，以及包含在批量更新中的日志
    query = db.query(AuditLog).filter(
        AuditLog.workspace_id == user.workspace_id,
        AuditLog.target_type == "alert",
        (AuditLog.target_id == str(alert_id)) | (AuditLog.target_id.like(f"%,{alert_id},%") | AuditLog.target_id.like(f"{alert_id},%") | AuditLog.target_id.like(f"%,{alert_id}") | (AuditLog.target_id == str(alert_id)))
    )
    rows = query.order_by(AuditLog.created_at.desc()).limit(100).all()
    
    # 复用 admin.py 中的 _user_map 逻辑进行用户关联展示
    from app.api.admin import _user_map, _audit_out
    users = _user_map(db, [row.actor_id for row in rows if row.actor_id])
    return [_audit_out(row, users) for row in rows]
