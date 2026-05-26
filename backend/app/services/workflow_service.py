from datetime import datetime
from typing import Any

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models.entities import Alert, User, AiExperience
from app.services.audit_service import write_audit
from app.services.ip_list_service import add_to_whitelist, block_ip
from app.services.message_service import notify_all, notify_role, notify_users
from app.services.workflow_constants import (
    ACTIVE_GROUP_ROLE,
    CLOSURE_ACTION_LABELS,
    DISPOSAL_ACTION_LABELS,
    DISPOSAL_TARGET_LABELS,
    GROUP_ANALYSIS,
    GROUP_DISPOSAL,
    GROUP_NONE,
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_DISPOSER,
    ROLE_MONITOR,
    STATUS_ANALYSIS,
    STATUS_DISPOSAL,
    STATUS_DISPOSED,
    STATUS_FALSE_POSITIVE,
    STATUS_IGNORED,
    STATUS_LABELS,
    TERMINAL_STATUSES,
    group_for_status,
    normalize_status,
)


def _alert_title(alert: Alert) -> str:
    return alert.event_type or alert.alert_hash or f"告警 {alert.id}"


def _target_ip(alert: Alert, target: str | None) -> str:
    if target == "src_ip":
        return alert.source_ip or ""
    if target == "dst_ip":
        return alert.destination_ip or ""
    return ""


def _user_label(user: User | None) -> str:
    if not user:
        return ""
    return user.display_name or user.username


def _create_pending_experience(db: Session, alert: Alert):
    # 检查是否已存在
    exists = db.query(AiExperience).filter_by(workspace_id=alert.workspace_id, source_alert_id=alert.id).first()
    if exists:
        return
    
    # 创建待生成记录
    row = AiExperience(
        workspace_id=alert.workspace_id,
        knowledge_id=f"EXP-{datetime.utcnow().strftime('%Y%m%d%H%M')}-{alert.id}",
        source_alert_id=alert.id,
        alert_hash=alert.alert_hash,
        title=f"针对 {alert.event_type} 的处置经验",
        status="pending_generation",
        tags=[alert.event_type] if alert.event_type else []
    )
    db.add(row)


def _jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _ensure_current_status(alert: Alert) -> None:
    normalized = normalize_status(alert.status)
    alert.status = normalized
    if not getattr(alert, "current_group", None):
        alert.current_group = group_for_status(normalized)
    if normalized in TERMINAL_STATUSES:
        alert.current_group = GROUP_NONE
        alert.assignee_id = None
        alert.claimed_at = None


def _assert_unstale(alert: Alert, updated_at: datetime | None) -> None:
    if updated_at and alert.updated_at:
        if alert.updated_at.replace(microsecond=0) > updated_at.replace(microsecond=0):
            raise HTTPException(status_code=409, detail="告警已被他人修改，请刷新页面后再试")


def _change_map(alert: Alert, fields: list[str], before: dict[str, Any]) -> dict[str, dict[str, Any]]:
    changes: dict[str, dict[str, Any]] = {}
    for field in fields:
        old_val = before.get(field)
        new_val = getattr(alert, field)
        if old_val != new_val:
            changes[field] = {"old": _jsonable(old_val), "new": _jsonable(new_val)}
    return changes


def _snapshot(alert: Alert) -> dict[str, Any]:
    fields = [
        "status",
        "current_group",
        "assignee_id",
        "claimed_at",
        "analysis_owner_id",
        "disposal_owner_id",
        "disposal_target",
        "disposal_action",
        "disposal_ip",
        "closure_target",
        "closure_action",
        "false_positive_reason",
    ]
    return {field: getattr(alert, field) for field in fields}


def notify_alert_reaches_group(db: Session, alert: Alert, group: str, actor: User | None = None) -> int:
    role = ACTIVE_GROUP_ROLE.get(group)
    if not role:
        return 0
    status_label = STATUS_LABELS.get(alert.status, alert.status)
    title = f"新告警进入{('研判组' if group == GROUP_ANALYSIS else '处置组')}：{_alert_title(alert)}"
    content = f"告警 {alert.alert_hash} 当前状态为【{status_label}】，请及时处理。"
    exclude = {actor.id} if actor else set()
    return notify_role(
        db,
        alert.workspace_id,
        role,
        title,
        content,
        actor=actor,
        alert=alert,
        message_type="workflow",
        payload={"alert_hash": alert.alert_hash, "status": alert.status, "current_group": group},
        exclude_user_ids=exclude,
    )


def can_claim(user: User, alert: Alert) -> bool:
    _ensure_current_status(alert)
    if user.role == ROLE_ADMIN:
        return alert.current_group in ACTIVE_GROUP_ROLE and not alert.assignee_id
    return ACTIVE_GROUP_ROLE.get(alert.current_group) == user.role and not alert.assignee_id


def claim_alert(db: Session, user: User, alert: Alert, *, updated_at: datetime | None = None) -> Alert:
    _ensure_current_status(alert)
    _assert_unstale(alert, updated_at)
    if alert.current_group not in ACTIVE_GROUP_ROLE:
        raise HTTPException(status_code=400, detail="已闭环告警不能认领")
    if alert.assignee_id:
        raise HTTPException(status_code=409, detail="该告警已被认领")
    if user.role != ROLE_ADMIN and ACTIVE_GROUP_ROLE.get(alert.current_group) != user.role:
        raise HTTPException(status_code=403, detail="当前账号不属于该告警所属组")

    before = _snapshot(alert)
    alert.assignee_id = user.id
    alert.claimed_at = datetime.utcnow()
    if alert.current_group == GROUP_ANALYSIS:
        alert.analysis_owner_id = user.id
    elif alert.current_group == GROUP_DISPOSAL:
        alert.disposal_owner_id = user.id
    alert.last_updated_by_id = user.id
    changes = _change_map(alert, list(before.keys()), before)
    write_audit(db, user, "alert.claim", "alert", alert.id, {"alert_hash": alert.alert_hash, "changes": changes})
    return alert


def release_claim(
    db: Session,
    user: User,
    alert: Alert,
    *,
    force: bool = False,
    assign_user_id: int | None = None,
    updated_at: datetime | None = None,
) -> Alert:
    _ensure_current_status(alert)
    _assert_unstale(alert, updated_at)
    if alert.current_group not in ACTIVE_GROUP_ROLE:
        raise HTTPException(status_code=400, detail="已闭环告警不能释放认领")
    if not alert.assignee_id:
        raise HTTPException(status_code=400, detail="该告警尚未认领")
    if not force and user.role != ROLE_ADMIN and alert.assignee_id != user.id:
        raise HTTPException(status_code=403, detail="只能释放自己认领的告警")
    if force and user.role != ROLE_ADMIN:
        raise HTTPException(status_code=403, detail="需要管理员权限")

    before = _snapshot(alert)
    alert.assignee_id = assign_user_id
    alert.claimed_at = datetime.utcnow() if assign_user_id else None
    if assign_user_id and alert.current_group == GROUP_ANALYSIS:
        alert.analysis_owner_id = assign_user_id
    elif assign_user_id and alert.current_group == GROUP_DISPOSAL:
        alert.disposal_owner_id = assign_user_id
    alert.last_updated_by_id = user.id
    changes = _change_map(alert, list(before.keys()), before)
    write_audit(
        db,
        user,
        "alert.force_assign" if force and assign_user_id else "alert.force_release" if force else "alert.release_claim",
        "alert",
        alert.id,
        {"alert_hash": alert.alert_hash, "changes": changes},
    )
    return alert


def assign_alert(db: Session, user: User, alert: Alert, assignee: User, *, updated_at: datetime | None = None) -> Alert:
    if user.role != ROLE_ADMIN:
        raise HTTPException(status_code=403, detail="需要管理员权限")
    _ensure_current_status(alert)
    _assert_unstale(alert, updated_at)
    expected_role = ACTIVE_GROUP_ROLE.get(alert.current_group)
    if not expected_role:
        raise HTTPException(status_code=400, detail="已闭环告警不能重新指派")
    if assignee.workspace_id != alert.workspace_id or not assignee.is_active or assignee.role != expected_role:
        raise HTTPException(status_code=400, detail="请选择所属组内的有效成员")
    before = _snapshot(alert)
    alert.assignee_id = assignee.id
    alert.claimed_at = datetime.utcnow()
    if alert.current_group == GROUP_ANALYSIS:
        alert.analysis_owner_id = assignee.id
    elif alert.current_group == GROUP_DISPOSAL:
        alert.disposal_owner_id = assignee.id
    alert.last_updated_by_id = user.id
    changes = _change_map(alert, list(before.keys()), before)
    write_audit(db, user, "alert.force_assign", "alert", alert.id, {"alert_hash": alert.alert_hash, "changes": changes})
    return alert


def _ensure_claim_for_transition(user: User, alert: Alert, target_status: str) -> None:
    if user.role == ROLE_ADMIN:
        return
    if user.role == ROLE_MONITOR:
        if target_status == STATUS_IGNORED and alert.current_group == GROUP_ANALYSIS and not alert.assignee_id and alert.created_by_id == user.id:
            return
        raise HTTPException(status_code=403, detail="监测组只能忽略自己同步且未被认领的告警")
    if user.role == ROLE_ANALYST:
        if alert.current_group == GROUP_ANALYSIS and alert.assignee_id == user.id and target_status in {STATUS_FALSE_POSITIVE, STATUS_IGNORED, STATUS_DISPOSAL}:
            return
        raise HTTPException(status_code=403, detail="研判组需先认领研判中的告警")
    if user.role == ROLE_DISPOSER:
        if alert.current_group == GROUP_DISPOSAL and alert.assignee_id == user.id and target_status in {STATUS_ANALYSIS, STATUS_FALSE_POSITIVE, STATUS_IGNORED, STATUS_DISPOSED}:
            return
        raise HTTPException(status_code=403, detail="处置组需先认领处置中的告警")
    raise HTTPException(status_code=403, detail="当前角色无权流转告警")


def _validate_transition(user: User, alert: Alert, target_status: str) -> None:
    if target_status not in STATUS_LABELS:
        raise HTTPException(status_code=400, detail="不支持的告警状态")
    
    # 管理员可以无视闭环限制进行回退
    if user.role == ROLE_ADMIN:
        return

    if alert.status in TERMINAL_STATUSES:
        raise HTTPException(status_code=400, detail="已闭环告警不能继续流转")
    if alert.status == STATUS_ANALYSIS and target_status not in {STATUS_FALSE_POSITIVE, STATUS_IGNORED, STATUS_DISPOSAL}:
        raise HTTPException(status_code=400, detail="研判中只能流转为误报、忽略或处置中")
    if alert.status == STATUS_DISPOSAL and target_status not in {STATUS_ANALYSIS, STATUS_FALSE_POSITIVE, STATUS_IGNORED, STATUS_DISPOSED}:
        raise HTTPException(status_code=400, detail="处置中只能退回研判或闭环")


def _terminal_reason(status: str, closure_action: str) -> str:
    if closure_action:
        return CLOSURE_ACTION_LABELS.get(closure_action, closure_action)
    if status == STATUS_FALSE_POSITIVE:
        return "仅误报"
    if status == STATUS_IGNORED:
        return "仅忽略"
    return "已处置"


def transition_alert(
    db: Session,
    user: User,
    alert: Alert,
    *,
    target_status: str,
    disposal_target: str = "",
    disposal_action: str = "",
    closure_target: str = "",
    closure_action: str = "",
    false_positive_reason: str = "",
    updated_at: datetime | None = None,
) -> Alert:
    _ensure_current_status(alert)
    _assert_unstale(alert, updated_at)
    target_status = normalize_status(target_status)
    _validate_transition(user, alert, target_status)
    _ensure_claim_for_transition(user, alert, target_status)

    before = _snapshot(alert)
    actor_label = _user_label(user)
    previous_group = alert.current_group

    if target_status == STATUS_DISPOSAL:
        if disposal_target not in DISPOSAL_TARGET_LABELS:
            raise HTTPException(status_code=400, detail="请选择处置对象")
        if disposal_action not in DISPOSAL_ACTION_LABELS:
            raise HTTPException(status_code=400, detail="请选择处置动作")
        disposal_ip = _target_ip(alert, disposal_target)
        if not disposal_ip:
            raise HTTPException(status_code=400, detail="处置对象没有可用 IP")

        alert.status = STATUS_DISPOSAL
        alert.current_group = GROUP_DISPOSAL
        alert.assignee_id = None
        alert.claimed_at = None
        alert.disposal_target = disposal_target
        alert.disposal_action = disposal_action
        alert.disposal_ip = disposal_ip
        
        # 动态更新威胁等级：处置中动作触发升级（取最高值）
        severity_rank = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        proposed_severity = "unknown"
        if disposal_action in {"block", "repair"}:
            proposed_severity = "medium"
        elif disposal_action == "emergency":
            proposed_severity = "high"
            
        if severity_rank.get(proposed_severity, 0) > severity_rank.get(alert.severity, 0):
            alert.severity = proposed_severity

        if user.role in {ROLE_ANALYST, ROLE_ADMIN}:
            alert.analysis_owner_id = user.id
        if disposal_action == "block":
            block_ip(db, user, disposal_ip, alert=alert, reason="研判流转处置时选择封禁")
        notify_alert_reaches_group(db, alert, GROUP_DISPOSAL, actor=user)

    elif target_status == STATUS_ANALYSIS:
        alert.status = STATUS_ANALYSIS
        alert.current_group = GROUP_ANALYSIS
        alert.assignee_id = None
        alert.claimed_at = None
        alert.severity = "low"
        notify_alert_reaches_group(db, alert, GROUP_ANALYSIS, actor=user)

    elif target_status in TERMINAL_STATUSES:
        if target_status in {STATUS_FALSE_POSITIVE, STATUS_IGNORED}:
            alert.severity = "low"
            
        if previous_group == GROUP_DISPOSAL and target_status == STATUS_FALSE_POSITIVE and not false_positive_reason.strip():
            raise HTTPException(status_code=400, detail="处置组闭环为误报时必须填写误报原因")
        if target_status in {STATUS_FALSE_POSITIVE, STATUS_IGNORED}:
            if closure_action and closure_action not in CLOSURE_ACTION_LABELS:
                raise HTTPException(status_code=400, detail="不支持的闭环动作")
            if target_status == STATUS_FALSE_POSITIVE and closure_action.startswith("ignore"):
                raise HTTPException(status_code=400, detail="误报状态只能选择误报类闭环动作")
            if target_status == STATUS_IGNORED and closure_action.startswith("false_positive"):
                raise HTTPException(status_code=400, detail="忽略状态只能选择忽略类闭环动作")
            needs_whitelist = closure_action in {"ignore_whitelist", "false_positive_whitelist"}
            if needs_whitelist:
                if closure_target not in DISPOSAL_TARGET_LABELS:
                    raise HTTPException(status_code=400, detail="请选择加白对象")
                closure_ip = _target_ip(alert, closure_target)
                if not closure_ip:
                    raise HTTPException(status_code=400, detail="加白对象没有可用 IP")
                add_to_whitelist(db, user, closure_ip, alert=alert, reason=_terminal_reason(target_status, closure_action))
            alert.closure_target = closure_target or ""
            alert.closure_action = closure_action or ("false_positive" if target_status == STATUS_FALSE_POSITIVE else "ignore")
        alert.status = target_status
        alert.current_group = GROUP_NONE
        alert.assignee_id = None
        alert.claimed_at = None
        if false_positive_reason.strip():
            alert.false_positive_reason = false_positive_reason.strip()

        # 核心增强：自动进入经验库待生成队列
        _create_pending_experience(db, alert)

        if previous_group == GROUP_DISPOSAL and target_status == STATUS_FALSE_POSITIVE:
            title = f"处置组纠正为误报：{_alert_title(alert)}"
            content = f"您之前研判的告警 {alert.alert_hash} 已被处置组纠正为【误报】，原因：{alert.false_positive_reason}"
            analyst = db.get(User, alert.analysis_owner_id) if alert.analysis_owner_id else None
            if analyst:
                notify_users(db, [analyst], title, content, actor=user, alert=alert, payload={"reason": alert.false_positive_reason})
            else:
                notify_role(db, alert.workspace_id, ROLE_ANALYST, title, content, actor=user, alert=alert, payload={"reason": alert.false_positive_reason})
        elif previous_group == GROUP_ANALYSIS and target_status in {STATUS_FALSE_POSITIVE, STATUS_IGNORED}:
            notify_role(
                db,
                alert.workspace_id,
                ROLE_MONITOR,
                f"研判组已闭环：{_alert_title(alert)}",
                f"告警 {alert.alert_hash} 已由 {actor_label} 标记为【{STATUS_LABELS[target_status]}】。",
                actor=user,
                alert=alert,
                payload={"status": target_status},
            )

    alert.last_updated_by_id = user.id
    changes = _change_map(alert, list(before.keys()), before)
    write_audit(
        db,
        user,
        "alert.transition",
        "alert",
        alert.id,
        {
            "alert_hash": alert.alert_hash,
            "changes": changes,
            "status_label": STATUS_LABELS.get(alert.status, alert.status),
            "disposal_action_label": DISPOSAL_ACTION_LABELS.get(alert.disposal_action, alert.disposal_action),
            "closure_action_label": CLOSURE_ACTION_LABELS.get(alert.closure_action, alert.closure_action),
        },
    )
    return alert
