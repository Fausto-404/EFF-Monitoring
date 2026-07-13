import csv
import io
import json
from datetime import datetime
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.api.deps import current_user, require_admin
from app.core.timezone import now
from app.core.security import hash_password
from app.models.database import get_db
from app.models.entities import Alert, AuditLog, Device, Message, ParseRule, Project, Template, User
from app.schemas.common import (
    AuditLogOut,
    DeviceCreate,
    DeviceOut,
    DeviceUpdate,
    ProjectCreate,
    ProjectOut,
    ProjectUpdate,
    UserCreate,
    UserOut,
    UserUpdate,
)
from app.services.audit_service import write_audit

router = APIRouter(tags=["admin"])
DEVICE_ROLES = {"monitor", "block"}


@router.get("/users", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), user: User = Depends(current_user)):
    return db.query(User).filter_by(workspace_id=user.workspace_id).order_by(User.id.asc()).all()


@router.post("/users", response_model=UserOut)
def create_user(payload: UserCreate, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    exists = db.query(User).filter_by(username=payload.username).first()
    if exists:
        raise HTTPException(status_code=409, detail="用户名已存在")
    row = User(
        workspace_id=user.workspace_id,
        username=payload.username,
        display_name=payload.display_name,
        password_hash=hash_password(payload.password),
        role=payload.role,
        is_active=payload.is_active,
    )
    db.add(row)
    db.flush()
    write_audit(db, user, "user.create", "user", row.id, {"username": row.username, "role": row.role})
    db.commit()
    db.refresh(row)
    return row


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(user_id: int, payload: UserUpdate, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    row = db.get(User, user_id)
    if not row or row.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="用户不存在")
    changes = payload.model_dump(exclude_unset=True)
    if "password" in changes:
        row.password_hash = hash_password(changes.pop("password"))
    for key, value in changes.items():
        setattr(row, key, value)
    write_audit(db, user, "user.update", "user", row.id, {"fields": list(payload.model_dump(exclude_unset=True).keys())})
    db.commit()
    db.refresh(row)
    return row


@router.delete("/users/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    row = db.get(User, user_id)
    if not row or row.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="用户不存在")
    if row.id == user.id:
        raise HTTPException(status_code=400, detail="不能删除当前登录用户")
    db.query(Alert).filter(Alert.workspace_id == user.workspace_id, Alert.assignee_id == row.id).update({"assignee_id": None})
    db.query(Alert).filter(Alert.workspace_id == user.workspace_id, Alert.analysis_owner_id == row.id).update({"analysis_owner_id": None})
    db.query(Alert).filter(Alert.workspace_id == user.workspace_id, Alert.disposal_owner_id == row.id).update({"disposal_owner_id": None})
    db.query(Alert).filter(Alert.workspace_id == user.workspace_id, Alert.created_by_id == row.id).update({"created_by_id": None})
    db.query(Alert).filter(Alert.workspace_id == user.workspace_id, Alert.last_updated_by_id == row.id).update({"last_updated_by_id": None})
    db.query(Message).filter(Message.workspace_id == user.workspace_id, Message.recipient_id == row.id).delete()
    write_audit(db, user, "user.delete", "user", row.id, {"username": row.username})
    db.delete(row)
    db.commit()
    return {"ok": True}


@router.get("/projects", response_model=list[ProjectOut])
def list_projects(db: Session = Depends(get_db), user: User = Depends(current_user)):
    return db.query(Project).filter_by(workspace_id=user.workspace_id).order_by(Project.id.asc()).all()


@router.post("/projects", response_model=ProjectOut)
def create_project(payload: ProjectCreate, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    row = Project(workspace_id=user.workspace_id, **payload.model_dump())
    db.add(row)
    db.flush()
    write_audit(db, user, "project.create", "project", row.id, {"name": row.name})
    db.commit()
    db.refresh(row)
    return row


@router.patch("/projects/{project_id}", response_model=ProjectOut)
def update_project(project_id: int, payload: ProjectUpdate, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    row = db.get(Project, project_id)
    if not row or row.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="项目不存在")
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(row, key, value)
    write_audit(db, user, "project.update", "project", row.id, {"fields": list(payload.model_dump(exclude_unset=True).keys())})
    db.commit()
    db.refresh(row)
    return row


@router.delete("/projects/{project_id}")
def delete_project(project_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    row = db.get(Project, project_id)
    if not row or row.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="项目不存在")
    db.query(Alert).filter(Alert.workspace_id == user.workspace_id, Alert.project_id == row.id).update({"project_id": None})
    write_audit(db, user, "project.delete", "project", row.id, {"name": row.name})
    db.delete(row)
    db.commit()
    return {"ok": True}


@router.get("/devices", response_model=list[DeviceOut])
def list_devices(db: Session = Depends(get_db), user: User = Depends(current_user)):
    return db.query(Device).filter_by(workspace_id=user.workspace_id).order_by(Device.id.asc()).all()


@router.post("/devices", response_model=DeviceOut)
def create_device(payload: DeviceCreate, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    if payload.device_role not in DEVICE_ROLES:
        raise HTTPException(status_code=400, detail="设备类型仅支持 monitor 或 block")
    row = Device(workspace_id=user.workspace_id, **payload.model_dump())
    db.add(row)
    db.flush()
    write_audit(db, user, "device.create", "device", row.id, {"name": row.name, "vendor": row.vendor})
    db.commit()
    db.refresh(row)
    return row


@router.patch("/devices/{device_id}", response_model=DeviceOut)
def update_device(device_id: int, payload: DeviceUpdate, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    row = db.get(Device, device_id)
    if not row or row.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="设备不存在")
    if payload.device_role and payload.device_role not in DEVICE_ROLES:
        raise HTTPException(status_code=400, detail="设备类型仅支持 monitor 或 block")
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(row, key, value)
    write_audit(db, user, "device.update", "device", row.id, {"fields": list(payload.model_dump(exclude_unset=True).keys())})
    db.commit()
    db.refresh(row)
    return row


@router.delete("/devices/{device_id}")
def delete_device(device_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    row = db.get(Device, device_id)
    if not row or row.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="设备不存在")
    db.query(Alert).filter(Alert.workspace_id == user.workspace_id, Alert.device_id == row.id).update({"device_id": None})
    write_audit(db, user, "device.delete", "device", row.id, {"name": row.name})
    db.delete(row)
    db.commit()
    return {"ok": True}


@router.get("/devices/{device_id}/package")
def export_device_package(device_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    device = db.get(Device, device_id)
    if not device or device.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="设备不存在")

    rules = db.query(ParseRule).filter_by(workspace_id=user.workspace_id, device_id=device.id).order_by(ParseRule.priority.asc(), ParseRule.id.asc()).all()
    templates = db.query(Template).filter_by(workspace_id=user.workspace_id, device_id=device.id).order_by(Template.type.asc(), Template.id.asc()).all()
    payload = {
        "package_type": "eff-monitoring.device-rule-template-package",
        "package_version": "1.0",
        "exported_at": now(db, user.workspace_id).isoformat(timespec="seconds"),
        "source_device": {
            "name": device.name,
            "vendor": device.vendor,
            "product": device.product,
            "device_ip": device.version,
            "version": device.version,
            "device_role": device.device_role,
        },
        "rules": [
            {
                "name": row.name,
                "field_key": row.field_key,
                "field_label": row.field_label,
                "match_type": row.match_type,
                "pattern": row.pattern,
                "priority": row.priority,
                "enabled": row.enabled,
                "match_all": row.match_all,
                "sample_log": row.sample_log,
            }
            for row in rules
            if not row.is_meta
        ],
        "templates": [
            {
                "name": row.name,
                "type": row.type,
                "content": row.content,
                "variables": row.variables or [],
                "scope": row.scope,
                "is_default": row.is_default,
            }
            for row in templates
        ],
    }
    write_audit(db, user, "device.package_export", "device", device.id, {"name": device.name, "rules": len(payload["rules"]), "templates": len(payload["templates"])})
    db.commit()

    data = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    filename = f"{device.name}-rules-templates.json"
    return StreamingResponse(
        iter([data]),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename)}"},
    )


@router.post("/devices/{device_id}/package")
async def import_device_package(device_id: int, file: UploadFile = File(...), db: Session = Depends(get_db), user: User = Depends(require_admin)):
    device = db.get(Device, device_id)
    if not device or device.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="设备不存在")

    try:
        raw = await file.read()
        payload = json.loads(raw.decode("utf-8-sig"))
    except Exception as exc:
        raise HTTPException(status_code=400, detail="导入包必须是有效 JSON 文件") from exc

    if payload.get("package_type") != "eff-monitoring.device-rule-template-package":
        raise HTTPException(status_code=400, detail="导入包类型不正确")
    rules = payload.get("rules")
    templates = payload.get("templates")
    if not isinstance(rules, list) or not isinstance(templates, list):
        raise HTTPException(status_code=400, detail="导入包缺少 rules 或 templates")

    rule_result = _import_device_rules(db, user.workspace_id, device.id, rules)
    template_result = _import_device_templates(db, user.workspace_id, device.id, templates)
    write_audit(
        db,
        user,
        "device.package_import",
        "device",
        device.id,
        {
            "name": device.name,
            "source_device": (payload.get("source_device") or {}).get("name", ""),
            "rules": rule_result,
            "templates": template_result,
        },
    )
    db.commit()
    return {"ok": True, "device_id": device.id, "rules": rule_result, "templates": template_result}


@router.get("/audit-logs", response_model=list[AuditLogOut])
def list_audit_logs(
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    action: str | None = None,
    actor_id: int | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    query = db.query(AuditLog).filter_by(workspace_id=user.workspace_id)
    if action:
        query = query.filter(AuditLog.action.like(f"%{action}%"))
    if actor_id:
        query = query.filter(AuditLog.actor_id == actor_id)
    rows = query.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit).all()
    users = _user_map(db, [row.actor_id for row in rows if row.actor_id])
    return [_audit_out(row, users) for row in rows]


@router.get("/exports/audit-logs.csv")
def export_audit_logs_csv(
    action: str | None = None,
    actor_id: int | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    query = db.query(AuditLog).filter_by(workspace_id=user.workspace_id)
    if action:
        query = query.filter(AuditLog.action.like(f"%{action}%"))
    if actor_id:
        query = query.filter(AuditLog.actor_id == actor_id)
    rows = query.order_by(AuditLog.created_at.desc()).limit(10000).all()
    users = _user_map(db, [row.actor_id for row in rows if row.actor_id])
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["时间", "操作账号", "操作人", "动作", "对象类型", "对象ID", "详情"])
    for row in rows:
        actor = users.get(row.actor_id)
        writer.writerow([
            row.created_at.isoformat(sep=" ", timespec="seconds"),
            actor.username if actor else "",
            actor.display_name if actor else "",
            row.action,
            row.target_type,
            row.target_id,
            row.detail,
        ])
    buffer.seek(0)
    return StreamingResponse(iter([buffer.getvalue().encode("utf-8-sig")]), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=audit_logs.csv"})


def _user_map(db: Session, ids: list[int]) -> dict[int, User]:
    if not ids:
        return {}
    return {row.id: row for row in db.query(User).filter(User.id.in_(set(ids))).all()}


def _clean_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _import_device_rules(db: Session, workspace_id: int, device_id: int, items: list[Any]) -> dict[str, int]:
    created = 0
    updated = 0
    skipped = 0
    for item in items:
        if not isinstance(item, dict):
            skipped += 1
            continue
        name = _clean_str(item.get("name")).strip()
        field_key = _clean_str(item.get("field_key")).strip()
        match_type = _clean_str(item.get("match_type"), "regex").strip() or "regex"
        pattern = _clean_str(item.get("pattern"))
        if not name or not field_key or match_type not in {"regex", "fixed", "builtin"}:
            skipped += 1
            continue

        row = db.query(ParseRule).filter_by(workspace_id=workspace_id, device_id=device_id, name=name).first()
        if not row:
            row = ParseRule(workspace_id=workspace_id, device_id=device_id, name=name, field_key=field_key, pattern=pattern)
            db.add(row)
            created += 1
        else:
            updated += 1
        row.field_key = field_key
        row.field_label = _clean_str(item.get("field_label"))
        row.match_type = match_type
        row.pattern = pattern
        row.priority = int(item.get("priority") or 100)
        row.enabled = bool(item.get("enabled", True))
        row.match_all = bool(item.get("match_all", False))
        row.is_meta = False
        row.sample_log = _clean_str(item.get("sample_log"))
    return {"created": created, "updated": updated, "skipped": skipped}


def _import_device_templates(db: Session, workspace_id: int, device_id: int, items: list[Any]) -> dict[str, int]:
    created = 0
    updated = 0
    skipped = 0
    for item in items:
        if not isinstance(item, dict):
            skipped += 1
            continue
        name = _clean_str(item.get("name")).strip()
        template_type = _clean_str(item.get("type"), "message").strip() or "message"
        content = _clean_str(item.get("content"))
        if not name or template_type not in {"message", "excel", "csv"}:
            skipped += 1
            continue

        row = db.query(Template).filter_by(workspace_id=workspace_id, device_id=device_id, name=name).first()
        if not row:
            row = Template(workspace_id=workspace_id, device_id=device_id, name=name, type=template_type, content=content)
            db.add(row)
            created += 1
        else:
            updated += 1
        row.type = template_type
        row.content = content
        raw_vars = item.get("variables") or []
        row.variables = [str(value) for value in raw_vars] if isinstance(raw_vars, list) else []
        row.scope = _clean_str(item.get("scope"), "team") or "team"
        row.is_default = bool(item.get("is_default", False))
        if row.is_default:
            db.flush()
            db.query(Template).filter(
                Template.workspace_id == workspace_id,
                Template.type == row.type,
                Template.id != row.id,
            ).update({"is_default": False})
    return {"created": created, "updated": updated, "skipped": skipped}


def _audit_out(row: AuditLog, users: dict[int, User]) -> dict:
    actor = users.get(row.actor_id)
    return {
        "id": row.id,
        "actor_id": row.actor_id,
        "actor_username": actor.username if actor else "",
        "actor_name": actor.display_name if actor else "",
        "action": row.action,
        "target_type": row.target_type,
        "target_id": row.target_id,
        "detail": row.detail,
        "created_at": row.created_at,
    }
