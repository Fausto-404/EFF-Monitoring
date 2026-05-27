import csv
import io

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.api.deps import current_user, require_admin
from app.core.security import hash_password
from app.models.database import get_db
from app.models.entities import Alert, AuditLog, Device, Message, Project, User
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
