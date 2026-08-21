import json
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy import DateTime, inspect, text
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.core.settings import get_settings
from app.core.timezone import now
from app.models.database import get_db
from app.models.entities import (
    AiConversation,
    AiExperience,
    AiMemory,
    AiMessage,
    AiPrompt,
    AiRun,
    Alert,
    Asset,
    AssetSegment,
    AuditLog,
    Device,
    Message,
    ParseRule,
    PluginAccessToken,
    Project,
    ReportRecord,
    Setting,
    TaskRecord,
    Template,
    User,
    Workspace,
)
from app.services.audit_service import write_audit

router = APIRouter(prefix="/backup", tags=["backup"])

BACKUP_FORMAT = "eff-monitoring.backup.v1"

# Parent tables first. Restore uses this order; replace deletion uses reverse order.
BACKUP_MODELS = [
    Workspace,
    User,
    Project,
    Device,
    AssetSegment,
    Asset,
    ParseRule,
    Template,
    Setting,
    Alert,
    Message,
    ReportRecord,
    AuditLog,
    TaskRecord,
    AiPrompt,
    AiExperience,
    AiConversation,
    AiMessage,
    AiMemory,
    AiRun,
    PluginAccessToken,
]


def _columns(model) -> dict[str, Any]:
    return {column.key: column for column in inspect(model).mapper.column_attrs}


def _json_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _row_out(row: Any) -> dict[str, Any]:
    return {name: _json_value(getattr(row, name)) for name in _columns(row.__class__)}


def _parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _coerce_row(model, row: dict[str, Any], workspace_id: int) -> dict[str, Any]:
    columns = _columns(model)
    cleaned: dict[str, Any] = {}
    for key, value in row.items():
        column = columns.get(key)
        if not column:
            continue
        if key == "workspace_id":
            cleaned[key] = workspace_id
            continue
        if isinstance(column.columns[0].type, DateTime):
            cleaned[key] = _parse_datetime(value)
        else:
            cleaned[key] = value
    if "workspace_id" in columns:
        cleaned["workspace_id"] = workspace_id
    return cleaned


def _workspace_rows(db: Session, model, workspace_id: int) -> list[Any]:
    if model is Workspace:
        row = db.get(Workspace, workspace_id)
        return [row] if row else []
    columns = _columns(model)
    if "workspace_id" not in columns:
        return []
    return db.query(model).filter(getattr(model, "workspace_id") == workspace_id).order_by(getattr(model, "id").asc()).all()


def _backup_payload(db: Session, user: User) -> dict[str, Any]:
    cfg = get_settings()
    tables: dict[str, list[dict[str, Any]]] = {}
    schema: dict[str, list[str]] = {}
    for model in BACKUP_MODELS:
        table_name = model.__tablename__
        schema[table_name] = list(_columns(model).keys())
        tables[table_name] = [_row_out(row) for row in _workspace_rows(db, model, user.workspace_id)]
    return {
        "format": BACKUP_FORMAT,
        "app": cfg.app_name,
        "exported_at": now().isoformat(),
        "exported_by": {"id": user.id, "username": user.username, "display_name": user.display_name},
        "workspace": _row_out(db.get(Workspace, user.workspace_id)),
        "schema": schema,
        "tables": tables,
    }


def _load_backup(data: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(data.decode("utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=400, detail="备份文件不是有效 JSON") from exc
    if payload.get("format") != BACKUP_FORMAT or not isinstance(payload.get("tables"), dict):
        raise HTTPException(status_code=400, detail="备份文件格式不匹配或版本过旧")
    return payload


def _table_summary(payload: dict[str, Any]) -> list[dict[str, Any]]:
    tables = payload.get("tables") or {}
    summary = []
    for model in BACKUP_MODELS:
        name = model.__tablename__
        backup_fields = set((payload.get("schema") or {}).get(name) or [])
        current_fields = set(_columns(model).keys())
        summary.append({
            "table": name,
            "count": len(tables.get(name) or []),
            "accepted_fields": len(backup_fields.intersection(current_fields)) if backup_fields else len(current_fields),
            "skipped_fields": sorted(backup_fields - current_fields),
            "new_fields": sorted(current_fields - backup_fields) if backup_fields else [],
        })
    return summary


def _clear_workspace(db: Session, user: User) -> None:
    # Delete all data in reverse dependency order
    dialect = db.bind.dialect.name if db.bind else "sqlite"
    for model in reversed(BACKUP_MODELS):
        if model is Workspace:
            continue
        columns = _columns(model)
        if "workspace_id" not in columns:
            continue
        query = db.query(model).filter(getattr(model, "workspace_id") == user.workspace_id)
        if model is User:
            query = query.filter(User.id != user.id)
        query.delete(synchronize_session=False)
    db.flush()
    # PostgreSQL: 重置所有表的序列，防止后续插入 ID 冲突
    if dialect == "postgresql":
        for model in BACKUP_MODELS:
            table_name = model.__tablename__
            try:
                db.execute(text(
                    f"SELECT setval(pg_get_serial_sequence('{table_name}', 'id'), "
                    f"COALESCE((SELECT MAX(id) FROM {table_name}), 1))"
                ))
            except Exception:
                pass


def _restore_model_rows(db: Session, model, rows: list[dict[str, Any]], user: User) -> dict[str, int]:
    columns = _columns(model)
    if model is Workspace:
        return {"created": 0, "updated": 0, "skipped": 1}
    created = updated = skipped = 0
    max_id_seen = 0
    # Foreign key fields for Alert model that reference User
    _alert_fk_fields = ["analysis_owner_id", "disposal_owner_id", "response_owner_id", "created_by_id", "last_updated_by_id", "assignee_id"]
    # Foreign key fields that reference Device
    _alert_device_fk = ["device_id"]
    # Foreign key fields that reference Project
    _alert_project_fk = ["project_id"]

    for raw in rows:
        if not isinstance(raw, dict):
            skipped += 1
            continue
        data = _coerce_row(model, raw, user.workspace_id)
        row_id = data.get("id")
        if row_id is not None:
            max_id_seen = max(max_id_seen, row_id)

        # Special handling for User model - preserve current admin
        if model is User and (row_id == user.id or data.get("username") == user.username):
            current = db.get(User, user.id)
            if current:
                for key, value in data.items():
                    if key in {"id", "workspace_id", "username", "password_hash", "is_active"}:
                        continue
                    if key in columns:
                        setattr(current, key, value)
                updated += 1
            continue

        # Check if record already exists (by original ID)
        existing = db.get(model, row_id) if row_id is not None else None
        if existing and hasattr(existing, "workspace_id") and existing.workspace_id != user.workspace_id:
            existing = None

        if existing:
            # Update existing record
            for key, value in data.items():
                if key in columns and key != "id":
                    setattr(existing, key, value)
            updated += 1
        else:
            # Validate foreign key references before inserting
            if model is Alert:
                for fk_field in _alert_fk_fields:
                    fk_value = data.get(fk_field)
                    if fk_value is not None and not db.get(User, fk_value):
                        data[fk_field] = None
                for fk_field in _alert_device_fk:
                    fk_value = data.get(fk_field)
                    if fk_value is not None and not db.get(Device, fk_value):
                        data[fk_field] = None
                for fk_field in _alert_project_fk:
                    fk_value = data.get(fk_field)
                    if fk_value is not None and not db.get(Project, fk_value):
                        data[fk_field] = None

            # 保留原始 ID，用 savepoint 处理冲突
            savepoint = db.begin_nested()
            try:
                db.add(model(**data))
                db.flush()
                savepoint.commit()
                created += 1
            except Exception:
                savepoint.rollback()
                # ID 冲突时去掉 ID 重试
                data.pop("id", None)
                try:
                    db.add(model(**data))
                    db.flush()
                    created += 1
                except Exception:
                    skipped += 1

    # 同步 PostgreSQL 序列，防止后续插入 ID 冲突
    dialect = db.bind.dialect.name if db.bind else "sqlite"
    if dialect == "postgresql" and max_id_seen > 0:
        try:
            table_name = model.__tablename__
            db.execute(text(
                f"SELECT setval(pg_get_serial_sequence('{table_name}', 'id'), "
                f"GREATEST((SELECT MAX(id) FROM {table_name}), {max_id_seen}))"
            ))
        except Exception:
            pass

    return {"created": created, "updated": updated, "skipped": skipped}


@router.get("/export")
def export_backup(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    payload = _backup_payload(db, user)
    content = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    filename = f"eff-monitoring-backup-{now().strftime('%Y%m%d-%H%M%S')}.json"
    write_audit(db, user, "backup.export", "backup", "workspace", {"tables": {k: len(v) for k, v in payload["tables"].items()}})
    db.commit()
    return StreamingResponse(
        iter([content]),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/inspect")
async def inspect_backup(file: UploadFile = File(...), user: User = Depends(require_admin)):
    payload = _load_backup(await file.read())
    return {
        "format": payload.get("format"),
        "app": payload.get("app"),
        "exported_at": payload.get("exported_at"),
        "workspace": payload.get("workspace") or {},
        "tables": _table_summary(payload),
    }


@router.post("/restore")
async def restore_backup(
    file: UploadFile = File(...),
    mode: str = Form("merge"),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
):
    if mode not in {"merge", "replace"}:
        raise HTTPException(status_code=400, detail="还原模式仅支持 merge 或 replace")
    payload = _load_backup(await file.read())
    if mode == "replace":
        _clear_workspace(db, user)
        db.flush()
    stats: dict[str, dict[str, int]] = {}
    tables = payload.get("tables") or {}
    for model in BACKUP_MODELS:
        try:
            stats[model.__tablename__] = _restore_model_rows(db, model, tables.get(model.__tablename__) or [], user)
            db.flush()
        except Exception as exc:
            import traceback
            traceback.print_exc()
            raise HTTPException(status_code=500, detail=f"还原表 {model.__tablename__} 失败: {str(exc)}")
    write_audit(db, user, "backup.restore", "backup", "workspace", {"mode": mode, "stats": stats})
    db.commit()
    return {"ok": True, "mode": mode, "stats": stats, "compatibility": _table_summary(payload)}
