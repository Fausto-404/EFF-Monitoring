from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import current_user
from app.models.database import get_db
from app.models.entities import Setting, User
from app.schemas.common import SettingOut, SettingUpdate
from app.services.audit_service import write_audit

router = APIRouter(prefix="/settings", tags=["settings"])


SECRET_KEYS = {"api_key", "secret", "http_cookie", "password", "token"}


def _mask(value):
    if isinstance(value, dict):
        return {key: ("******" if key in SECRET_KEYS and val else _mask(val)) for key, val in value.items()}
    if isinstance(value, list):
        return [_mask(item) for item in value]
    return value


def _merge_settings(incoming, current):
    """
    深度合并配置：
    1. 如果 incoming 中某个 key 的值为 '******'，从 current 中还原旧值。
    2. 如果 incoming 中没有某个 key，但 current 中有，则保留 current 中的值（非破坏性合并）。
    3. 如果两者都是字典，则递归合并。
    """
    if not isinstance(current, dict):
        return incoming
    if not isinstance(incoming, dict):
        return incoming
        
    merged = current.copy()
    for key, value in incoming.items():
        if key in SECRET_KEYS and value == "******":
            merged[key] = current.get(key, "")
        elif isinstance(value, dict) and isinstance(current.get(key), dict):
            merged[key] = _merge_settings(value, current.get(key))
        else:
            merged[key] = value
    return merged


@router.get("", response_model=list[dict[str, Any]])
def list_settings(db: Session = Depends(get_db), user: User = Depends(current_user)):
        # 管理员看全部（全员+个人），普通成员仅看个人
    query = db.query(Setting).filter(Setting.workspace_id == user.workspace_id)
    
    if user.role == "admin":
        # 获取全员配置和该管理员的个人配置
        rows = query.filter((Setting.user_id.is_(None)) | (Setting.user_id == user.id)).all()
    else:
        # 普通成员仅允许看到并管理自己的个人配置
        rows = query.filter(Setting.user_id == user.id).all()
        
    res = []
    for row in rows:
        scope = "global" if row.user_id is None else "personal"
        res.append({
            "key": row.key,
            "value": _mask(row.value or {}),
            "scope": scope,
            "user_id": row.user_id,
            "updated_at": row.updated_at
        })
    return res


@router.patch("/{key}", response_model=dict[str, Any])
def update_setting(
    key: str, 
    payload: SettingUpdate, 
    scope: str = Query("global", pattern="^(global|personal)$"),
    db: Session = Depends(get_db), 
    user: User = Depends(current_user)
):
    # 权限校验
    if scope == "global" and user.role != "admin":
        raise HTTPException(status_code=403, detail="仅管理员可修改全员配置")

    target_user_id = user.id if scope == "personal" else None
    
    row = db.query(Setting).filter_by(
        workspace_id=user.workspace_id, 
        key=key, 
        user_id=target_user_id
    ).first()
    
    if not row:
        # 新增配置
        row = Setting(
            workspace_id=user.workspace_id, 
            key=key, 
            user_id=target_user_id,
            value=payload.value
        )
        db.add(row)
    else:
        # 乐观锁检查
        if payload.updated_at and row.updated_at:
            if row.updated_at.replace(microsecond=0) > payload.updated_at.replace(microsecond=0):
                raise HTTPException(status_code=409, detail="配置已被他人修改，请刷新页面后再试")

        # 非破坏性合并更新
        current = row.value or {}
        row.value = _merge_settings(payload.value, current)
        
    write_audit(db, user, "setting.update", "setting", f"{scope}.{key}", {"key": key, "scope": scope})
    db.commit()
    db.refresh(row)
    return {
        "key": row.key, 
        "value": _mask(row.value or {}),
        "scope": scope,
        "updated_at": row.updated_at
    }
