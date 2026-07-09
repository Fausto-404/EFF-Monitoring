from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from app.api.deps import current_user, require_not_viewer
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


def _clean_masks(value):
    """
    递归移除所有值为 '******' 的键，防止前端传来的掩码被误存到数据库。
    """
    if isinstance(value, dict):
        return {k: _clean_masks(v) for k, v in value.items() if v != "******"}
    if isinstance(value, list):
        return [_clean_masks(item) for item in value]
    return value


def _merge_settings(incoming, current):
    """
    递归合并配置：
    1. 如果 incoming 中某个 key 的值为 '******'，从 current 中还原旧值。
    2. 递归处理嵌套字典。
    """
    if not isinstance(current, dict) or not isinstance(incoming, dict):
        return incoming
        
    merged = current.copy()
    for key, value in incoming.items():
        if key in SECRET_KEYS and value == "******":
            # 还原脱敏值
            merged[key] = current.get(key, "")
        elif isinstance(value, dict) and isinstance(current.get(key), dict):
            # 递归合并字典
            merged[key] = _merge_settings(value, current.get(key))
        else:
            # 直接覆盖
            merged[key] = value
    return merged


@router.get("", response_model=list[dict[str, Any]])
def list_settings(db: Session = Depends(get_db), user: User = Depends(current_user)):
    # 管理员看全部（全员+个人），普通成员仅看个人
    query = db.query(Setting).filter(Setting.workspace_id == user.workspace_id)
    
    if user.role == "admin":
        rows = query.filter((Setting.user_id.is_(None)) | (Setting.user_id == user.id)).all()
    else:
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
    user: User = Depends(require_not_viewer)
):
    # 权限校验
    if scope == "global" and user.role != "admin":
        raise HTTPException(status_code=403, detail="仅管理员可修改全员配置")

    target_user_id = user.id if scope == "personal" else None
    
    # 精准查找行
    query = db.query(Setting).filter(
        Setting.workspace_id == user.workspace_id,
        Setting.key == key
    )
    if target_user_id is None:
        query = query.filter(Setting.user_id.is_(None))
    else:
        query = query.filter(Setting.user_id == target_user_id)
        
    row = query.first()
    
    # 诊断日志
    print(f"[Settings] Update: key={key}, scope={scope}, user_id={target_user_id}, row_id={row.id if row else 'NEW'}")
    
    if not row:
        # 新增配置：移除所有前端传来的掩码，防止损坏数据
        # 不再继承全员配置，确保账号隔离与安全性，防止越权查看全员配置
        new_value = _clean_masks(payload.value)
        
        row = Setting(
            workspace_id=user.workspace_id, 
            key=key, 
            user_id=target_user_id,
            value=new_value
        )
        db.add(row)
    else:
        # 乐观锁检查
        if payload.updated_at and row.updated_at:
            if row.updated_at.replace(microsecond=0) > payload.updated_at.replace(microsecond=0):
                raise HTTPException(status_code=409, detail="配置已被他人修改，请刷新页面后再试")

        # 递归合并更新
        current_data = row.value or {}
        row.value = _merge_settings(payload.value, current_data)
        # 显式标记 JSON 已修改，确保 SQLAlchemy 写入
        flag_modified(row, "value")
        
    write_audit(db, user, "setting.update", "setting", f"{scope}.{key}", {"key": key, "scope": scope})
    db.commit()
    db.refresh(row)
    
    return {
        "key": row.key, 
        "value": _mask(row.value or {}),
        "scope": scope,
        "updated_at": row.updated_at
    }
