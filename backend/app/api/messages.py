from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import current_user, require_admin
from app.models.database import get_db
from app.models.entities import Message, User
from app.schemas.common import MessageOut
from app.services.message_service import mark_message_read

router = APIRouter(prefix="/messages", tags=["messages"])


@router.get("", response_model=list[MessageOut])
def list_messages(
    unread_only: bool = False,
    read_status: str | None = None,
    recipient_id: int | None = None,
    actor_id: int | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    query = db.query(Message).filter_by(workspace_id=user.workspace_id)
    
    # 权限控制：普通用户只能看自己的，管理员可以看所有人
    if user.role != "admin":
        query = query.filter(Message.recipient_id == user.id)
    elif recipient_id:
        query = query.filter(Message.recipient_id == recipient_id)
    
    if unread_only or read_status == "unread":
        query = query.filter(Message.is_read.is_(False))
    elif read_status == "read":
        query = query.filter(Message.is_read.is_(True))
    if actor_id:
        query = query.filter(Message.actor_id == actor_id)
    
    if start_date:
        from app.core.utils import parse_day
        query = query.filter(Message.created_at >= parse_day(start_date))
    if end_date:
        from app.core.utils import parse_day
        query = query.filter(Message.created_at <= parse_day(end_date, end_of_day=True))

    rows = query.order_by(Message.created_at.desc()).offset(offset).limit(limit).all()
    
    # 批量获取关联的用户姓名以提升性能
    user_ids = {r.recipient_id for r in rows} | {r.actor_id for r in rows if r.actor_id}
    user_map = {u.id: u.display_name or u.username for u in db.query(User).filter(User.id.in_(user_ids)).all()} if user_ids else {}
    
    res = []
    for r in rows:
        out = MessageOut.model_validate(r)
        out.recipient_name = user_map.get(r.recipient_id, "未知")
        out.actor_name = user_map.get(r.actor_id, "系统") if r.actor_id else "系统"
        res.append(out)
    return res


@router.get("/unread-count")
def unread_count(db: Session = Depends(get_db), user: User = Depends(current_user)):
    query = db.query(Message).filter_by(workspace_id=user.workspace_id, recipient_id=user.id, is_read=False)
    count = query.count()
    return {"count": count}


@router.delete("/{message_id}")
def delete_message(message_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    row = db.get(Message, message_id)
    if not row or row.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="消息不存在")
    db.delete(row)
    db.commit()
    return {"ok": True, "deleted": 1}


@router.post("/{message_id}/read", response_model=MessageOut)
def read_message(message_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    row = db.get(Message, message_id)
    if not row or row.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="消息不存在")
    
    if row.recipient_id != user.id:
        raise HTTPException(status_code=403, detail="只能操作自己的消息")
        
    mark_message_read(db, row)
    db.commit()
    db.refresh(row)
    
    out = MessageOut.model_validate(row)
    u = db.get(User, row.recipient_id)
    out.recipient_name = u.display_name if u else ""
    if row.actor_id:
        a = db.get(User, row.actor_id)
        out.actor_name = a.display_name if a else "系统"
    else:
        out.actor_name = "系统"
    return out


@router.post("/batch-read")
def batch_read_messages(payload: dict[str, Any], db: Session = Depends(get_db), user: User = Depends(current_user)):
    ids = payload.get("ids", [])
    if not ids:
        return {"ok": True, "updated": 0}
    
    query = db.query(Message).filter(
        Message.workspace_id == user.workspace_id, 
        Message.id.in_(ids), 
        Message.is_read == False,
        Message.recipient_id == user.id
    )
        
    rows = query.all()
    now = datetime.utcnow()
    for row in rows:
        row.is_read = True
        row.read_at = now
    db.commit()
    return {"ok": True, "updated": len(rows)}


@router.post("/read-all")
def read_all_messages(db: Session = Depends(get_db), user: User = Depends(current_user)):
    rows = db.query(Message).filter_by(workspace_id=user.workspace_id, recipient_id=user.id, is_read=False).all()
    now = datetime.utcnow()
    for row in rows:
        row.is_read = True
        row.read_at = now
    db.commit()
    return {"ok": True, "updated": len(rows)}
