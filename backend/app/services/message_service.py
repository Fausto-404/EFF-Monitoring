from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.entities import Alert, Message, User


def create_message(
    db: Session,
    recipient: User,
    title: str,
    content: str = "",
    *,
    actor: User | None = None,
    alert: Alert | None = None,
    message_type: str = "workflow",
    payload: dict[str, Any] | None = None,
) -> Message:
    row = Message(
        workspace_id=recipient.workspace_id,
        recipient_id=recipient.id,
        actor_id=actor.id if actor else None,
        alert_id=alert.id if alert else None,
        alert_hash=alert.alert_hash if alert else "",
        title=title,
        content=content,
        message_type=message_type,
        payload=payload or {},
    )
    db.add(row)
    return row


def notify_users(
    db: Session,
    users: list[User],
    title: str,
    content: str = "",
    *,
    actor: User | None = None,
    alert: Alert | None = None,
    message_type: str = "workflow",
    payload: dict[str, Any] | None = None,
    exclude_user_ids: set[int] | None = None,
) -> int:
    exclude_user_ids = exclude_user_ids or set()
    count = 0
    seen: set[int] = set()
    for user in users:
        if not user.is_active or user.id in exclude_user_ids or user.id in seen:
            continue
        create_message(db, user, title, content, actor=actor, alert=alert, message_type=message_type, payload=payload)
        seen.add(user.id)
        count += 1
    return count


def notify_role(
    db: Session,
    workspace_id: int,
    role: str,
    title: str,
    content: str = "",
    *,
    actor: User | None = None,
    alert: Alert | None = None,
    message_type: str = "workflow",
    payload: dict[str, Any] | None = None,
    exclude_user_ids: set[int] | None = None,
) -> int:
    users = db.query(User).filter_by(workspace_id=workspace_id, role=role, is_active=True).all()
    return notify_users(
        db,
        users,
        title,
        content,
        actor=actor,
        alert=alert,
        message_type=message_type,
        payload=payload,
        exclude_user_ids=exclude_user_ids,
    )


def notify_all(
    db: Session,
    workspace_id: int,
    title: str,
    content: str = "",
    *,
    actor: User | None = None,
    alert: Alert | None = None,
    message_type: str = "workflow",
    payload: dict[str, Any] | None = None,
    exclude_user_ids: set[int] | None = None,
) -> int:
    users = db.query(User).filter_by(workspace_id=workspace_id, is_active=True).all()
    return notify_users(
        db,
        users,
        title,
        content,
        actor=actor,
        alert=alert,
        message_type=message_type,
        payload=payload,
        exclude_user_ids=exclude_user_ids,
    )


def mark_message_read(db: Session, message: Message) -> None:
    if not message.is_read:
        message.is_read = True
        message.read_at = datetime.utcnow()
