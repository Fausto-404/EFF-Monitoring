from typing import Any

from sqlalchemy.orm import Session

from app.models.entities import AuditLog, User


def write_audit(
    db: Session,
    user: User,
    action: str,
    target_type: str = "",
    target_id: str | int = "",
    detail: dict[str, Any] | None = None,
) -> None:
    db.add(
        AuditLog(
            workspace_id=user.workspace_id,
            actor_id=user.id,
            action=action,
            target_type=target_type,
            target_id=str(target_id) if target_id is not None else "",
            detail=detail or {},
        )
    )
