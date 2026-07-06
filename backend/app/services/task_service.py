from typing import Any

from sqlalchemy.orm import Session

from app.models.entities import TaskRecord, User


def create_task(
    db: Session,
    user: User,
    task_type: str,
    target_type: str = "",
    target_id: str | int = "",
    input_data: dict[str, Any] | None = None,
) -> TaskRecord:
    task = TaskRecord(
        workspace_id=user.workspace_id,
        actor_id=user.id,
        task_type=task_type,
        status="running",
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else "",
        input=input_data or {},
    )
    db.add(task)
    db.flush()
    return task


def finish_task(db: Session, task: TaskRecord, output: dict[str, Any] | None = None) -> TaskRecord:
    task.status = "success"
    task.output = output or {}
    db.flush()
    return task


def fail_task(db: Session, task: TaskRecord, error: Exception | str) -> TaskRecord:
    task.status = "failed"
    task.error = str(error)
    db.flush()
    return task
