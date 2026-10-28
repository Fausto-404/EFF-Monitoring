"""Persistent, bounded-memory workspace backup export for the worker process."""

import json
import os
from pathlib import Path

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.backup import BACKUP_FORMAT, BACKUP_MODELS, _columns, _row_out
from app.core.settings import get_settings
from app.core.timezone import now
from app.models.database import SessionLocal
from app.models.entities import BackupJob, User, Workspace


def backup_directory() -> Path:
    directory = Path(get_settings().backup_dir).resolve()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    return directory


def backup_path(job_id: int) -> Path:
    return backup_directory() / f"backup-{job_id}.json"


def recover_interrupted_jobs() -> None:
    # The compose deployment runs one backup worker. A killed worker can safely
    # rebuild an unfinished file from scratch on its next start.
    with SessionLocal() as db:
        for job in db.query(BackupJob).filter(BackupJob.status == "running").all():
            job.status = "queued"
            job.current_table = ""
            job.processed_rows = 0
            job.bytes_written = 0
        db.commit()


def claim_backup_job() -> int | None:
    with SessionLocal() as db:
        job = (
            db.query(BackupJob)
            .filter(BackupJob.status == "queued")
            .order_by(BackupJob.created_at.asc(), BackupJob.id.asc())
            .with_for_update(skip_locked=True)
            .first()
        )
        if not job:
            return None
        job.status = "running"
        job.updated_at = now(db, job.workspace_id)
        job_id = job.id
        db.commit()
        return job_id


def _progress(job_id: int, table: str, processed: int, total: int, written: int) -> None:
    with SessionLocal() as db:
        job = db.get(BackupJob, job_id)
        if job:
            job.current_table = table
            job.processed_rows = processed
            job.total_rows = total
            job.bytes_written = written
            job.updated_at = now(db, job.workspace_id)
            db.commit()


def run_backup_job(job_id: int) -> None:
    destination = backup_path(job_id)
    temporary = destination.with_suffix(".json.part")
    try:
        with SessionLocal() as db:
            job = db.get(BackupJob, job_id)
            if not job or job.status != "running":
                return
            workspace_id = job.workspace_id
            actor = db.get(User, job.actor_id)
            workspace = db.get(Workspace, workspace_id)
            if not actor or not workspace:
                raise RuntimeError("备份所属用户或工作区不存在")
            counts = {
                model.__tablename__: (
                    1 if model is Workspace else db.query(func.count(model.id)).filter(model.workspace_id == workspace_id).scalar() or 0
                )
                for model in BACKUP_MODELS
            }
            total = sum(counts.values())
            schema = {model.__tablename__: list(_columns(model).keys()) for model in BACKUP_MODELS}
            header = {
                "format": BACKUP_FORMAT,
                "app": get_settings().app_name,
                "exported_at": now(db, workspace_id).isoformat(),
                "exported_by": {"id": actor.id, "username": actor.username, "display_name": actor.display_name},
                "workspace": _row_out(workspace),
                "schema": schema,
            }
            processed = 0
            written = 0
            temporary.unlink(missing_ok=True)
            with temporary.open("wb") as output:
                def write(value: str) -> None:
                    nonlocal written
                    data = value.encode("utf-8")
                    output.write(data)
                    written += len(data)

                write(json.dumps(header, ensure_ascii=False, separators=(",", ":"))[:-1])
                write(',"tables":{')
                for index, model in enumerate(BACKUP_MODELS):
                    name = model.__tablename__
                    if index:
                        write(",")
                    write(json.dumps(name) + ":[")
                    last_id = 0
                    first = True
                    while True:
                        if model is Workspace:
                            rows = [workspace] if last_id == 0 else []
                        else:
                            rows = (
                                db.query(model)
                                .filter(model.workspace_id == workspace_id, model.id > last_id)
                                .order_by(model.id.asc())
                                .limit(100)
                                .all()
                            )
                        if not rows:
                            break
                        for row in rows:
                            if not first:
                                write(",")
                            write(json.dumps(_row_out(row), ensure_ascii=False, separators=(",", ":")))
                            first = False
                            last_id = row.id
                            processed += 1
                        output.flush()
                        _progress(job_id, name, processed, total, written)
                        if model is Workspace:
                            break
                    write("]")
                    _progress(job_id, name, processed, total, written)
                write("}}")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, destination)

        with SessionLocal() as db:
            job = db.get(BackupJob, job_id)
            if job:
                job.status = "success"
                job.current_table = ""
                job.processed_rows = processed
                job.total_rows = total
                job.bytes_written = written
                job.filename = f"eff-monitoring-backup-{now(db, job.workspace_id).strftime('%Y%m%d-%H%M%S')}.json"
                job.completed_at = now(db, job.workspace_id)
                job.updated_at = job.completed_at
                db.commit()
    except Exception as exc:
        temporary.unlink(missing_ok=True)
        with SessionLocal() as db:
            job = db.get(BackupJob, job_id)
            if job:
                job.status = "failed"
                job.error = str(exc)[:2000]
                job.completed_at = now(db, job.workspace_id)
                job.updated_at = job.completed_at
                db.commit()
        raise
