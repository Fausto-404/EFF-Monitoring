import re
from datetime import datetime
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import String, cast, or_
from sqlalchemy.orm import Session

from app.api.deps import current_user, require_not_viewer
from app.models.database import get_db
from app.models.entities import Device, Project, ReportRecord, Template, User
from app.schemas.common import ReportCreate, ReportFacetsOut, ReportGenerateOut, ReportGenerateRequest, ReportOut, ReportUpdate
from app.services.audit_service import write_audit
from app.services.report_service import generate_report

router = APIRouter(prefix="/reports", tags=["reports"])


def _get_report(db: Session, user: User, report_id: int) -> ReportRecord:
    row = db.get(ReportRecord, report_id)
    if not row or row.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="报告不存在")
    return row


def _validate_refs(db: Session, user: User, data: dict[str, Any]) -> None:
    template_id = data.get("template_id")
    if template_id:
        row = db.get(Template, template_id)
        if not row or row.workspace_id != user.workspace_id:
            raise HTTPException(status_code=400, detail="模板不存在")
    project_id = data.get("project_id")
    if project_id:
        row = db.get(Project, project_id)
        if not row or row.workspace_id != user.workspace_id:
            raise HTTPException(status_code=400, detail="项目不存在")
    device_id = data.get("device_id")
    if device_id:
        row = db.get(Device, device_id)
        if not row or row.workspace_id != user.workspace_id:
            raise HTTPException(status_code=400, detail="设备不存在")


def _safe_filename(title: str, suffix: str) -> str:
    name = re.sub(r"[^\w\u4e00-\u9fff.-]+", "_", title).strip("._") or "report"
    return f"{name[:80]}.{suffix}"


@router.get("", response_model=list[ReportOut])
def list_reports(
    q: str | None = None,
    report_category: str | None = None,
    report_key: str | None = None,
    source_type: str | None = None,
    source_module: str | None = None,
    source_id: int | None = None,
    template_id: int | None = None,
    rule_id: int | None = None,
    project_id: int | None = None,
    device_id: int | None = None,
    tag: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    query = db.query(ReportRecord).filter(ReportRecord.workspace_id == user.workspace_id)
    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(
                ReportRecord.title.like(like),
                ReportRecord.content.like(like),
                ReportRecord.report_category.like(like),
                ReportRecord.report_key.like(like),
            )
        )
    if report_category:
        query = query.filter(ReportRecord.report_category == report_category)
    if report_key:
        query = query.filter(ReportRecord.report_key == report_key)
    if source_type:
        query = query.filter(ReportRecord.source_type == source_type)
    if source_module:
        query = query.filter(ReportRecord.source_module == source_module)
    if source_id is not None:
        query = query.filter(ReportRecord.source_id == source_id)
    if template_id is not None:
        query = query.filter(ReportRecord.template_id == template_id)
    if rule_id is not None:
        query = query.filter(ReportRecord.rule_id == rule_id)
    if project_id is not None:
        query = query.filter(ReportRecord.project_id == project_id)
    if device_id is not None:
        query = query.filter(ReportRecord.device_id == device_id)
    if tag:
        query = query.filter(cast(ReportRecord.tags, String).like(f'%"{tag}"%'))
    if start_date:
        query = query.filter(ReportRecord.created_at >= start_date)
    if end_date:
        query = query.filter(ReportRecord.created_at <= end_date)
    return query.order_by(ReportRecord.created_at.desc()).offset(offset).limit(limit).all()


@router.get("/facets", response_model=ReportFacetsOut)
def report_facets(db: Session = Depends(get_db), user: User = Depends(current_user)):
    rows = db.query(ReportRecord).filter(ReportRecord.workspace_id == user.workspace_id).all()
    categories = sorted({row.report_category for row in rows if row.report_category})
    report_keys = sorted({row.report_key for row in rows if row.report_key})
    source_types = sorted({row.source_type for row in rows if row.source_type})
    source_modules = sorted({row.source_module for row in rows if row.source_module})
    tags = sorted({str(tag) for row in rows for tag in (row.tags or []) if str(tag)})
    return ReportFacetsOut(
        categories=categories,
        report_keys=report_keys,
        source_types=source_types,
        source_modules=source_modules,
        tags=tags,
    )


@router.post("", response_model=ReportOut)
def create_report(payload: ReportCreate, db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    data = payload.model_dump()
    _validate_refs(db, user, data)
    row = ReportRecord(workspace_id=user.workspace_id, created_by_id=user.id, updated_by_id=user.id, **data)
    db.add(row)
    db.flush()
    write_audit(db, user, "report.create", "report", row.id, {"title": row.title})
    db.commit()
    db.refresh(row)
    return row


@router.post("/generate", response_model=ReportGenerateOut)
def generate_report_endpoint(
    payload: ReportGenerateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_not_viewer),
):
    content, row = generate_report(db, user, payload)
    if row:
        write_audit(
            db,
            user,
            "report.generate",
            "report",
            row.id,
            {"title": row.title, "source_type": row.source_type, "source_module": row.source_module},
        )
        db.commit()
        db.refresh(row)
    else:
        db.rollback()
    return ReportGenerateOut(content=content, report=row)


@router.get("/{report_id}", response_model=ReportOut)
def get_report(report_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    return _get_report(db, user, report_id)


@router.patch("/{report_id}", response_model=ReportOut)
def update_report(report_id: int, payload: ReportUpdate, db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    row = _get_report(db, user, report_id)
    data = payload.model_dump(exclude_unset=True)
    for key, value in data.items():
        setattr(row, key, value)
    row.updated_by_id = user.id
    write_audit(db, user, "report.update", "report", row.id, {"fields": list(data.keys())})
    db.commit()
    db.refresh(row)
    return row


@router.delete("/{report_id}")
def delete_report(report_id: int, db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    row = _get_report(db, user, report_id)
    write_audit(db, user, "report.delete", "report", row.id, {"title": row.title})
    db.delete(row)
    db.commit()
    return {"ok": True}


@router.post("/{report_id}/duplicate", response_model=ReportOut)
def duplicate_report(report_id: int, db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    row = _get_report(db, user, report_id)
    copied = ReportRecord(
        workspace_id=user.workspace_id,
        title=f"{row.title} 副本",
        report_category=row.report_category,
        report_key=row.report_key,
        source_type=row.source_type,
        source_module=row.source_module,
        source_id=row.source_id,
        template_id=row.template_id,
        rule_id=row.rule_id,
        project_id=row.project_id,
        device_id=row.device_id,
        period_start=row.period_start,
        period_end=row.period_end,
        scope=row.scope or {},
        input_payload=row.input_payload or {},
        render_context=row.render_context or {},
        source_refs=row.source_refs or {},
        summary=row.summary or {},
        content=row.content,
        format=row.format,
        tags=row.tags or [],
        created_by_id=user.id,
        updated_by_id=user.id,
    )
    db.add(copied)
    db.flush()
    write_audit(db, user, "report.duplicate", "report", copied.id, {"source_report_id": row.id})
    db.commit()
    db.refresh(copied)
    return copied


def _export_report(report_id: int, suffix: str, db: Session, user: User):
    row = _get_report(db, user, report_id)
    write_audit(db, user, "report.export", "report", row.id, {"format": suffix})
    db.commit()
    filename = _safe_filename(row.title, suffix)
    media_type = "text/markdown; charset=utf-8" if suffix == "md" else "text/plain; charset=utf-8"
    return StreamingResponse(
        iter([row.content]),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="report.{suffix}"; filename*=UTF-8\'\'{quote(filename)}'},
    )


@router.get("/{report_id}/export.md")
def export_markdown(report_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    return _export_report(report_id, "md", db, user)
