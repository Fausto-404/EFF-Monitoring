import json
import re
from typing import Any

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.timezone import now as app_now
from app.models.entities import ReportRecord, Template, User
from app.schemas.common import ReportGenerateRequest


PLACEHOLDER_RE = re.compile(r"{{\s*([^{}]+?)\s*}}")


def _stringify_value(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, indent=2)
    if value is None:
        return ""
    return str(value)


def render_simple_template(template_text: str, context: dict[str, Any]) -> str:
    def replace(match: re.Match[str]) -> str:
        key = match.group(1).strip()
        if key not in context:
            return match.group(0)
        return _stringify_value(context[key])

    return PLACEHOLDER_RE.sub(replace, template_text or "")


def build_base_context(payload: ReportGenerateRequest, current_time=None) -> dict[str, Any]:
    now = current_time or app_now()
    period = ""
    if payload.period_start or payload.period_end:
        start = payload.period_start.isoformat(sep=" ") if payload.period_start else ""
        end = payload.period_end.isoformat(sep=" ") if payload.period_end else ""
        period = f"{start} - {end}".strip(" -")

    title = payload.title or ""
    category = payload.report_category or ""
    return {
        "报告标题": title,
        "report_title": title,
        "报告分类": category,
        "report_category": category,
        "当前时间": now.strftime("%Y-%m-%d %H:%M:%S"),
        "current_time": now.strftime("%Y-%m-%d %H:%M:%S"),
        "当前日期": now.strftime("%Y-%m-%d"),
        "current_date": now.strftime("%Y-%m-%d"),
        "统计开始时间": payload.period_start.isoformat(sep=" ") if payload.period_start else "",
        "period_start": payload.period_start.isoformat(sep=" ") if payload.period_start else "",
        "统计结束时间": payload.period_end.isoformat(sep=" ") if payload.period_end else "",
        "period_end": payload.period_end.isoformat(sep=" ") if payload.period_end else "",
        "统计周期": period,
        "period": period,
    }


def _summary(content: str, payload: ReportGenerateRequest, current_time=None) -> dict[str, Any]:
    generated_at = current_time or app_now()
    return {
        "content_length": len(content),
        "word_count": len(content.split()),
        "source_type": payload.source_type,
        "source_module": payload.source_module,
        "generated_at": generated_at.isoformat(),
    }


def generate_report(db: Session, user: User, payload: ReportGenerateRequest) -> tuple[str, ReportRecord | None]:
    current_time = app_now(db, user.workspace_id)
    context = build_base_context(payload, current_time)
    context.update(payload.render_context or {})

    if payload.content is not None and payload.content != "":
        content = payload.content
    elif payload.template_id:
        template = db.get(Template, payload.template_id)
        if not template or template.workspace_id != user.workspace_id:
            raise HTTPException(status_code=404, detail="模板不存在")
        content = render_simple_template(template.content, context)
    elif payload.raw_template is not None and payload.raw_template != "":
        content = render_simple_template(payload.raw_template, context)
    else:
        raise HTTPException(status_code=400, detail="需要提供 content、template_id 或 raw_template")

    if not payload.save:
        return content, None

    now_label = current_time.strftime("%Y-%m-%d %H:%M:%S")
    title = payload.title or f"{payload.report_category or '未分类报告'} - {now_label}"
    input_payload = payload.model_dump(mode="json")
    row = ReportRecord(
        workspace_id=user.workspace_id,
        title=title,
        report_category=payload.report_category,
        report_key=payload.report_key,
        source_type=payload.source_type or "manual",
        source_module=payload.source_module or "report_center",
        source_id=payload.source_id,
        template_id=payload.template_id,
        rule_id=payload.rule_id,
        project_id=payload.project_id,
        device_id=payload.device_id,
        period_start=payload.period_start,
        period_end=payload.period_end,
        scope=payload.scope or {},
        input_payload=input_payload,
        render_context=context,
        source_refs=payload.source_refs or {},
        summary=_summary(content, payload, current_time),
        content=content,
        format="markdown",
        tags=payload.tags or [],
        created_by_id=user.id,
        updated_by_id=user.id,
    )
    db.add(row)
    db.flush()
    return content, row
