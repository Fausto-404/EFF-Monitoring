from __future__ import annotations

import hashlib
import secrets
import time
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.api.deps import current_user
from app.core.security import decode_access_token
from app.core.timezone import now
from app.models.bootstrap import get_effective_setting
from app.models.database import get_db
from app.models.entities import AiRun, Alert, Device, PluginAccessToken, Template, User
from app.services.ai_service import investigate_threat
from app.services.alert_service import create_alert, normalize_alert_fields
from app.services.parser_service import parse_text_for_user
from app.services.task_service import create_task, fail_task, finish_task
from app.services.audit_service import write_audit
from app.services.workflow_service import notify_alert_reaches_group
from integration.webhook import send_record

router = APIRouter(prefix="/plugin", tags=["plugin"])
bearer = HTTPBearer(auto_error=False)

PLUGIN_SCOPES = {
    "plugin:devices:read",
    "plugin:parse",
    "plugin:alert:create",
    "plugin:ai:investigate",
}


def _safe_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="参数格式无效")


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _issue_pat() -> tuple[str, str, str]:
    token = f"eff_pat_{secrets.token_urlsafe(32)}"
    return token, token[:18], _token_hash(token)


def _authenticate_plugin_user(
    db: Session,
    credentials: HTTPAuthorizationCredentials | None,
    required_scopes: set[str],
) -> User:
    token = credentials.credentials.strip() if credentials else ""
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="缺少插件认证 Token")

    jwt_payload = decode_access_token(token)
    if jwt_payload and jwt_payload.get("sub"):
        user = db.get(User, int(jwt_payload["sub"]))
        if not user or not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="无效用户")
        return user

    row = db.query(PluginAccessToken).filter_by(token_hash=_token_hash(token)).first()
    if not row or row.revoked_at:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="插件密钥无效或已吊销")
    current = now(db, row.workspace_id)
    if row.expires_at and row.expires_at < current:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="插件密钥已过期")
    scopes = set(row.scopes or [])
    if not required_scopes.issubset(scopes):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="插件密钥权限不足")
    user = db.get(User, row.created_by_id) if row.created_by_id else None
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="插件密钥缺少可用用户上下文")
    row.last_used_at = current
    db.commit()
    return user


def plugin_user(*scopes: str):
    required = set(scopes)

    def dependency(
        db: Session = Depends(get_db),
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    ) -> User:
        return _authenticate_plugin_user(db, credentials, required)

    return dependency


def _device_out(device: Device) -> dict[str, Any]:
    patterns = []
    raw_patterns = getattr(device, "browser_url_patterns", None)
    if isinstance(raw_patterns, list):
        patterns = [str(item) for item in raw_patterns if item]
    if not patterns:
        patterns = ["http://*/*", "https://*/*"]
    return {
        "id": device.id,
        "name": device.name,
        "vendor": device.vendor,
        "product": device.product,
        "url_patterns": patterns,
    }


def _parse_page_payload(db: Session, user: User, payload: dict[str, Any]) -> dict[str, Any]:
    text = str(payload.get("text") or "")
    device_id = _safe_int(payload.get("device_id"))
    message_template_id = _safe_int(payload.get("message_template_id") or payload.get("template_id"))
    if not text.strip():
        raise HTTPException(status_code=400, detail="页面文本不能为空")
    if device_id:
        device = db.get(Device, device_id)
        if not device or device.workspace_id != user.workspace_id:
            raise HTTPException(status_code=404, detail="插件设备不存在")
    parsed = parse_text_for_user(db, user, text, device_id, message_template_id)
    device = db.get(Device, device_id) if device_id else None
    fields = parsed.get("parsed_fields") or {}
    src_context = dict(fields.get("src_asset_context") or (fields.get("asset_context") or {}).get("src_asset") or {})
    dst_context = dict(fields.get("dst_asset_context") or (fields.get("asset_context") or {}).get("dst_asset") or {})
    for item in parsed.get("ip_list_alerts") or fields.get("ip_list_alerts") or []:
        ip = str(item.get("ip") or item.get("value") or "")
        target = dst_context if ip and ip == str(fields.get("dst_ip") or "") else src_context
        tags = list(target.get("tags") or [])
        list_name = str(item.get("list") or item.get("type") or "")
        label = "黑名单命中" if list_name == "blacklist" else "白名单命中" if list_name == "whitelist" else str(item.get("label") or "名单命中")
        tags.append({"type": list_name or "list", "label": label, "severity": "danger" if list_name == "blacklist" else "success"})
        target["tags"] = tags
    return {
        "parse_token": None,
        "device": {"id": device.id, "name": device.name} if device else None,
        "fields": fields,
        "formatted_chat": parsed.get("formatted_chat") or "",
        "formatted_excel": parsed.get("formatted_excel") or "",
        "matched_rules": parsed.get("matched_rules") or [],
        "src_context": src_context,
        "dst_context": dst_context,
        "asset_context": {"src_asset": src_context, "dst_asset": dst_context},
        "warnings": parsed.get("warnings") or [],
    }


def _plugin_template_out(template: Template) -> dict[str, Any]:
    return {
        "id": template.id,
        "name": template.name,
        "type": template.type,
        "device_id": template.device_id,
        "is_default": template.is_default,
    }


def _source_context_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    page = payload.get("page") if isinstance(payload.get("page"), dict) else {}
    source = payload.get("source") if isinstance(payload.get("source"), dict) else {}
    source_url = str(source.get("url") or page.get("url") or "").strip()
    source_title = str(source.get("title") or page.get("title") or "").strip()
    source_type = str(source.get("type") or "browser_assistant").strip() or "browser_assistant"
    context: dict[str, Any] = {"type": source_type}
    if source_url:
        context["url"] = source_url
    if source_title:
        context["title"] = source_title
    return context


@router.get("/me")
def plugin_me(db: Session = Depends(get_db), user: User = Depends(plugin_user())):
    ai_settings = get_effective_setting(db, user.workspace_id, user.id, "ai") or {}
    return {
        "platform": "EFF-Monitoring",
        "version": "2.2.1",
        "workspace": {"id": user.workspace_id},
        "user": {"id": user.id, "username": user.username, "display_name": user.display_name},
        "capabilities": {
            "platform_ai": bool(ai_settings),
            "quick_ai_independent": True,
            "smart_investigation": True,
            "pat_auth": True,
        },
    }


@router.get("/devices")
def plugin_devices(db: Session = Depends(get_db), user: User = Depends(plugin_user("plugin:devices:read"))):
    devices = (
        db.query(Device)
        .filter(Device.workspace_id == user.workspace_id, Device.browser_assistant_enabled.is_(True))
        .order_by(Device.name.asc())
        .all()
    )
    return {"devices": [_device_out(item) for item in devices]}


@router.get("/templates")
def plugin_templates(
    type: str = "message",
    device_id: int | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(plugin_user("plugin:parse")),
):
    query = db.query(Template).filter(Template.workspace_id == user.workspace_id, Template.type == type)
    if device_id:
        device = db.get(Device, device_id)
        if not device or device.workspace_id != user.workspace_id:
            raise HTTPException(status_code=404, detail="插件设备不存在")
        query = query.filter((Template.device_id == device_id) | (Template.device_id.is_(None)))
    else:
        query = query.filter(Template.device_id.is_(None))
    rows = query.order_by(Template.is_default.desc(), Template.updated_at.desc()).all()
    return {"templates": [_plugin_template_out(item) for item in rows]}


@router.post("/parse")
def plugin_parse(payload: dict[str, Any], db: Session = Depends(get_db), user: User = Depends(plugin_user("plugin:parse"))):
    return _parse_page_payload(db, user, payload)


@router.post("/alerts")
def plugin_create_alert(payload: dict[str, Any], db: Session = Depends(get_db), user: User = Depends(plugin_user("plugin:alert:create"))):
    parsed = _parse_page_payload(db, user, payload)
    source_context = _source_context_from_payload(payload)
    alert = create_alert(
        db,
        user,
        str(payload.get("text") or ""),
        parsed.get("fields") or {},
        device_id=payload.get("device_id"),
        tags=["browser_assistant"],
        commit=False,
    )
    alert.source_context = source_context
    write_audit(
        db,
        user,
        "alert.create",
        "alert",
        alert.id,
        {
            "alert_hash": alert.alert_hash,
            "event_type": alert.event_type,
            "source": "browser_assistant",
        },
    )
    notify_alert_reaches_group(db, alert, alert.current_group, actor=user)
    db.commit()
    db.refresh(alert)
    return {
        "id": alert.id,
        "alert_id": alert.id,
        "alert_hash": alert.alert_hash,
        "status": alert.status,
        "device": parsed.get("device"),
        "fields": parsed.get("fields") or {},
        "formatted_chat": parsed.get("formatted_chat") or "",
        "formatted_excel": parsed.get("formatted_excel") or "",
        "src_context": parsed.get("src_context") or {},
        "dst_context": parsed.get("dst_context") or {},
        "source_context": alert.source_context or {},
        "workbench_url": f"/alerts?alert_id={alert.id}",
    }


@router.post("/alerts/{alert_id}/send-webhook")
def plugin_send_alert_webhook(
    alert_id: int,
    payload: dict[str, Any] | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(plugin_user("plugin:alert:create")),
):
    alert = db.get(Alert, alert_id)
    if not alert or alert.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="告警不存在")
    webhook_cfg = get_effective_setting(db, user.workspace_id, user.id, "webhook")
    if not webhook_cfg or webhook_cfg.get("enabled") is False:
        raise HTTPException(status_code=400, detail="Webhook 未配置或已禁用")

    message_template_id = _safe_int((payload or {}).get("message_template_id") or (payload or {}).get("template_id"))
    parsed = parse_text_for_user(db, user, alert.raw_text or "", alert.device_id, message_template_id)
    text = parsed.get("formatted_chat") or ""
    if not text.strip():
        raise HTTPException(status_code=400, detail="通报消息为空")

    task = create_task(db, user, "plugin.alert.webhook_send", "alert", alert.id, {"alert_hash": alert.alert_hash})
    try:
        result = send_record(text, {"webhook": webhook_cfg})
        if not result.get("success"):
            raise HTTPException(status_code=502, detail=result)
        finish_task(db, task, {"result": result})
    except Exception as exc:
        fail_task(db, task, exc)
        raise
    write_audit(db, user, "plugin.alert.webhook_send", "alert", alert.id, {"alert_hash": alert.alert_hash, "task_id": task.id, "result": result})
    db.commit()
    return {"ok": True, "result": result}


@router.post("/investigate")
def plugin_investigate(payload: dict[str, Any], db: Session = Depends(get_db), user: User = Depends(plugin_user("plugin:ai:investigate"))):
    parsed = _parse_page_payload(db, user, payload)
    ai_settings = get_effective_setting(db, user.workspace_id, user.id, "ai")
    alert = Alert(
        workspace_id=user.workspace_id,
        device_id=payload.get("device_id"),
        raw_text=str(payload.get("text") or ""),
        parsed_fields=parsed.get("fields") or {},
        source_context=_source_context_from_payload(payload),
        status="analysis",
        current_group="analysis",
        severity="unknown",
        reported_by_name=user.display_name or user.username,
        created_by_id=user.id,
        last_updated_by_id=user.id,
    )
    db.add(alert)
    db.flush()
    normalize_alert_fields(alert)
    if not alert.alert_hash:
        alert.alert_hash = f"plugin-{alert.id}"
    run = AiRun(
        workspace_id=user.workspace_id,
        actor_id=user.id,
        source="plugin_smart",
        agent="alert_investigation",
        reasoning_mode="smart",
        status="running",
        model=str(ai_settings.get("model") or ""),
        target_type="plugin_page",
        target_id=alert.alert_hash,
        input={"device_id": payload.get("device_id"), "page": payload.get("page") or {}},
    )
    db.add(run)
    started = time.monotonic()
    try:
        result, _matched_ids = investigate_threat(
            db,
            user,
            source="plugin",
            alert=alert,
            include_recommended_actions=False,
            planner_timeout=30,
            analysis_timeout=150,
            reflect_timeout=30,
        )
        result["recommended_actions"] = []
        run.status = "success"
        run.result = result
        run.timing_ms = int((time.monotonic() - started) * 1000)
        db.delete(alert)
        db.commit()
    except Exception as exc:
        run.status = "failed"
        run.error = str(exc)
        run.timing_ms = int((time.monotonic() - started) * 1000)
        db.delete(alert)
        db.commit()
        raise
    return {"result": result}


@router.post("/tokens")
def create_plugin_token(payload: dict[str, Any], db: Session = Depends(get_db), user: User = Depends(current_user)):
    scopes = payload.get("scopes") or sorted(PLUGIN_SCOPES)
    scopes = [str(item) for item in scopes if str(item) in PLUGIN_SCOPES]
    if not scopes:
        raise HTTPException(status_code=400, detail="至少需要一个插件权限")
    expires_at = payload.get("expires_at")
    if isinstance(expires_at, str) and expires_at:
        try:
            expires_at = datetime.fromisoformat(expires_at.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            raise HTTPException(status_code=400, detail="expires_at 时间格式无效")
    else:
        expires_at = None
    token, prefix, digest = _issue_pat()
    row = PluginAccessToken(
        workspace_id=user.workspace_id,
        created_by_id=user.id,
        name=str(payload.get("name") or "浏览器助手密钥"),
        token_prefix=prefix,
        token_hash=digest,
        scopes=scopes,
        expires_at=expires_at,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return {
        "id": row.id,
        "name": row.name,
        "token": token,
        "token_prefix": row.token_prefix,
        "scopes": row.scopes,
        "expires_at": row.expires_at,
        "created_at": row.created_at,
    }


@router.get("/tokens")
def list_plugin_tokens(db: Session = Depends(get_db), user: User = Depends(current_user)):
    rows = (
        db.query(PluginAccessToken)
        .filter_by(workspace_id=user.workspace_id, created_by_id=user.id)
        .order_by(PluginAccessToken.created_at.desc())
        .limit(100)
        .all()
    )
    return [
        {
            "id": row.id,
            "name": row.name,
            "token_prefix": row.token_prefix,
            "scopes": row.scopes or [],
            "expires_at": row.expires_at,
            "revoked_at": row.revoked_at,
            "last_used_at": row.last_used_at,
            "created_at": row.created_at,
        }
        for row in rows
    ]


@router.delete("/tokens/{token_id}")
def delete_plugin_token(token_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    row = db.get(PluginAccessToken, token_id)
    if not row or row.workspace_id != user.workspace_id or row.created_by_id != user.id:
        raise HTTPException(status_code=404, detail="插件密钥不存在")
    db.delete(row)
    db.commit()
    return {"ok": True}
