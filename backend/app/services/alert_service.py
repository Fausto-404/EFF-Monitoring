import hashlib
import json
import secrets
from typing import Any

from sqlalchemy.orm import Session

from app.models.entities import Alert, User
from app.services.workflow_constants import GROUP_ANALYSIS, STATUS_ANALYSIS

DEDUP_IGNORED_FIELDS = {
    "timestamp", "time", "alert_time", "msg_time", "log_time", "current_time", "current_date",
    "received_at", "received_time", "request_id", "parse_timestamp", "received_timestamp",
    "id", "alert_id", "hash", "alert_hash", "dedup_hash", "raw_text", "alert_code",
    "created_by_name", "last_updated_by_name", "assignee_name", "status_label",
    "ti_result", "ai_result", "current_user", "current_username"
}


def _stable_for_dedup(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _stable_for_dedup(val)
            for key, val in sorted(value.items())
            if key not in DEDUP_IGNORED_FIELDS and not key.startswith("template_")
        }
    if isinstance(value, list):
        return [_stable_for_dedup(item) for item in value]
    if isinstance(value, str):
        return value.strip()
    return value


def alert_dedup_hash(parsed_fields: dict | None, device_id: int | None = None) -> str:
    stable_payload = {
        "device_id": device_id,
        "parsed_fields": _stable_for_dedup(parsed_fields or {}),
    }
    raw = json.dumps(stable_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def generate_alert_hash(workspace_id: int, alert_id: int) -> str:
    raw = f"{workspace_id}:{alert_id}:{secrets.token_hex(16)}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def generate_unique_alert_hash(db: Session, workspace_id: int, alert_id: int) -> str:
    for _ in range(5):
        value = generate_alert_hash(workspace_id, alert_id)
        exists = db.query(Alert.id).filter(Alert.workspace_id == workspace_id, Alert.alert_hash == value).first()
        if not exists:
            return value
    return hashlib.sha256(f"{workspace_id}:{alert_id}:{secrets.token_hex(32)}".encode("utf-8")).hexdigest()


def find_duplicate_alert(db: Session, user: User, parsed_fields: dict | None, device_id: int | None = None) -> Alert | None:
    dedup_hash = alert_dedup_hash(parsed_fields, device_id)
    return (
        db.query(Alert)
        .filter(
            Alert.workspace_id == user.workspace_id,
            Alert.device_id == device_id,
            Alert.dedup_hash == dedup_hash,
        )
        .order_by(Alert.created_at.asc(), Alert.id.asc())
        .first()
    )


def normalize_alert_fields(alert: Alert) -> None:
    fields = alert.parsed_fields or {}
    alert.source_ip = str(fields.get("src_ip") or "")
    alert.destination_ip = str(fields.get("dst_ip") or "")
    alert.event_type = str(fields.get("event_type") or fields.get("event_name") or "")
    asset_context = fields.get("asset_context") or {}
    alert.src_asset_context = fields.get("src_asset_context") or asset_context.get("src_asset") or {}
    alert.dst_asset_context = fields.get("dst_asset_context") or asset_context.get("dst_asset") or {}
    alert.dedup_hash = alert_dedup_hash(fields, alert.device_id)


def create_alert(db: Session, user: User, raw_text: str, parsed_fields: dict, project_id=None, device_id=None, tags=None, commit: bool = True) -> Alert:
    alert = Alert(
        workspace_id=user.workspace_id,
        project_id=project_id,
        device_id=device_id,
        raw_text=raw_text,
        parsed_fields=parsed_fields or {},
        src_asset_context=(parsed_fields or {}).get("src_asset_context") or ((parsed_fields or {}).get("asset_context") or {}).get("src_asset") or {},
        dst_asset_context=(parsed_fields or {}).get("dst_asset_context") or ((parsed_fields or {}).get("asset_context") or {}).get("dst_asset") or {},
        status=STATUS_ANALYSIS,
        current_group=GROUP_ANALYSIS,
        severity="low",
        assignee_id=None,
        tags=tags or [],
        created_by_id=user.id,
        last_updated_by_id=user.id,
    )
    normalize_alert_fields(alert)
    db.add(alert)
    db.flush()
    if not alert.alert_hash:
        alert.alert_hash = generate_unique_alert_hash(db, alert.workspace_id, alert.id)
    if commit:
        db.commit()
        db.refresh(alert)
    return alert
