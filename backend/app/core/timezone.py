from datetime import datetime
from os import getenv
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


DEFAULT_TIMEZONE = getenv("APP_TIMEZONE", "UTC")
SYSTEM_TIME_KEY = "system_time"

COMMON_TIMEZONES = [
    "UTC",
    "Asia/Shanghai",
    "Asia/Hong_Kong",
    "Asia/Tokyo",
    "Asia/Singapore",
    "Europe/London",
    "Europe/Berlin",
    "America/New_York",
    "America/Los_Angeles",
]


def is_valid_timezone(timezone_name: str) -> bool:
    try:
        ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError:
        return False
    return True


def normalize_system_time(value: dict[str, Any] | None) -> dict[str, Any]:
    data = value or {}
    timezone_name = str(data.get("timezone") or DEFAULT_TIMEZONE).strip() or "UTC"
    if not is_valid_timezone(timezone_name):
        timezone_name = "UTC"
    ntp_servers = data.get("ntp_servers")
    if not isinstance(ntp_servers, list):
        ntp_servers = ["pool.ntp.org", "time.apple.com"]
    ntp_servers = [str(item).strip() for item in ntp_servers if str(item).strip()]
    return {
        "timezone": timezone_name,
        "ntp_enabled": bool(data.get("ntp_enabled", True)),
        "ntp_servers": ntp_servers,
    }


def get_system_time_config(db=None, workspace_id: int | None = None) -> dict[str, Any]:
    if db is not None and workspace_id is not None:
        from app.models.entities import Setting

        row = db.query(Setting).filter_by(workspace_id=workspace_id, user_id=None, key=SYSTEM_TIME_KEY).first()
        if row:
            return normalize_system_time(row.value)
    return normalize_system_time(None)


def get_app_timezone(db=None, workspace_id: int | None = None) -> ZoneInfo:
    return ZoneInfo(get_system_time_config(db, workspace_id)["timezone"])


def now(db=None, workspace_id: int | None = None) -> datetime:
    """Return app-local time as a naive datetime for existing DB columns."""
    return datetime.now(get_app_timezone(db, workspace_id)).replace(tzinfo=None)


def today_start(db=None, workspace_id: int | None = None) -> datetime:
    return now(db, workspace_id).replace(hour=0, minute=0, second=0, microsecond=0)


def today_end(db=None, workspace_id: int | None = None) -> datetime:
    return now(db, workspace_id).replace(hour=23, minute=59, second=59, microsecond=999999)
