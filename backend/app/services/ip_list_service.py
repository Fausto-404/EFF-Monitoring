from ipaddress import AddressValueError, ip_address, ip_network
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session

from app.core.timezone import now
from app.models.entities import Alert, Setting, User
from app.services.audit_service import write_audit
from app.services.message_service import notify_all
from core.lists import is_ip_in_list


def get_ip_list_setting(db: Session, workspace_id: int) -> Setting:
    row = db.query(Setting).filter_by(workspace_id=workspace_id, key="ip_lists").first()
    if not row:
        row = Setting(
            workspace_id=workspace_id,
            user_id=None,
            key="ip_lists",
            value={"whitelist": [], "blacklist": [], "items": []},
            created_at=now(db, workspace_id),
            updated_at=now(db, workspace_id),
        )
        db.add(row)
        db.flush()
    return row


def detect_value_type(value: str) -> str:
    text = (value or "").strip()
    if "/" in text:
        ip_network(text, strict=False)
        return "cidr"
    if "-" in text:
        _range_bounds(text)
        return "range"
    ip_address(text)
    return "single"


def _range_bounds(value: str):
    start_text, end_text = [part.strip() for part in value.split("-", 1)]
    start_ip = ip_address(start_text)
    if "." in start_text and "." not in end_text and ":" not in end_text:
        prefix = start_text.rsplit(".", 1)[0]
        end_text = f"{prefix}.{end_text}"
    elif ":" in start_text and ":" not in end_text and "." not in end_text:
        prefix = start_text.rsplit(":", 1)[0]
        end_text = f"{prefix}:{end_text}"
    end_ip = ip_address(end_text)
    if start_ip.__class__ is not end_ip.__class__:
        raise ValueError("IP 范围起止地址版本不一致")
    if start_ip > end_ip:
        raise ValueError("IP 范围起始地址不能大于结束地址")
    return start_ip, end_ip


def normalize_items(items: list[Any]) -> list[str]:
    return list(dict.fromkeys(item.strip() for item in items if isinstance(item, str) and item.strip()))


def _item_from_value(value: str, list_type: str, *, description: str = "", source: str = "manual") -> dict[str, Any]:
    text = str(value or "").strip()
    value_type = detect_value_type(text)
    current = now()
    return {
        "id": uuid4().hex,
        "list_type": list_type,
        "value": text,
        "value_type": value_type,
        "description": description,
        "source": source,
        "created_at": current.isoformat(sep=" ", timespec="seconds"),
        "updated_at": current.isoformat(sep=" ", timespec="seconds"),
    }


def normalize_item_rows(rows: list[Any]) -> list[dict[str, Any]]:
    normalized = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        list_type = row.get("list_type")
        value = str(row.get("value") or "").strip()
        if list_type not in {"whitelist", "blacklist"} or not value:
            continue
        try:
            value_type = detect_value_type(value)
        except (ValueError, AddressValueError):
            continue
        key = (list_type, value)
        if key in seen:
            continue
        seen.add(key)
        current = now().isoformat(sep=" ", timespec="seconds")
        normalized.append({
            "id": str(row.get("id") or uuid4().hex),
            "list_type": list_type,
            "value": value,
            "value_type": value_type,
            "description": str(row.get("description") or ""),
            "source": str(row.get("source") or "manual"),
            "created_at": str(row.get("created_at") or current),
            "updated_at": str(row.get("updated_at") or current),
        })
    return normalized


def normalize_value(value: dict[str, Any] | None) -> dict[str, Any]:
    data = value or {}
    if isinstance(data.get("items"), list):
        items = normalize_item_rows(data["items"])
    else:
        items = []
        for list_type in ("whitelist", "blacklist"):
            for item in normalize_items(data.get(list_type, [])):
                try:
                    items.append(_item_from_value(item, list_type, source="legacy"))
                except (ValueError, AddressValueError):
                    continue
        items = normalize_item_rows(items)
    whitelist = [item["value"] for item in items if item["list_type"] == "whitelist"]
    blacklist = [item["value"] for item in items if item["list_type"] == "blacklist"]
    return {"whitelist": whitelist, "blacklist": blacklist, "items": items}


def set_ip_list_value(db: Session, row: Setting, value: dict[str, Any]) -> None:
    row.value = normalize_value(value)
    row.updated_at = now(db, row.workspace_id)


def save_ip_lists(db: Session, actor: User, whitelist: list[Any], blacklist: list[Any]) -> Setting:
    row = get_ip_list_setting(db, actor.workspace_id)
    rows = [_item_from_value(item, "whitelist") for item in normalize_items(whitelist)]
    rows.extend(_item_from_value(item, "blacklist") for item in normalize_items(blacklist))
    set_ip_list_value(db, row, {"items": rows})
    write_audit(
        db,
        actor,
        "ip_lists.update",
        "setting",
        "ip_lists",
        {"whitelist": len(row.value["whitelist"]), "blacklist": len(row.value["blacklist"])},
    )
    return row


def add_ip_list_item(db: Session, actor: User, payload: dict[str, Any]) -> tuple[Setting, dict[str, Any], bool]:
    row = get_ip_list_setting(db, actor.workspace_id)
    value = normalize_value(row.value)
    list_type = payload.get("list_type")
    if list_type not in {"whitelist", "blacklist"}:
        raise ValueError("名单类型仅支持 whitelist 或 blacklist")
    item = _item_from_value(
        str(payload.get("value") or ""),
        list_type,
        description=str(payload.get("description") or ""),
        source=str(payload.get("source") or "manual"),
    )
    exists = any(existing["list_type"] == item["list_type"] and existing["value"] == item["value"] for existing in value["items"])
    if not exists:
        value["items"].append(item)
        set_ip_list_value(db, row, value)
    return row, item, not exists


def update_ip_list_item(db: Session, actor: User, item_id: str, payload: dict[str, Any]) -> tuple[Setting, dict[str, Any]]:
    row = get_ip_list_setting(db, actor.workspace_id)
    value = normalize_value(row.value)
    target = None
    for item in value["items"]:
        if item["id"] == item_id:
            target = item
            break
    if not target:
        raise KeyError("名单项不存在")
    list_type = payload.get("list_type", target["list_type"])
    if list_type not in {"whitelist", "blacklist"}:
        raise ValueError("名单类型仅支持 whitelist 或 blacklist")
    text = str(payload.get("value", target["value"]) or "").strip()
    value_type = detect_value_type(text)
    duplicate = any(item["id"] != item_id and item["list_type"] == list_type and item["value"] == text for item in value["items"])
    if duplicate:
        raise ValueError("名单项已存在")
    target.update({
        "list_type": list_type,
        "value": text,
        "value_type": value_type,
        "description": str(payload.get("description", target.get("description", "")) or ""),
        "source": str(payload.get("source", target.get("source", "manual")) or "manual"),
        "updated_at": now(db, actor.workspace_id).isoformat(sep=" ", timespec="seconds"),
    })
    set_ip_list_value(db, row, value)
    return row, target


def delete_ip_list_items(db: Session, actor: User, item_ids: list[str]) -> tuple[Setting, int]:
    ids = {str(item) for item in item_ids if str(item)}
    row = get_ip_list_setting(db, actor.workspace_id)
    value = normalize_value(row.value)
    before = len(value["items"])
    value["items"] = [item for item in value["items"] if item["id"] not in ids]
    deleted = before - len(value["items"])
    if deleted:
        set_ip_list_value(db, row, value)
    return row, deleted


def add_to_whitelist(
    db: Session,
    actor: User,
    ip: str,
    *,
    alert: Alert | None = None,
    reason: str = "",
) -> bool:
    ip = (ip or "").strip()
    if not ip:
        return False
    row = get_ip_list_setting(db, actor.workspace_id)
    value = normalize_value(row.value)
    whitelist = normalize_items(value.get("whitelist", []))
    if ip in whitelist:
        return False
    value["items"].append(_item_from_value(ip, "whitelist", description=reason, source="alert_flow"))
    set_ip_list_value(db, row, value)
    write_audit(
        db,
        actor,
        "ip_lists.whitelist_add",
        "alert" if alert else "setting",
        alert.id if alert else "ip_lists",
        {"ip": ip, "alert_hash": alert.alert_hash if alert else "", "reason": reason},
    )
    return True


def block_ip(
    db: Session,
    actor: User,
    ip: str,
    *,
    alert: Alert | None = None,
    reason: str = "",
) -> dict[str, Any]:
    ip = (ip or "").strip()
    if not ip:
        return {"blocked": False, "was_whitelisted": False, "removed_whitelist": []}

    row = get_ip_list_setting(db, actor.workspace_id)
    value = normalize_value(row.value)
    whitelist = normalize_items(value.get("whitelist", []))
    blacklist = normalize_items(value.get("blacklist", []))

    matched_whitelist = [item for item in whitelist if is_ip_in_list(ip, [item])]
    removed_whitelist = [item for item in matched_whitelist if item == ip]
    if removed_whitelist:
        value["items"] = [
            item for item in value["items"]
            if not (item["list_type"] == "whitelist" and item["value"] in removed_whitelist)
        ]

    added_blacklist = False
    if ip not in blacklist:
        value["items"].append(_item_from_value(ip, "blacklist", description=reason, source="alert_flow"))
        added_blacklist = True

    set_ip_list_value(db, row, value)
    detail = {
        "ip": ip,
        "alert_hash": alert.alert_hash if alert else "",
        "reason": reason,
        "added_blacklist": added_blacklist,
        "was_whitelisted": bool(matched_whitelist),
        "removed_whitelist": removed_whitelist,
        "matched_whitelist": matched_whitelist,
    }
    write_audit(db, actor, "ip_lists.blacklist_add", "alert" if alert else "setting", alert.id if alert else "ip_lists", detail)

    if matched_whitelist:
        notify_all(
            db,
            actor.workspace_id,
            f"{ip} 疑似失陷，已从白名单移至黑名单",
            f"{ip} 命中白名单，由于关联告警处置动作，已将其移除并加入黑名单。{reason}",
            actor=actor,
            alert=alert,
            message_type="ip_list",
            payload=detail,
        )

    return {"blocked": added_blacklist, "was_whitelisted": bool(matched_whitelist), "removed_whitelist": removed_whitelist}
