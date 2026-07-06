from typing import Any

from sqlalchemy.orm import Session

from app.models.entities import Alert, Setting, User
from app.services.audit_service import write_audit
from app.services.message_service import notify_all
from core.lists import is_ip_in_list


def get_ip_list_setting(db: Session, workspace_id: int) -> Setting:
    row = db.query(Setting).filter_by(workspace_id=workspace_id, key="ip_lists").first()
    if not row:
        row = Setting(workspace_id=workspace_id, user_id=None, key="ip_lists", value={"whitelist": [], "blacklist": []})
        db.add(row)
        db.flush()
    return row


def normalize_items(items: list[Any]) -> list[str]:
    return list(dict.fromkeys(item.strip() for item in items if isinstance(item, str) and item.strip()))


def save_ip_lists(db: Session, actor: User, whitelist: list[Any], blacklist: list[Any]) -> Setting:
    row = get_ip_list_setting(db, actor.workspace_id)
    row.value = {
        "whitelist": normalize_items(whitelist),
        "blacklist": normalize_items(blacklist),
    }
    write_audit(
        db,
        actor,
        "ip_lists.update",
        "setting",
        "ip_lists",
        {"whitelist": len(row.value["whitelist"]), "blacklist": len(row.value["blacklist"])},
    )
    return row


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
    value = row.value or {"whitelist": [], "blacklist": []}
    whitelist = normalize_items(value.get("whitelist", []))
    if ip in whitelist:
        return False
    whitelist.append(ip)
    row.value = {"whitelist": whitelist, "blacklist": normalize_items(value.get("blacklist", []))}
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
    value = row.value or {"whitelist": [], "blacklist": []}
    whitelist = normalize_items(value.get("whitelist", []))
    blacklist = normalize_items(value.get("blacklist", []))

    matched_whitelist = [item for item in whitelist if is_ip_in_list(ip, [item])]
    removed_whitelist = [item for item in matched_whitelist if item == ip]
    if removed_whitelist:
        whitelist = [item for item in whitelist if item not in removed_whitelist]

    added_blacklist = False
    if ip not in blacklist:
        blacklist.append(ip)
        added_blacklist = True

    row.value = {"whitelist": whitelist, "blacklist": blacklist}
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
