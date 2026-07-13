ROLE_ADMIN = "admin"
ROLE_MONITOR = "monitor"
ROLE_ANALYST = "analyst"
ROLE_DISPOSER = "disposer"
ROLE_VIEWER = "viewer"

ROLE_LABELS = {
    ROLE_ADMIN: "管理员",
    ROLE_MONITOR: "监测组",
    ROLE_ANALYST: "研判组",
    ROLE_DISPOSER: "处置组",
    ROLE_VIEWER: "只读人员",
}

STATUS_ANALYSIS = "analysis"
STATUS_FALSE_POSITIVE = "false_positive"
STATUS_IGNORED = "ignored"
STATUS_DISPOSAL = "disposal"
STATUS_DISPOSED = "disposed"

STATUS_LABELS = {
    STATUS_ANALYSIS: "研判中",
    STATUS_FALSE_POSITIVE: "误报",
    STATUS_IGNORED: "忽略",
    STATUS_DISPOSAL: "处置中",
    STATUS_DISPOSED: "已处置",
}

GROUP_ANALYSIS = "analysis"
GROUP_DISPOSAL = "disposal"
GROUP_NONE = "none"

GROUP_LABELS = {
    GROUP_ANALYSIS: "研判组",
    GROUP_DISPOSAL: "处置组",
    GROUP_NONE: "无（已闭环）",
}

ACTIVE_GROUP_ROLE = {
    GROUP_ANALYSIS: ROLE_ANALYST,
    GROUP_DISPOSAL: ROLE_DISPOSER,
}

ACTIVE_STATUSES = {STATUS_ANALYSIS, STATUS_DISPOSAL}
TERMINAL_STATUSES = {STATUS_FALSE_POSITIVE, STATUS_IGNORED, STATUS_DISPOSED}

OLD_STATUS_MAP = {
    "pending": STATUS_ANALYSIS,
    "in_progress": STATUS_ANALYSIS,
    "review": STATUS_ANALYSIS,
    "pending_disposal": STATUS_DISPOSAL,
    "confirmed": STATUS_DISPOSED,
    "closed": STATUS_DISPOSED,
}

DISPOSAL_TARGET_LABELS = {
    "src_ip": "源 IP",
    "dst_ip": "目的 IP",
}

DISPOSAL_ACTION_LABELS = {
    "repair": "修复",
    "emergency": "应急",
    "block": "封禁",
}

CLOSURE_ACTION_LABELS = {
    "ignore": "仅忽略",
    "ignore_whitelist": "忽略并加白",
    "false_positive": "仅误报",
    "false_positive_whitelist": "误报并加白",
}


def normalize_status(status: str | None) -> str:
    if not status:
        return STATUS_ANALYSIS
    return OLD_STATUS_MAP.get(status, status)


def group_for_status(status: str | None) -> str:
    normalized = normalize_status(status)
    if normalized == STATUS_ANALYSIS:
        return GROUP_ANALYSIS
    if normalized == STATUS_DISPOSAL:
        return GROUP_DISPOSAL
    return GROUP_NONE
