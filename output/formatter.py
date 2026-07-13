"""
输出格式化模块
职责: 将解析结果格式化为聊天或 Excel 文本
"""
from typing import Any, Dict


def render_chat(data: Dict[str, Any], cfg: Dict) -> str:
    """
    格式化为聊天格式
    输出: 人类可读的 key: value 格式，换行分隔
    """
    lines = []

    field_order = cfg.get("fields", {}).get("order", [])
    auto_append = cfg.get("fields", {}).get("auto_append_extra", False)
    labels = cfg.get("field_labels", {})

    for field in field_order:
        if field in data:
            value = data[field]
            if value is not None and value != "":
                label = labels.get(field, field)
                lines.append(f"{label}: {value}")
        elif field:
            lines.append(str(field))

    if auto_append:
        for field, value in data.items():
            if field not in field_order and value is not None and value != "":
                label = labels.get(field, field)
                lines.append(f"{label}: {value}")

    return "\n".join(lines)


def render_excel(data: Dict[str, Any], cfg: Dict) -> str:
    """
    格式化为 Excel 格式
    输出: 值使用制表符分隔，适合直接复制到 Excel 行
    """
    values = []
    field_order = cfg.get("fields", {}).get("order", [])
    auto_append = cfg.get("fields", {}).get("auto_append_extra", False)

    for field in field_order:
        if field in data:
            value = data[field]
            if value is not None:
                values.append(str(value).replace("\n", " "))

    if auto_append:
        for field, value in data.items():
            if field not in field_order and value is not None:
                values.append(str(value).replace("\n", " "))

    return "\t".join(values)


def render_ti_info(ti_result: Dict) -> str:
    """
    格式化威胁情报结果
    """
    if not ti_result:
        return "无威胁情报数据"

    lines = []

    def _fmt_one(title: str, ti: Dict):
        if not ti:
            return
        lines.append(f"=== {title} ===")
        lines.append(f"IP: {ti.get('ip')}")
        lines.append(f"是否恶意: {'是' if ti.get('is_malicious') else '否'}")
        labels = ti.get("labels") or []
        if labels:
            lines.append("威胁标签: " + ", ".join(labels))
        if ti.get("location"):
            loc = ti["location"]
            loc_parts = [loc.get("country"), loc.get("province"), loc.get("city")]
            loc_text = " / ".join([p for p in loc_parts if p])
            if loc.get("carrier"):
                loc_text = f"{loc_text} ({loc['carrier']})" if loc_text else loc["carrier"]
            if loc_text:
                lines.append(f"地理位置: {loc_text}")
        sources = ti.get("sources") or []
        if sources:
            lines.append("来源: " + ", ".join(sources))
        lines.append("")

    _fmt_one("源IP威胁情报", ti_result.get("src_ip_ti"))
    _fmt_one("目的IP威胁情报", ti_result.get("dst_ip_ti"))

    return "\n".join(lines).strip()


def render_ai_result(ai_response: str) -> str:
    """
    格式化 AI 研判结果
    """
    if not ai_response:
        return "无AI研判结果"

    lines = []
    for line in ai_response.split("\n"):
        line = line.strip()
        if line:
            lines.append(line)

    return "\n".join(lines)
