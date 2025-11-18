"""
输出格式化模块
职责: 将解析结果格式化为聊天或 Excel 文本
"""
from typing import Dict, Any


def render_chat(data: Dict[str, Any], cfg: Dict) -> str:
    """
    格式化为聊天格式
    输出: 人类可读的 key: value 格式，换行分隔
    
    Args:
        data: 解析结果
        cfg: 配置字典
    
    Returns:
        str: 格式化的聊天文本
    
    Example:
        事件名称: RDP远程登录尝试
        源IP: 111.218.49.101
        目的IP: 239.118.130.94
    """
    lines = []
    
    # 获取字段顺序
    field_order = cfg.get('fields', {}).get('order', [])
    auto_append = cfg.get('fields', {}).get('auto_append_extra', False)
    
    # 获取标签映射
    labels = cfg.get('field_labels', {})

    # 按顺序添加字段（使用标签显示名）
    for field in field_order:
        if field in data:
            # 正常字段：按「标签: 值」输出
            value = data[field]
            if value is not None and value != '':
                label = labels.get(field, field)
                lines.append(f"{label}: {value}")
        else:
            # 若字段顺序中出现了但解析结果里没有对应字段（通常用于分区标题），
            # 则原样作为一行文本输出，便于配置「【分析研判】」之类的分组标题。
            if field:
                lines.append(str(field))
    
    # 自动追加未知字段
    if auto_append:
        for field, value in data.items():
            if field not in field_order and value is not None and value != '':
                label = labels.get(field, field)
                lines.append(f"{label}: {value}")
    
    return '\n'.join(lines)


def render_excel(data: Dict[str, Any], cfg: Dict) -> str:
    """
    格式化为Excel格式
    输出: 值换行分隔，每行一个值，适合直接复制到Excel单元格
    
    Args:
        data: 解析结果
        cfg: 配置字典
    
    Returns:
        str: 格式化的Excel文本
    
    Example:
        RDP远程登录尝试
        111.218.49.101
        239.118.130.94
    """
    # 为了方便复制到 Excel，输出为一行，字段间用制表符分隔
    values = []
    labels = cfg.get('field_labels', {})
    field_order = cfg.get('fields', {}).get('order', [])
    auto_append = cfg.get('fields', {}).get('auto_append_extra', False)

    for field in field_order:
        if field in data:
            value = data[field]
            if value is not None:
                # 把多行替换为单行，保留内容间空格
                value_str = str(value).replace('\n', ' ')
                values.append(value_str)

    if auto_append:
        for field, value in data.items():
            if field not in field_order and value is not None:
                value_str = str(value).replace('\n', ' ')
                values.append(value_str)

    # 返回单行，使用制表符分隔
    return '\t'.join(values)


def render_ti_info(ti_result: Dict) -> str:
    """
    格式化威胁情报结果
    
    Args:
        ti_result: 威胁情报结果
    
    Returns:
        str: 格式化的文本
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
        labels = ti.get('labels') or []
        if labels:
            lines.append("威胁标签: " + ", ".join(labels))
        if ti.get('location'):
            loc = ti['location']
            loc_parts = [loc.get('country'), loc.get('province'), loc.get('city')]
            loc_text = " / ".join([p for p in loc_parts if p])
            if loc.get('carrier'):
                loc_text = f"{loc_text} ({loc['carrier']})" if loc_text else loc['carrier']
            if loc_text:
                lines.append(f"地理位置: {loc_text}")
        sources = ti.get('sources') or []
        if sources:
            lines.append("来源: " + ", ".join(sources))
        lines.append("")

    _fmt_one("源IP威胁情报", ti_result.get('src_ip_ti'))
    _fmt_one("目的IP威胁情报", ti_result.get('dst_ip_ti'))

    return '\n'.join(lines).strip()


def render_ai_result(ai_response: str) -> str:
    """
    格式化AI研判结果
    
    Args:
        ai_response: AI原始响应
    
    Returns:
        str: 格式化的结果
    """
    if not ai_response:
        return "无AI研判结果"
    
    # 尝试解析并格式化
    lines = []
    for line in ai_response.split('\n'):
        line = line.strip()
        if line:
            lines.append(line)
    
    return '\n'.join(lines)
