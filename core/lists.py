"""
IP 名单匹配工具。

Web 版名单数据存储在数据库系统配置中；本模块只负责判断单个 IP 是否
命中单 IP、CIDR 或范围规则。
"""

from ipaddress import AddressValueError, ip_address, ip_network


def _range_bounds(value: str):
    start_text, end_text = [part.strip() for part in value.split("-", 1)]
    start_ip = ip_address(start_text)
    if "." in start_text and "." not in end_text and ":" not in end_text:
        # IPv4 简写处理，如 192.168.1.1-100
        prefix = start_text.rsplit(".", 1)[0]
        end_text = f"{prefix}.{end_text}"
    elif ":" in start_text and ":" not in end_text and "." not in end_text:
        # IPv6 简写理论上不常用，但也做类似处理
        prefix = start_text.rsplit(":", 1)[0]
        end_text = f"{prefix}:{end_text}"
    end_ip = ip_address(end_text)
    return start_ip, end_ip


def is_ip_in_list(ip: str, ip_list: list[str]) -> bool:
    """检查 IP 是否命中名单项，支持单 IP、CIDR、完整范围和 IPv4 简写范围。"""
    try:
        target = ip_address((ip or "").strip())
    except (ValueError, AddressValueError):
        return False

    for item in ip_list:
        value = (item or "").strip()
        if not value:
            continue

        try:
            if "/" in value:
                # CIDR 格式
                network = ip_network(value, strict=False)
                if target in network:
                    return True
            elif "-" in value:
                # 范围格式 (包括简写)
                start_ip, end_ip = _range_bounds(value)
                if target.__class__ is start_ip.__class__:
                    if start_ip <= target <= end_ip:
                        return True
            else:
                # 单 IP 格式
                if target == ip_address(value):
                    return True
        except (ValueError, AddressValueError):
            continue

    return False
