"""
IP 名单管理模块
职责: 白名单/黑名单的读写与 IP 格式转换
支持: 单个 IP、CIDR、范围、简写范围
"""
import os
import re
from ipaddress import ip_address, ip_network, AddressValueError
import ipaddress


def read_lines(path):
    """
    读取并解析IP文件
    
    Args:
        path: 文件路径
    
    Returns:
        list: IP列表 (已标准化)
    
    Raises:
        FileNotFoundError: 文件不存在时
    """
    if not os.path.exists(path):
        return []
    
    ips = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # 处理简写范围
            normalized = _normalize_ip_range(line)
            if normalized:
                ips.append(normalized)
    
    return ips


def write_lines(path, lines):
    """
    保存IP列表到文件
    
    Args:
        path: 文件路径
        lines: IP列表
    """
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    
    with open(path, 'w', encoding='utf-8') as f:
        for line in lines:
            if line.strip():
                f.write(line.strip() + '\n')


def normalize_ip(ip_str):
    """
    标准化单个IP
    
    Args:
        ip_str: IP字符串
    
    Returns:
        str: 标准化的IP，或None
    """
    ip_str = ip_str.strip()
    
    try:
        # 尝试解析为IP地址
        ip_obj = ip_address(ip_str)
        return str(ip_obj)
    except (ValueError, AddressValueError):
        pass
    
    return None


def _normalize_ip_range(range_str):
    """
    标准化IP范围
    支持格式:
    - 单个IP: 192.168.1.1
    - CIDR: 192.168.1.0/24
    - 范围: 192.168.1.1-192.168.1.100
    - 简写范围: 192.168.1.1-100
    
    Args:
        range_str: 范围字符串
    
    Returns:
        str: 标准化的范围，或None
    """
    range_str = range_str.strip()
    
    # 尝试简写范围转换: 192.168.1.1-100 -> 192.168.1.1-192.168.1.100
    if '-' in range_str and '/' not in range_str:
        parts = range_str.split('-')
        if len(parts) == 2:
            start_ip = parts[0].strip()
            end_part = parts[1].strip()
            
            # 检查end_part是否只是数字 (简写范围)
            if end_part.isdigit():
                # 提取start_ip的前缀
                start_parts = start_ip.split('.')
                if len(start_parts) == 4:
                    # IPv4简写范围
                    end_ip = '.'.join(start_parts[:3]) + '.' + end_part
                    return f"{start_ip}-{end_ip}"
                elif ':' in start_ip:
                    # IPv6暂不支持简写
                    return range_str
    
    return range_str


def normalize_ip_range(ip_range):
    """兼容的标准化函数，返回CIDR/单IP/范围表示（来自v2.1 的实现）"""
    try:
        # CIDR格式
        if '/' in ip_range:
            network = ipaddress.ip_network(ip_range, strict=False)
            return str(network)

        # 范围格式
        if '-' in ip_range:
            parts = ip_range.split('-')
            if len(parts) == 2:
                start_ip = ipaddress.ip_address(parts[0].strip())

                # 简写范围格式: 192.168.1.1-100
                if '.' not in parts[1] and ':' not in parts[1]:
                    base_ip = parts[0].rsplit('.', 1)[0]
                    end_ip = ipaddress.ip_address(f"{base_ip}.{parts[1].strip()}")
                else:
                    end_ip = ipaddress.ip_address(parts[1].strip())

                return f"{start_ip}-{end_ip}"

        # 单个IP
        return str(ipaddress.ip_address(ip_range))
    except Exception:
        return ip_range


def is_ip_in_range(ip_str, ip_range):
    """检查单个IP是否落在给定的范围/CIDR/单IP内（v2.1 兼容）"""
    try:
        ip = ipaddress.ip_address(ip_str)

        # CIDR
        if '/' in ip_range:
            network = ipaddress.ip_network(ip_range, strict=False)
            return ip in network

        # 范围
        if '-' in ip_range:
            start_str, end_str = ip_range.split('-', 1)
            start_ip = ipaddress.ip_address(start_str.strip())
            end_ip = ipaddress.ip_address(end_str.strip())
            return start_ip <= ip <= end_ip

        # 单个IP
        return ip_str == ip_range
    except Exception:
        return False


def validate_ip_range(ip_range):
    """验证IP或范围或CIDR是否有效（v2.1 兼容）"""
    try:
        if '/' in ip_range:
            ipaddress.ip_network(ip_range, strict=False)
            return True

        if '-' in ip_range:
            parts = ip_range.split('-')
            if len(parts) != 2:
                return False
            ipaddress.ip_address(parts[0].strip())
            ipaddress.ip_address(parts[1].strip())
            return True

        ipaddress.ip_address(ip_range)
        return True
    except Exception:
        return False


def is_ip_in_list(ip, ip_list):
    """
    检查IP是否在列表中
    支持单个IP、CIDR、范围匹配
    
    Args:
        ip: 待检查的IP字符串
        ip_list: IP列表 (来自read_lines)
    
    Returns:
        bool: 是否在列表中
    """
    ip = ip.strip()
    
    try:
        ip_obj = ip_address(ip)
    except (ValueError, AddressValueError):
        return False
    
    for item in ip_list:
        item = item.strip()
        
        if not item:
            continue
        
        # 检查CIDR
        if '/' in item:
            try:
                network = ip_network(item, strict=False)
                if ip_obj in network:
                    return True
            except (ValueError, AddressValueError):
                pass
        
        # 检查范围
        elif '-' in item:
            parts = item.split('-')
            if len(parts) == 2:
                try:
                    start_ip = ip_address(parts[0].strip())
                    end_ip = ip_address(parts[1].strip())
                    
                    if isinstance(ip_obj, type(start_ip)):
                        if start_ip <= ip_obj <= end_ip:
                            return True
                except (ValueError, AddressValueError):
                    pass
        
        # 检查单个IP
        else:
            try:
                list_ip = ip_address(item)
                if ip_obj == list_ip:
                    return True
            except (ValueError, AddressValueError):
                pass
    
    return False


def search_ips(ip_list, keyword):
    """
    在IP列表中搜索关键字
    
    Args:
        ip_list: IP列表
        keyword: 搜索关键字
    
    Returns:
        list: 匹配的IP列表
    """
    if not keyword:
        return ip_list
    
    keyword = keyword.lower().strip()
    return [ip for ip in ip_list if keyword in ip.lower()]


def export_ips(ip_list, path):
    """
    导出IP列表到文件
    
    Args:
        ip_list: IP列表
        path: 导出路径
    """
    write_lines(path, ip_list)


def import_ips(path):
    """
    从文件导入IP列表
    
    Args:
        path: 导入路径
    
    Returns:
        list: IP列表
    """
    return read_lines(path)
