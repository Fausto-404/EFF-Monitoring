"""
文本解析模块
职责: 基础文本解析，提取key-value对
"""
import re
from .regex import load_engine


def parse_text(text):
    """
    基础文本解析，提取KV对
    支持多种分隔符: ; \t 换行
    
    Args:
        text: 原始文本
    
    Returns:
        dict: 解析结果 {key: value}
    
    Examples:
        >>> parse_text("src_ip:192.168.1.1; dst_ip:8.8.8.8; protocol:UDP")
        {'src_ip': '192.168.1.1', 'dst_ip': '8.8.8.8', 'protocol': 'UDP'}
    """
    result = {}
    
    if not text or not isinstance(text, str):
        return result
    
    # 尝试多种分隔符分割
    # 首先按换行符分割，然后每行按 ; 或 \t 分割
    lines = text.split('\n')
    
    for line in lines:
        # 跳过空行
        line = line.strip()
        if not line:
            continue
        
        # 按 ; 或 \t 分割
        for sep in [';', '\t']:
            if sep in line:
                parts = line.split(sep)
                for part in parts:
                    part = part.strip()
                    if not part:
                        continue
                    
                    # 尝试从部分中提取KV
                    kv = _extract_kv(part)
                    if kv:
                        key, value = kv
                        result[key] = value
                break
        else:
            # 如果没有分隔符，尝试直接提取KV
            kv = _extract_kv(line)
            if kv:
                key, value = kv
                result[key] = value
    
    return result


def _extract_kv(text):
    """
    从单个文本片段中提取KV对
    支持 key:value 和 key=value 格式
    
    Args:
        text: 文本片段
    
    Returns:
        tuple: (key, value) 或 None
    """
    text = text.strip()
    
    # 尝试 key:value 格式
    if ':' in text:
        parts = text.split(':', 1)
        if len(parts) == 2:
            key = parts[0].strip()
            value = parts[1].strip()
            if key and value:
                return (key, value)
    
    # 尝试 key=value 格式
    if '=' in text:
        parts = text.split('=', 1)
        if len(parts) == 2:
            key = parts[0].strip()
            value = parts[1].strip()
            if key and value:
                return (key, value)
    
    return None


def split_lines(text):
    """
    将文本按换行符分割
    
    Args:
        text: 原始文本
    
    Returns:
        list: 行列表
    """
    if not text:
        return []
    return [line.strip() for line in text.split('\n') if line.strip()]


def extract_with_patterns(patterns, text):
    """按顺序尝试多个正则，返回第一个匹配值（支持传入字符串或列表）。

    如果正则含捕获组，返回第一个分组，否则返回完整匹配。
    """
    if not patterns:
        return None

    if isinstance(patterns, str):
        patterns = [patterns]

    for p in patterns:
        try:
            reg = re.compile(p)
        except re.error:
            continue

        m = reg.search(text)
        if m:
            if m.groups():
                return m.group(1)
            return m.group(0)

    return None


def parse_log(text, cfg=None):
    """增强的日志解析器，兼容 v2.1 的 pattern 配置。

    优先使用已加载的 RegexEngine（cfg 下的 regex.five_tuple / extra_fields），
    如果 cfg 中存在 `log_patterns` 或 `custom_patterns`，则会用这些规则填充/覆盖字段。

    返回格式:
        {
            'data': {field: value, ...},
            'warnings': [str, ...]
        }
    """
    result = {'data': {}, 'warnings': []}

    if not text:
        return result

    # 1. 尝试使用 RegexEngine（优先）
    try:
        engine = load_engine(cfg)
        fields = engine.extract_fields(text)
        if fields:
            result['data'].update(fields)
    except Exception:
        # 若引擎失败，则继续使用备用规则
        pass

    # 2. 支持 v2.1 风格的 log_patterns / custom_patterns
    cfg = cfg or {}
    log_patterns = cfg.get('log_patterns') or cfg.get('regex', {}).get('log_patterns')
    custom = cfg.get('custom_patterns') or cfg.get('regex', {}).get('custom_patterns')

    # 合并 custom 到 log_patterns（custom 优先，覆盖或追加）
    patterns = {}
    if isinstance(log_patterns, dict):
        patterns.update(log_patterns)

    if isinstance(custom, dict):
        for k, v in custom.items():
            patterns[k] = v

    # 使用 patterns 填充字段（不覆盖已存在的字段，除非为空）
    for field, pats in patterns.items():
        if field in result['data'] and result['data'].get(field):
            continue
        value = extract_with_patterns(pats, text)
        if value:
            result['data'][field] = value

    # 3. 若仍缺少常见五元组字段，尝试从简单KV解析中补偿
    # 例如 src_ip, dst_ip, protocol 等
    kvs = parse_text(text)
    for key in ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol']:
        if key not in result['data'] and kvs.get(key):
            result['data'][key] = kvs.get(key)

    return result
