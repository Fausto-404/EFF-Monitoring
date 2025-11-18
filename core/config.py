"""
配置管理模块
职责: JSON 配置文件的读写与初始化
"""
import json
import os


CONFIG_FILE = "config.json"


def get_default_config():
    """返回默认配置结构"""
    return {
        "regex": {
            "five_tuple": {
                "src_ip": r"[\d.]+|[\da-fA-F:]+",
                "dst_ip_port": r"[\d.]+(?::\d+)?|[\da-fA-F:]+(?::\d+)?",
                "protocol": r"TCP|UDP|ICMP|HTTP|HTTPS"
            },
            "extra_fields": {}
        },
        "providers": {
            "threatbook": {
                "enabled": False,
                "api_key": "",
                "mode": "both",          # both | src | dst
                "request_mode": "api",   # off | api | http
                "http_cookie": ""        # 浏览器复制的 Cookie 字符串（仅 http 模式使用）
            }
        },
        "ai": {
            "enabled": False,
            "model": "deepseek-ai/DeepSeek-V2",
            "api_key": "",
            "base_url": "https://api.siliconflow.cn",
            "objective": "对该告警进行专业安全威胁研判，给出威胁等级、是否需要封禁源IP/目的IP以及主要原因与风险分析。",
            "audience": "expert",            # customer | expert | beginner
            "response_mode": "structured"    # structured | brief | report
        },
        "webhook": {
            "dingtalk": {"enabled": False, "url": "", "secret": ""},
            "wecom": {"enabled": False, "url": ""},
            "feishu": {"enabled": False, "url": ""}
        },
        "fields": {
            "order": ["src_ip", "dst_ip", "event_name", "alert_device", "analyst", "alert_id", "compromised", "event_type", "suggestion"],
            "auto_append_extra": False
        },
        "lists": {
            "whitelist_path": "lists/whitelist.txt",
            "blocked_path": "lists/blocked.txt",
            "whitelist_skip_ti": True
        },
        "static_fields": {},
        "manual_fields": [
            {"key": "alert_device", "label": "告警设备", "type": "text"},
            {"key": "analyst", "label": "研判人员", "type": "text"},
            {"key": "alert_id", "label": "告警编号", "type": "text"},
            {"key": "compromised", "label": "是否失陷", "type": "select", "options": ["否", "是"]},
            {"key": "event_type", "label": "事件类型", "type": "text"},
            {"key": "suggestion", "label": "处置建议", "type": "textarea"}
        ],
        "field_labels": {
            "src_ip": "源IP",
            "dst_ip": "目的IP",
            "event_name": "事件名称",
            "alert_device": "告警设备",
            "analyst": "研判人员",
            "alert_id": "告警编号",
            "compromised": "是否失陷",
            "event_type": "事件类型",
            "suggestion": "处置建议"
        },
        "history": {
            "enabled": True,
            "max_entries": 200,
            "file": "output/log_history.json"
        }
    }


def ensure_config():
    """
    保证配置文件及默认结构存在
    如果文件不存在，创建并写入默认配置
    """
    if not os.path.exists(CONFIG_FILE):
        default_cfg = get_default_config()
        save_config(default_cfg)
        return default_cfg
    
    try:
        cfg = load_config()
        default_cfg = get_default_config()
        for key, val in default_cfg.items():
            if key not in cfg:
                cfg[key] = val
        if "history" not in cfg:
            cfg["history"] = default_cfg.get("history", {})
        save_config(cfg)
        return cfg
    except Exception:
        # 如果加载失败，使用默认配置
        default_cfg = get_default_config()
        save_config(default_cfg)
        return default_cfg


def load_config(path=CONFIG_FILE):
    """
    加载JSON配置文件
    
    Args:
        path: 配置文件路径
    
    Returns:
        dict: 配置字典
    
    Raises:
        FileNotFoundError: 文件不存在
        json.JSONDecodeError: JSON格式错误
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"配置文件不存在: {path}")
    
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_config(cfg, path=CONFIG_FILE):
    """
    保存配置到JSON文件
    
    Args:
        cfg: 配置字典
        path: 配置文件路径
    """
    # 确保目录存在
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def validate_config(cfg):
    """
    验证配置完整性
    
    Args:
        cfg: 配置字典
    
    Returns:
        tuple: (is_valid, error_message)
    """
    required_keys = ['regex', 'providers', 'ai', 'webhook', 'fields', 'lists']
    
    for key in required_keys:
        if key not in cfg:
            return False, f"缺失配置项: {key}"
    
    # 检查regex结构
    if 'five_tuple' not in cfg['regex']:
        return False, "缺失regex.five_tuple配置"
    
    # 检查providers结构（目前仅保留 threatbook）
    if 'threatbook' not in cfg['providers']:
        return False, "缺失providers.threatbook配置"
    
    return True, ""
