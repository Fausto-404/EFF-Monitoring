"""
Web 版默认配置。

运行态配置由数据库和系统配置接口管理；这里仅保留解析与格式化所需的
内置默认值，避免再次依赖旧版桌面应用的 config.json。
"""


def get_default_config():
    """返回解析和格式化流程所需的默认配置。"""
    return {
        "regex": {
            "five_tuple": {
                "src_ip": r"[\d.]+|[\da-fA-F:]+",
                "dst_ip_port": r"[\d.]+(?::\d+)?|[\da-fA-F:]+(?::\d+)?",
                "protocol": r"TCP|UDP|ICMP|HTTP|HTTPS",
            },
            "extra_fields": {},
        },
        "providers": {
            "threatbook": {
                "enabled": False,
                "mode": "both",
                "request_mode": "http",
                "http_cookie": "",
            }
        },
        "ai": {
            "enabled": False,
            "model": "Qwen2.5:7b",
            "api_key": "",
            "base_url": "http://127.0.0.1:11434",
            "audience": "expert",
            "response_mode": "structured",
        },
        "webhook": {
            "dingtalk": {"enabled": False, "url": "", "secret": ""},
            "wecom": {"enabled": False, "url": ""},
            "feishu": {"enabled": False, "url": ""},
        },
        "fields": {
            "order": [
                "src_ip",
                "dst_ip",
                "event_name",
                "alert_device",
                "analyst",
                "alert_id",
                "compromised",
                "event_type",
                "suggestion",
            ],
            "auto_append_extra": False,
        },
        "static_fields": {},
        "field_labels": {
            "src_ip": "源IP",
            "dst_ip": "目的IP",
            "event_name": "事件名称",
            "alert_device": "告警设备",
            "analyst": "研判组成员",
            "alert_id": "告警编号",
            "compromised": "是否失陷",
            "event_type": "事件类型",
            "suggestion": "处置建议",
        },
    }
