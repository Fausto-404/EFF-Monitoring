"""
Webhook 集成模块
职责: 将处理结果发送到第三方群聊平台（钉钉、企业微信、飞书）
"""
import requests
import hmac
import hashlib
import base64
import time
from typing import Dict, Any
from urllib.parse import quote


def send_record(data_text: str, cfg: Dict) -> Dict[str, Any]:
    """
    发送记录到所有启用的webhook
    
    Args:
        data_text: 要发送的文本数据（聊天格式）
        cfg: 配置字典
    
    Returns:
        dict: 发送结果统计 {
            'success': 3,
            'failed': 0,
            'details': {
                'dingtalk': {'success': True, 'message': '...'},
                'wecom': {'success': False, 'error': '...'},
                'feishu': {'success': True, 'message': '...'}
            }
        }
    """
    results = {
        'success': 0,
        'failed': 0,
        'details': {}
    }
    
    webhook_cfg = cfg.get('webhook', {}) or {}

    # 全局开关：若显式关闭，则不发送到任何平台
    if not webhook_cfg.get('enabled', True):
        results['details']['webhook'] = {
            'success': False,
            'error': '消息推送已在配置中关闭'
        }
        return results
    
    provider = webhook_cfg.get("provider")
    if not provider:
        for name in ("dingtalk", "wecom", "feishu"):
            if webhook_cfg.get(name, {}).get("enabled") and webhook_cfg.get(name, {}).get("url"):
                provider = name
                break
    if not provider and webhook_cfg.get("url"):
        provider = "dingtalk"

    senders = {
        "dingtalk": _send_dingtalk,
        "wecom": _send_wecom,
        "feishu": _send_feishu,
    }
    sender = senders.get(provider)
    if not sender:
        results["details"]["webhook"] = {"success": False, "error": "请选择钉钉、企业微信或飞书通知平台"}
        results["failed"] += 1
        return results

    provider_cfg = webhook_cfg.get(provider, {}) or {}
    if not provider_cfg.get("url") and webhook_cfg.get("url"):
        provider_cfg = {**provider_cfg, "url": webhook_cfg.get("url"), "secret": webhook_cfg.get("secret")}
    result = sender(data_text, provider_cfg)
    results["details"][provider] = result
    if result.get("success"):
        results["success"] += 1
    else:
        results["failed"] += 1
    
    return results


def _send_dingtalk(text: str, config: Dict) -> Dict[str, Any]:
    """
    发送到钉钉
    
    Args:
        text: 消息文本
        config: 钉钉配置 {'url': '...', 'secret': '...'}
    
    Returns:
        dict: {'success': bool, 'message': str} or {'success': bool, 'error': str}
    """
    try:
        url = config.get('url')
        secret = config.get('secret')
        
        if not url:
            return {'success': False, 'error': '钉钉URL未配置'}
        
        # 生成签名（如果提供了secret）
        headers = {'Content-Type': 'application/json; charset=utf-8'}
        if secret:
            timestamp = str(int(time.time() * 1000))
            sign_str = f"{timestamp}\n{secret}"
            sign = hmac.new(
                secret.encode('utf-8'),
                sign_str.encode('utf-8'),
                hashlib.sha256
            ).digest()
            sign_b64 = base64.b64encode(sign).decode('utf-8')
            url = f"{url}&timestamp={timestamp}&sign={quote(sign_b64)}"
        
        payload = {"msgtype": "text", "text": {"content": text}}
        
        response = requests.post(url, json=payload, headers=headers, timeout=15)
        
        if response.status_code == 200:
            resp_json = response.json()
            if resp_json.get('errcode') == 0:
                return {
                    'success': True,
                    'message': f"钉钉发送成功"
                }
            else:
                return {
                    'success': False,
                    'error': f"钉钉返回错误: {resp_json.get('errmsg')}"
                }
        else:
            return {
                'success': False,
                'error': f"HTTP {response.status_code}: {response.text}"
            }
    
    except Exception as e:
        return {
            'success': False,
            'error': f"钉钉发送异常: {str(e)}"
        }


def _send_wecom(text: str, config: Dict) -> Dict[str, Any]:
    """
    发送到企业微信
    
    Args:
        text: 消息文本
        config: 企业微信配置 {'url': '...'}
    
    Returns:
        dict: {'success': bool, 'message': str} or {'success': bool, 'error': str}
    """
    try:
        url = config.get('url')
        
        if not url:
            return {'success': False, 'error': '企业微信URL未配置'}
        
        headers = {'Content-Type': 'application/json; charset=utf-8'}
        
        mentioned_list = _split_csv(config.get("mentioned_list"))
        mentioned_mobile_list = _split_csv(config.get("mentioned_mobile_list"))
        payload = {
            "msgtype": "text",
            "text": {"content": text}
        }
        if mentioned_list:
            payload["text"]["mentioned_list"] = mentioned_list
        if mentioned_mobile_list:
            payload["text"]["mentioned_mobile_list"] = mentioned_mobile_list
        
        response = requests.post(url, json=payload, headers=headers, timeout=15)
        
        if response.status_code == 200:
            resp_json = response.json()
            if resp_json.get('errcode') == 0:
                return {
                    'success': True,
                    'message': f"企业微信发送成功"
                }
            else:
                return {
                    'success': False,
                    'error': f"企业微信返回错误: {resp_json.get('errmsg')}"
                }
        else:
            return {
                'success': False,
                'error': f"HTTP {response.status_code}: {response.text}"
            }
    
    except Exception as e:
        return {
            'success': False,
            'error': f"企业微信发送异常: {str(e)}"
        }


def _send_feishu(text: str, config: Dict) -> Dict[str, Any]:
    """
    发送到飞书
    
    Args:
        text: 消息文本
        config: 飞书配置 {'url': '...'}
    
    Returns:
        dict: {'success': bool, 'message': str} or {'success': bool, 'error': str}
    """
    try:
        url = config.get('url')
        
        if not url:
            return {'success': False, 'error': '飞书URL未配置'}
        
        headers = {'Content-Type': 'application/json; charset=utf-8'}
        
        payload = {
            "msg_type": "text",
            "content": {
                "text": text
            }
        }
        secret = config.get('secret')
        if secret:
            timestamp = str(int(time.time()))
            sign_str = f"{timestamp}\n{secret}"
            sign = base64.b64encode(
                hmac.new(sign_str.encode("utf-8"), b"", digestmod=hashlib.sha256).digest()
            ).decode("utf-8")
            payload["timestamp"] = timestamp
            payload["sign"] = sign
        
        response = requests.post(url, json=payload, headers=headers, timeout=15)
        
        if response.status_code == 200:
            resp_json = response.json()
            if resp_json.get('code') == 0:
                return {
                    'success': True,
                    'message': f"飞书发送成功"
                }
            else:
                return {
                    'success': False,
                    'error': f"飞书返回错误: {resp_json.get('msg')}"
                }
        else:
            return {
                'success': False,
                'error': f"HTTP {response.status_code}: {response.text}"
            }
    
    except Exception as e:
        return {
            'success': False,
            'error': f"飞书发送异常: {str(e)}"
        }


def _split_csv(value) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [item.strip() for item in str(value or "").replace("，", ",").split(",") if item.strip()]
