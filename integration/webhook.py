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
    
    # 钉钉
    if webhook_cfg.get('dingtalk', {}).get('enabled'):
        dt_result = _send_dingtalk(data_text, webhook_cfg['dingtalk'])
        results['details']['dingtalk'] = dt_result
        if dt_result.get('success'):
            results['success'] += 1
        else:
            results['failed'] += 1
    
    # 企业微信
    if webhook_cfg.get('wecom', {}).get('enabled'):
        wecom_result = _send_wecom(data_text, webhook_cfg['wecom'])
        results['details']['wecom'] = wecom_result
        if wecom_result.get('success'):
            results['success'] += 1
        else:
            results['failed'] += 1
    
    # 飞书
    if webhook_cfg.get('feishu', {}).get('enabled'):
        feishu_result = _send_feishu(data_text, webhook_cfg['feishu'])
        results['details']['feishu'] = feishu_result
        if feishu_result.get('success'):
            results['success'] += 1
        else:
            results['failed'] += 1
    
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
        
        # 构造消息
        payload = {
            "msgtype": "text",
            "text": {
                "content": text
            }
        }
        
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
        
        # 构造消息
        payload = {
            "msgtype": "text",
            "text": {
                "content": text
            }
        }
        
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
        
        # 构造消息
        payload = {
            "msg_type": "text",
            "content": {
                "text": text
            }
        }
        
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
