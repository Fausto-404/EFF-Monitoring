"""
威胁情报聚合模块（ThreatBook 专用）
职责: 调用微步 ThreatBook 接口，返回规范化结果，供日志解析和 AI 研判使用
"""
import requests
import json
import re
from typing import Optional, Dict, Any


class ThreatIntelService:
    """威胁情报服务（仅微步 ThreatBook）"""

    # ThreatBook 官方 IP 信誉查询端点
    THREATBOOK_URL = "https://api.threatbook.cn/v3/scene/ip_reputation"

    TIMEOUT = 15
    
    @staticmethod
    def query_threatbook(ip: str, api_key: str) -> Optional[Dict[str, Any]]:
        """
        查询微步威胁情报（ThreatBook IP Query）
        
        Args:
            ip: IP地址
            api_key: API密钥
        
        Returns:
            dict或None: 标准化结果；请求严重失败时返回None
        """
        # 默认返回结构（即便没有情报也给出基础结构，方便上层展示）
        base = {
            'source': 'threatbook',
            'is_malicious': False,
            'severity': None,
            'confidence_level': None,
            'judgments': [],
            'labels': [],
            'location': {},
            'raw': {}
        }

        if not api_key:
            return None

        # 兼容配置中意外带入的换行/空格
        api_key = api_key.strip()
        if not api_key:
            return None

        # 有些规则可能把整段文本误解析为“IP”，这里先从中提取标准 IPv4，
        # 若没有找到 4 段形式的 IPv4，则直接认为无情报，避免向接口发送明显非法参数。
        ip = (ip or "").strip()
        m = re.search(r'(?:\d{1,3}\.){3}\d{1,3}', ip)
        if m:
            ip_param = m.group(0)
        else:
            return base

        try:
            # 根据官方文档与错误信息，此接口使用 resource 作为必选参数名
            params = {
                "apikey": api_key,
                "resource": ip_param,
                "lang": "zh"
            }

            resp = requests.get(
                ThreatIntelService.THREATBOOK_URL,
                params=params,
                timeout=ThreatIntelService.TIMEOUT
            )
            resp.raise_for_status()
            
            data = resp.json()

            base['raw'] = data or {}

            # 默认 data 容器
            container = data.get('data') or data.get('ips') or {}
            ip_data = container.get(ip_param) or {}

            # 请求成功且有该IP的详细信息
            if data.get('response_code') == 0 and ip_data:
                # 提取标签与类型（judgments / intelligences 下的 intel_types / tags_classes）
                judgments = ip_data.get('judgments') or []
                intel_types = []
                try:
                    intelligences = ip_data.get('intelligences') or {}
                    for items in intelligences.values():
                        for entry in items or []:
                            intel_types.extend(entry.get('intel_types', []) or [])
                            intel_types.extend(entry.get('intel_tags', []) or [])
                except Exception:
                    pass
                tags_classes = []
                try:
                    for tc in ip_data.get('tags_classes') or []:
                        tags_classes.extend(tc.get('tags', []) or [])
                except Exception:
                    pass
                labels = list({*judgments, *intel_types, *tags_classes})

                is_malicious = ip_data.get('is_malicious')
                if is_malicious is None:
                    is_malicious = bool(labels)

                location = {}
                try:
                    loc = ip_data.get('basic', {}).get('location', {}) or {}
                    location = {
                        'country': loc.get('country'),
                        'province': loc.get('province'),
                        'city': loc.get('city'),
                        'carrier': ip_data.get('basic', {}).get('carrier')
                    }
                except Exception:
                    location = {}

                base.update({
                    'is_malicious': is_malicious,
                    'severity': ip_data.get('severity'),
                    'confidence_level': ip_data.get('confidence_level'),
                    'judgments': judgments,
                    'labels': labels,
                    'location': location,
                    'raw': ip_data
                })

            return base

        except Exception as e:
            print(f"微步(ThreatBook) API 查询失败: {e}")
            return None

    @staticmethod
    def query_threatbook_http(ip: str, cookie: str) -> Optional[Dict[str, Any]]:
        """
        使用浏览器 Cookie 方式，通过 https://x.threatbook.com/v5/ip/<ip> 查询情报。
        适合 API 配额不足时临时人工复制 Cookie 使用。
        """
        base = {
            'source': 'threatbook',
            'is_malicious': False,
            'severity': None,
            'confidence_level': None,
            'judgments': [],
            'labels': [],
            'location': {},
            'raw': {}
        }

        cookie = (cookie or "").strip()
        if not cookie:
            return base

        ip = (ip or "").strip()
        m = re.search(r'(?:\d{1,3}\.){3}\d{1,3}', ip)
        if m:
            ip_param = m.group(0)
        else:
            return base

        url = f"https://x.threatbook.com/v5/ip/{ip_param}"
        headers = {
            "User-Agent": "Mozilla/5.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Referer": "https://x.threatbook.com/v5/serviceCenter?tab=apiAuth",
            "Cookie": cookie,
        }

        try:
            resp = requests.get(url, headers=headers, timeout=ThreatIntelService.TIMEOUT)
            resp.raise_for_status()
            text = resp.text or ""

            # 从 window.__INITIAL_STATE__ 中解析 JSON
            m = re.search(r"window\.__INITIAL_STATE__\s*=\s*(\{.*?\})\s*;", text, re.S)
            if not m:
                base['raw'] = {"html_snippet": text[:2000]}
                return base

            state = json.loads(m.group(1))
            data = state.get("data") or {}
            summary = data.get("summaryInfo") or {}

            judgments = summary.get("judgments") or []
            labels = []
            try:
                for j in judgments:
                    name = j.get("name")
                    if name:
                        labels.append(name)
            except Exception:
                pass

            events = summary.get("events") or []
            for ev in events:
                name = ev.get("name")
                if name:
                    labels.append(name)

            labels = list(set(labels))

            loc = summary.get("location") or {}
            location = {
                "country": loc.get("country"),
                "province": loc.get("province"),
                "city": loc.get("city"),
                "carrier": loc.get("carrier"),
            }

            judge = summary.get("judge")
            is_malicious = False
            try:
                if isinstance(judge, (int, float)):
                    # 0 通常为白名单/无风险，其它视为可疑/恶意
                    is_malicious = judge != 0
                elif labels:
                    is_malicious = True
            except Exception:
                is_malicious = bool(labels)

            base.update(
                {
                    "is_malicious": is_malicious,
                    "severity": None,
                    "confidence_level": None,
                    "judgments": labels,
                    "labels": labels,
                    "location": location,
                    "raw": summary or {},
                }
            )

            return base

        except Exception as e:
            print(f"微步(ThreatBook) HTTP 查询失败: {e}")
            return None


def query_pair(src_ip: Optional[str], dst_ip: Optional[str], cfg: Dict) -> Dict[str, Any]:
    """
    查询IP对的威胁情报
    
    Args:
        src_ip: 源IP
        dst_ip: 目的IP
        cfg: 配置字典
    
    Returns:
        dict: 聚合的威胁情报结果
    """
    result = {
        'src_ip_ti': None,
        'dst_ip_ti': None,
        'sources': []
    }
    
    providers_cfg = cfg.get('providers', {}) or {}
    tb_cfg = providers_cfg.get('threatbook', {}) or {}
    mode = tb_cfg.get('mode', 'both')  # both | src | dst
    
    # 查询源IP
    if src_ip and mode in ('both', 'src'):
        src_ti = _query_ip(src_ip, providers_cfg)
        result['src_ip_ti'] = src_ti
        if src_ti:
            result['sources'].extend(src_ti.get('sources', []))
    
    # 查询目的IP
    if dst_ip and mode in ('both', 'dst'):
        dst_ti = _query_ip(dst_ip, providers_cfg)
        result['dst_ip_ti'] = dst_ti
        if dst_ti:
            result['sources'].extend(dst_ti.get('sources', []))
    
    # 去重sources
    result['sources'] = list(set(result['sources']))
    
    return result


def _query_ip(ip: str, providers_cfg: Dict) -> Optional[Dict[str, Any]]:
    """
    查询单个IP的威胁情报
    
    Args:
        ip: IP地址
        providers_cfg: 提供商配置
    
    Returns:
        dict或None: 聚合结果
    """
    if not ip:
        return None
    
    ti_results = []
    sources = []

    # ThreatBook（唯一的 TI 源）
    tb_cfg = providers_cfg.get('threatbook', {}) or {}
    if tb_cfg.get('enabled'):
        request_mode = tb_cfg.get("request_mode", "api")
        if request_mode == "http":
            cookie = tb_cfg.get("http_cookie", "")
            result = ThreatIntelService.query_threatbook_http(ip, cookie)
        else:
            api_key = tb_cfg.get('api_key')
            result = ThreatIntelService.query_threatbook(ip, api_key)
        if result:
            ti_results.append(result)
            sources.append('threatbook')
    
    if not ti_results:
        return None
    
    # 聚合结果
    is_malicious = any(r.get('is_malicious', False) for r in ti_results)
    
    labels = []
    aggregated_location = None
    raw = None
    severity = None
    confidence_level = None

    # 目前只有 ThreatBook，一般只会有一个结果，此处仍按聚合逻辑写，便于未来扩展
    for result in ti_results:
        if result.get('source') == 'threatbook':
            labels.extend(result.get('labels', []) or result.get('judgments', []))
            if aggregated_location is None:
                aggregated_location = result.get('location')
            if raw is None:
                raw = result.get('raw')
            severity = severity or result.get('severity')
            confidence_level = confidence_level or result.get('confidence_level')

    return {
        'ip': ip,
        'is_malicious': is_malicious,
        'labels': list(set(labels)),
        'sources': sources,
        'details': ti_results,
        'location': aggregated_location,
        'severity': severity,
        'confidence_level': confidence_level,
        'raw': raw
    }
