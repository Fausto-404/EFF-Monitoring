"""
威胁情报聚合模块
职责: 调用微步 ThreatBook、绿盟 NTI、奇安信 TI 和安恒 TI 接口，返回规范化结果
"""
import requests
import json
import re
from typing import Optional, Dict, Any


class ThreatIntelService:
    """微步在线 (ThreatBook) 威胁情报服务"""
    API_URL = "https://api.threatbook.cn/v3/scene/ip_reputation"
    
    @staticmethod
    def query_threatbook_api(ip: str, config: Dict) -> Optional[Dict[str, Any]]:
        """使用官方 API Key 查询"""
        base = {
            'source': 'threatbook',
            'is_malicious': False,
            'severity': None,
            'judgments': [],
            'labels': [],
            'location': {},
            'raw': {}
        }
        api_key = config.get("api_key", "").strip()
        if not api_key:
            return base

        m = re.search(r'(?:\d{1,3}\.){3}\d{1,3}', ip)
        ip_param = m.group(0) if m else None
        if not ip_param:
            return base

        try:
            params = {"apikey": api_key, "resource": ip_param, "lang": "zh"}
            resp = requests.get(ThreatIntelService.API_URL, params=params, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            base['raw'] = data

            if data.get('response_code') == 0:
                container = data.get('data') or data.get('ips') or {}
                ip_data = container.get(ip_param) or {}
                if ip_data:
                    basic = ip_data.get('basic', {})
                    loc = basic.get('location', {})
                    carrier = basic.get('carrier')
                    location = {
                        "country": loc.get('country'),
                        "province": loc.get('province'),
                        "city": loc.get('city'),
                        "carrier": carrier,
                    }
                    
                    # 提取标签 (Greedy 模式)
                    labels = []
                    labels.extend(ip_data.get('judgments') or [])
                    for tc in ip_data.get('tags_classes') or []:
                        labels.extend(tc.get('tags', []) or [])
                    scene = ip_data.get('scene')
                    if scene: labels.append(f"场景:{scene}")
                    if carrier: labels.append(carrier)
                    
                    labels = list(dict.fromkeys(filter(None, labels)))

                    base.update({
                        'is_malicious': ip_data.get('is_malicious', False),
                        'severity': ip_data.get('severity'),
                        'judgments': labels,
                        'labels': labels,
                        'location': location
                    })
            return base
        except Exception as e:
            print(f"微步 API 查询失败: {e}")
            return None

    @staticmethod
    def query_threatbook_http(ip: str, config: Dict) -> Optional[Dict[str, Any]]:
        base = {
            'source': 'threatbook',
            'is_malicious': False,
            'severity': None,
            'judgments': [],
            'labels': [],
            'location': {},
            'raw': {}
        }

        cookie = config.get("http_cookie", "").strip()
        if not cookie:
            return base

        m = re.search(r'(?:\d{1,3}\.){3}\d{1,3}', ip)
        ip_param = m.group(0) if m else None
        if not ip_param:
            return base

        url = f"https://x.threatbook.com/v5/ip/{ip_param}"
        csrf_token = config.get("x_csrf_token", "")
        xx_csrf = config.get("xx_csrf", "")
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Referer": f"https://x.threatbook.com/v5/ip/{ip_param}",
            "Cookie": cookie,
            "x-csrf-token": csrf_token,
            "xx-csrf": xx_csrf,
            "sec-ch-ua": '"Chromium";v="148", "Microsoft Edge";v="148", "Not/A)Brand";v="99"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"macOS"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
        }
        headers = {k: v for k, v in headers.items() if v}

        try:
            resp = requests.get(url, headers=headers, timeout=15)
            resp.raise_for_status()
            text = resp.text or ""

            m = re.search(r"window\.__INITIAL_STATE__\s*=\s*(\{.*?\})\s*;", text, re.S)
            if not m:
                base['raw'] = {"html_snippet": text[:2000]}
                return base

            state = json.loads(m.group(1))
            data = state.get("data") or {}
            summary = data.get("summaryInfo") or {}

            labels = []
            judgments = summary.get("judgments") or []
            for j in judgments:
                if j.get("name"):
                    labels.append(j.get("name"))
            
            events = summary.get("events") or []
            for ev in events:
                if ev.get("name"):
                    labels.append(ev.get("name"))

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
            if isinstance(judge, (int, float)):
                is_malicious = judge != 0
            elif labels:
                is_malicious = True

            base.update({
                "is_malicious": is_malicious,
                "judgments": list(set(labels)),
                "labels": list(set(labels)),
                "location": location,
                "raw": summary,
            })
            return base

        except Exception as e:
            print(f"微步 HTTP 查询失败: {e}")
            return None


class NSFocusService:
    """绿盟 (NSFocus NTI) 威胁情报服务"""
    NTI_URL = "https://nti.nsfocus.com/api/v2/objects/ioc-ipv4/"
    
    @staticmethod
    def query_nti(ip: str, config: Dict) -> Optional[Dict[str, Any]]:
        base = {
            'source': 'nsfocus',
            'is_malicious': False,
            'severity': None,
            'confidence_level': None,
            'judgments': [],
            'labels': [],
            'location': {},
            'raw': {}
        }
        
        api_key = config.get("api_key", "").strip()
        if not api_key:
            return base

        m = re.search(r'(?:\d{1,3}\.){3}\d{1,3}', ip)
        ip_param = m.group(0) if m else None
        if not ip_param:
            return base

        headers = {
            "Accept": "application/nsfocus.nti.spec+json; version=2.0",
            "X-Ns-Nti-Key": api_key,
            "Accept-encoding": "gzip"
        }
        
        try:
            resp = requests.get(NSFocusService.NTI_URL, params={"query": ip_param}, headers=headers, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            base['raw'] = data
            objects = data.get('objects') or []
            # 无论是否有 objects，都要保留 raw 供分析
            base['raw'] = data

            labels = []
            max_threat_level = 0

            for obj in objects:
                # 提取分类：ip, c2, malware_family 等
                labels.extend(obj.get('categories') or [])
                # 提取绿盟标签
                for tag_obj in obj.get('tags', []):
                    labels.extend(tag_obj.get('tag_values', []))

                # 记录最高威胁等级
                lvl = obj.get('threat_level') or 0
                if lvl > max_threat_level:
                    max_threat_level = lvl

            # 即使绿盟没返回地理位置，也可以通过 API 获取一些描述性标签
            # 尝试通过 fallback 获取位置并提取运营商标签
            fallback_loc = get_fallback_location(ip_param)
            if fallback_loc:
                base['location'] = fallback_loc
                if fallback_loc.get('carrier'):
                    labels.append(fallback_loc['carrier'])

            labels = list(dict.fromkeys(filter(None, labels)))

            severity_map = {1: "low", 3: "medium", 5: "high"}
            
            base.update({
                'is_malicious': max_threat_level > 0,
                'severity': severity_map.get(max_threat_level),
                'judgments': list(set(labels)),
                'labels': list(set(labels)),
            })
            return base
        except Exception as e:
            print(f"绿盟 NTI 查询失败: {e}")
            return None


class QiAnXinService:
    """奇安信 TI 威胁情报服务"""
    API_URL = "https://webapi.ti.qianxin.com/ip/v3/reputation"

    @staticmethod
    def query_qianxin(ip: str, config: Dict) -> Optional[Dict[str, Any]]:
        base = {
            'source': 'qianxin',
            'is_malicious': False,
            'severity': None,
            'confidence_level': None,
            'judgments': [],
            'labels': [],
            'location': {},
            'raw': {}
        }
        api_key = config.get("api_key", "").strip()
        if not api_key:
            return base

        m = re.search(r'(?:\d{1,3}\.){3}\d{1,3}', ip)
        ip_param = m.group(0) if m else None
        if not ip_param:
            return base

        headers = {"Api-Key": api_key}
        try:
            resp = requests.get(QiAnXinService.API_URL, params={"param": ip_param}, headers=headers, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            base['raw'] = data

            if data.get('status') == 10000:
                ip_data = data.get('data', {}).get(ip_param)
                if ip_data:
                    geo = ip_data.get('geo', {})
                    location = {
                        "country": geo.get('country'),
                        "province": geo.get('province'),
                        "city": geo.get('city'),
                        "carrier": ip_data.get('normal_info', {}).get('asn_org'),
                    }
                    
                    summary = ip_data.get('summary_info', {})
                    labels = []
                    labels.extend(summary.get('malicious_label') or [])
                    labels.extend(summary.get('ip_infrastructure_label') or [])
                    labels.extend(summary.get('ipservice_benign_label') or [])
                    
                    # 威胁事件列表
                    threat_events = []
                    
                    # 处理 compromised_info
                    for comp in ip_data.get('compromised_info', []) or []:
                        if comp.get('malware_family'): labels.append(f"家族:{comp['malware_family']}")
                        threat_events.append({
                            "source": "qianxin",
                            "type": "compromised_info",
                            "malicious_family": [comp.get('malware_family')] if comp.get('malware_family') else [],
                            "malicious_type": comp.get('malicious_type'),
                            "etime": comp.get('etime'),
                        })

                    # 处理 compromise (重点修复)
                    for item in ip_data.get('compromise', []) or []:
                        event = {
                            "source": "qianxin",
                            "type": "compromise",
                            "alert_name": item.get("alert_name"),
                            "malicious_type": item.get("malicious_type"),
                            "kill_chain": item.get("kill_chain"),
                            "risk": item.get("risk"),
                            "confidence": item.get("confidence"),
                            "current_status": item.get("current_status"),
                            "etime": item.get("etime"),
                            "malicious_family": item.get("malicious_family") or [],
                            "tag": item.get("tag") or [],
                            "platform": item.get("platform"),
                            "ioc": item.get("ioc") or [],
                            "ioc_category": item.get("ioc_category"),
                            "ttp": item.get("TTP")
                        }
                        threat_events.append(event)
                        
                        # 提取标签
                        if item.get("alert_name"): labels.append(item.get("alert_name"))
                        if item.get("malicious_type"): labels.append(item.get("malicious_type"))
                        if item.get("kill_chain"): labels.append(f"kill_chain:{item.get('kill_chain')}")
                        if item.get("risk"): labels.append(f"风险:{item.get('risk')}")
                        if item.get("confidence"): labels.append(f"置信度:{item.get('confidence')}")
                        for f in (item.get("malicious_family") or []): labels.append(f"家族:{f}")
                        for t in (item.get("tag") or []): labels.append(f"tag:{t}")
                        if item.get("platform"): labels.append(f"平台:{item.get('platform')}")

                    user_type = ip_data.get('normal_info', {}).get('user_type')
                    if user_type: labels.append(user_type)
                    labels = list(dict.fromkeys(filter(None, labels)))
                    
                    reputation = summary.get('reputation', 'unknown')
                    is_malicious = reputation in ('malicious', 'suspicious')
                    
                    # 风险判定增强
                    sev_score = {"high": 3, "medium": 2, "low": 1, None: 0}
                    current_sev = None
                    
                    # 1. 原始恶意信息
                    mal_infos = ip_data.get('malicious_info', [])
                    if mal_infos:
                        current_sev = mal_infos[0].get('severity')
                    
                    # 2. 如果 reputation 对应等级更高
                    rep_sev = "high" if reputation == "malicious" else "medium" if reputation == "suspicious" else None
                    if sev_score.get(rep_sev, 0) > sev_score.get(current_sev, 0):
                        current_sev = rep_sev

                    # 3. compromise 中的 risk
                    for te in threat_events:
                        risk = te.get("risk")
                        if risk in ("high", "medium", "low", "critical"):
                            # 把 critical 映射为 high
                            mapped_risk = "high" if risk in ("high", "critical") else risk
                            if sev_score.get(mapped_risk, 0) > sev_score.get(current_sev, 0):
                                current_sev = mapped_risk
                            # 如果有中高风险事件，判定为恶意
                            if risk in ("high", "medium", "critical"):
                                is_malicious = True

                    base.update({
                        'is_malicious': is_malicious,
                        'severity': current_sev,
                        'judgments': labels,
                        'labels': labels,
                        'location': location,
                        'threat_events': threat_events
                    })
            return base
        except Exception as e:
            print(f"奇安信 TI 查询失败: {e}")
            return None


class DBAppService:
    """安恒 (DBAppSecurity) 威胁情报服务"""
    API_URL = "https://ti.dbappsecurity.com.cn/oapi/v1/ip-threat-intel"

    @staticmethod
    def query_dbapp(ip: str, config: Dict) -> Optional[Dict[str, Any]]:
        base = {
            'source': 'dbapp',
            'is_malicious': False,
            'severity': None,
            'confidence_level': None,
            'judgments': [],
            'labels': [],
            'location': {},
            'raw': {}
        }
        api_key = config.get("api_key", "").strip()
        if not api_key:
            return base

        m = re.search(r'(?:\d{1,3}\.){3}\d{1,3}', ip)
        ip_param = m.group(0) if m else None
        if not ip_param:
            return base

        headers = {"X-API-Key": api_key}
        try:
            resp = requests.get(DBAppService.API_URL, params={"ip": ip_param}, headers=headers, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            base['raw'] = data

            if data.get('code') == 0:
                res_data = data.get('data', {})
                basic = res_data.get('basic_info', {})
                geo = basic.get('geolocation', {})
                location = {
                    "country": geo.get('country'),
                    "province": geo.get('subdivisions'),
                    "city": geo.get('city'),
                    "carrier": geo.get('isp'),
                }
                
                threat = basic.get('threat_intel', {})
                labels = list(threat.get('tags', []) or [])
                for cat in threat.get('threat_category', []) or []:
                    if cat.get('name'): labels.append(cat.get('name'))
                
                # 提取组织与家族
                for g in threat.get('related_hacker_groups', []) or []:
                    if g.get('name'): labels.append(f"组织:{g['name']}")
                for f in threat.get('related_families', []) or []:
                    if f.get('name'): labels.append(f"家族:{f['name']}")

                labels = list(dict.fromkeys(filter(None, labels)))
                
                base.update({
                    'is_malicious': lvl > 0,
                    'severity': severity_map.get(lvl),
                    'judgments': list(set(labels)),
                    'labels': list(set(labels)),
                    'location': location
                })
            return base
        except Exception as e:
            print(f"安恒 TI 查询失败: {e}")
            return None


def get_fallback_location(ip: str) -> Optional[Dict[str, str]]:
    """使用公共 GeoIP API (ip-api.com) 进行位置兜底"""
    try:
        url = f"http://ip-api.com/json/{ip}?lang=zh-CN"
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country"),
                    "province": data.get("regionName"),
                    "city": data.get("city"),
                    "carrier": data.get("isp"),
                }
    except Exception:
        pass
    return None


def query_pair(src_ip: Optional[str], dst_ip: Optional[str], cfg: Dict) -> Dict[str, Any]:
    result = {'src_ip_ti': None, 'dst_ip_ti': None, 'sources': []}
    providers_cfg = cfg.get('providers', {}) or {}
    if not providers_cfg.get('enabled', True):
        return result
        
    mode = providers_cfg.get('mode', 'both')
    
    if src_ip and mode in ('both', 'src'):
        src_ti = _query_ip(src_ip, providers_cfg)
        result['src_ip_ti'] = src_ti
        if src_ti:
            result['sources'].extend(src_ti.get('sources', []))
    
    if dst_ip and mode in ('both', 'dst'):
        dst_ti = _query_ip(dst_ip, providers_cfg)
        result['dst_ip_ti'] = dst_ti
        if dst_ti:
            result['sources'].extend(dst_ti.get('sources', []))
    
    result['sources'] = list(set(result['sources']))
    return result


def _query_ip(ip: str, providers_cfg: Dict) -> Optional[Dict[str, Any]]:
    if not ip:
        return None
    
    active_provider = providers_cfg.get('active_provider', 'threatbook')
    ti_results = []
    
    if active_provider == 'nsfocus':
        nti_cfg = providers_cfg.get('nsfocus', {}) or {}
        res = NSFocusService.query_nti(ip, nti_cfg)
        if res: ti_results.append(res)
    elif active_provider == 'qianxin':
        qax_cfg = providers_cfg.get('qianxin', {}) or {}
        res = QiAnXinService.query_qianxin(ip, qax_cfg)
        if res: ti_results.append(res)
    elif active_provider == 'dbapp':
        dbapp_cfg = providers_cfg.get('dbapp', {}) or {}
        res = DBAppService.query_dbapp(ip, dbapp_cfg)
        if res: ti_results.append(res)
    else:
        tb_cfg = providers_cfg.get('threatbook', {}) or {}
        mode = tb_cfg.get("mode", "api")
        if mode == "web":
            res = ThreatIntelService.query_threatbook_http(ip, tb_cfg)
        else:
            res = ThreatIntelService.query_threatbook_api(ip, tb_cfg)
        if res: ti_results.append(res)
    
    if not ti_results:
        return None
    
    labels = []
    is_malicious = False
    aggregated_location = None
    severity = None
    raw = None
    sources = []
    threat_events = []

    for r in ti_results:
        is_malicious = is_malicious or r.get('is_malicious', False)
        labels.extend(r.get('labels', []))
        if aggregated_location is None:
            aggregated_location = r.get('location')
        if severity is None:
            severity = r.get('severity')
        if raw is None:
            raw = r.get('raw')
        sources.append(r.get('source'))
        if r.get('threat_events'):
            threat_events.extend(r.get('threat_events'))

    # 如果当前提供商没有返回位置信息（如绿盟 IOC），则使用兜底 GeoIP
    if not aggregated_location or not any(aggregated_location.values()):
        fallback = get_fallback_location(ip)
        if fallback:
            aggregated_location = fallback

    loc = aggregated_location or {}
    parts = filter(None, [loc.get('country'), loc.get('province'), loc.get('city')])
    location_str = ".".join(parts)
    if not location_str:
        location_str = loc.get('country') or loc.get('carrier') or ""

    return {
        'ip': ip,
        'is_malicious': is_malicious,
        'labels': list(set(labels)),
        'sources': sources,
        'source': sources[0] if sources else None,
        'location': aggregated_location,
        'location_str': location_str,
        'severity': severity,
        'threat_events': threat_events,
        'raw': raw
    }
