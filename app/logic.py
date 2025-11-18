"""
业务逻辑模块
职责: 协调日志处理、威胁情报查询、AI分析等核心流程
"""
from typing import Dict, Any
import json
import requests
from core.parser import parse_text, parse_log
from core.lists import is_ip_in_list, read_lines
from core.ti_service import query_pair
from output.formatter import render_chat, render_excel


def process_log_data(
    text: str,
    cfg: Dict,
    enable_ti: bool = True,
    enable_ai: bool = True,
    format_type: str = 'chat'
) -> Dict[str, Any]:
    """
    完整日志处理流程：解析 -> TI查询 -> 列表检查 -> AI分析
    
    Args:
        text: 原始日志文本
        cfg: 配置字典
        enable_ti: 是否启用威胁情报查询
        enable_ai: 是否启用AI分析
        format_type: 输出格式 'chat' 或 'excel'
    
    Returns:
        dict: {
            'success': bool,
            'parsed_data': dict,           # 解析后的数据
            'ti_result': dict,             # 威胁情报结果
            'ai_result': str,              # AI分析结果
            'ip_list_alerts': dict,        # IP列表检查结果
            'formatted_output': str,       # 格式化输出
            'error': str                   # 错误信息
        }
    """
    result = {
        'success': False,
        'parsed_data': {},
        'ti_result': {},
        'ai_result': '',
        'ip_list_alerts': {},
        'formatted_output': '',
        'error': None
    }
    
    try:
        # 第1步: 解析文本（使用增强的 parse_log，兼容 v2.1 的规则配置）
        parsed = parse_log(text, cfg)
        parsed_data = parsed.get('data', {})
        warnings = parsed.get('warnings', [])

        if not parsed_data:
            result['error'] = '无法解析日志内容'
            return result

        result['parsed_data'] = parsed_data
        if warnings:
            result.setdefault('warnings', []).extend(warnings)
        
        # 第2步: 检查IP列表（白名单/黑名单）
        whitelist = []
        blacklist = []
        ip_list_alerts = {}
        
        lists_cfg = cfg.get('lists', {})
        whitelist_path = lists_cfg.get('whitelist_path')
        blacklist_path = lists_cfg.get('blocked_path')
        
        if whitelist_path:
            try:
                whitelist = read_lines(whitelist_path)
            except:
                pass
        
        if blacklist_path:
            try:
                blacklist = read_lines(blacklist_path)
            except:
                pass
        
        # 检查源IP和目的IP
        src_ip = parsed_data.get('src_ip')
        dst_ip = parsed_data.get('dst_ip')
        
        if src_ip:
            if is_ip_in_list(src_ip, whitelist):
                ip_list_alerts['src_ip_status'] = ('whitelist', src_ip)
            elif is_ip_in_list(src_ip, blacklist):
                ip_list_alerts['src_ip_status'] = ('blacklist', src_ip)
        
        if dst_ip:
            if is_ip_in_list(dst_ip, whitelist):
                ip_list_alerts['dst_ip_status'] = ('whitelist', dst_ip)
            elif is_ip_in_list(dst_ip, blacklist):
                ip_list_alerts['dst_ip_status'] = ('blacklist', dst_ip)
        
        result['ip_list_alerts'] = ip_list_alerts
        
        # 第3步: 威胁情报查询
        ti_result = {}
        if enable_ti and cfg.get('providers', {}) and (src_ip or dst_ip):
            try:
                # 始终查询威胁情报（即使命中白名单也展示情报，便于研判）
                ti_result = query_pair(src_ip, dst_ip, cfg)
            except Exception as e:
                result['error'] = f"威胁情报查询失败: {str(e)}"
                # 不中断流程，继续AI分析
        
        result['ti_result'] = ti_result
        
        # 第4步: AI分析
        ai_result = ""
        if enable_ai and cfg.get('ai', {}).get('enabled'):
            try:
                ai_result = _call_ai_analysis(parsed_data, ti_result, cfg)
            except Exception as e:
                ai_result = f"AI分析失败: {str(e)}"
        
        result['ai_result'] = ai_result
        
        # 第5步: 格式化输出
        # 添加静态字段
        output_data = dict(parsed_data)
        static_fields = cfg.get('static_fields', {})
        output_data.update(static_fields)
        
        if format_type == 'excel':
            formatted_output = render_excel(output_data, cfg)
        else:
            formatted_output = render_chat(output_data, cfg)
        
        result['formatted_output'] = formatted_output
        result['success'] = True
        
    except Exception as e:
        result['error'] = f"处理流程异常: {str(e)}"
    
    return result


def _call_ai_analysis(
    parsed_data: Dict,
    ti_result: Dict,
    cfg: Dict
) -> str:
    """
    调用AI进行告警研判
    
    Args:
        parsed_data: 解析后的数据
        ti_result: 威胁情报结果
        cfg: 配置字典
    
    Returns:
        str: AI分析结果
    """
    ai_cfg = cfg.get('ai', {})
    api_key = ai_cfg.get('api_key')
    base_url = ai_cfg.get('base_url', 'https://api.siliconflow.cn/v1')
    model = ai_cfg.get('model', 'deepseek-ai/DeepSeek-V2')
    
    if not api_key:
        return "AI API Key未配置"
    
    # 构造提示词
    prompt = _build_ai_prompt(parsed_data, ti_result, cfg)
    
    try:
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
        
        payload = {
            'model': model,
            'messages': [
                {
                    'role': 'user',
                    'content': prompt
                }
            ],
            'temperature': 0.7,
            'max_tokens': 1000
        }
        
        response = requests.post(
            f'{base_url}/chat/completions',
            json=payload,
            headers=headers,
            timeout=30
        )
        
        if response.status_code == 200:
            resp_json = response.json()
            choices = resp_json.get('choices', [])
            if choices:
                return choices[0].get('message', {}).get('content', '无AI响应')
            else:
                return "AI返回空响应"
        else:
            return f"AI API返回错误 {response.status_code}: {response.text[:200]}"
    
    except requests.exceptions.Timeout:
        return "AI API请求超时"
    except Exception as e:
        return f"AI API调用异常: {str(e)}"


def _build_ai_prompt(
    parsed_data: Dict,
    ti_result: Dict,
    cfg: Dict
) -> str:
    """
    构造发送给AI的提示词（CO-STAR 框架）
    C: Context  - 固定为日志解析结果 + 请求/响应载荷 + 威胁情报
    O: Objective - 从配置中读取，可自定义
    S: Style     - 固定为专业安全威胁分析风格
    T: Tone      - 固定为专业、客观、审慎的语气
    A: Audience  - 从配置中读取（客户 / 专业安全人员 / 安全初学者）
    R: Response  - 从配置中读取输出模式（结构化 / 简要 / 报告）
    """
    ai_cfg = cfg.get('ai', {}) or {}
    objective = ai_cfg.get(
        'objective',
        "对该告警进行专业安全威胁研判，给出威胁等级、是否需要封禁源IP/目的IP以及主要原因与风险分析。"
    ).strip()
    audience = ai_cfg.get('audience', 'expert')
    response_mode = ai_cfg.get('response_mode', 'structured')

    # -------- C: Context --------
    lines: list[str] = []
    lines.append("你是一名资深网络安全威胁分析专家。")
    lines.append("")
    lines.append("【C: Context】")
    lines.append("下面是一次安全告警的解析结果、请求/响应载荷以及对应的威胁情报，请基于这些信息进行研判。")
    lines.append("")
    # 先突出6个必填字段
    required_keys = ["src_ip", "dst_ip", "event_type", "request", "response", "payload"]
    field_labels = cfg.get("field_labels", {}) or {}

    lines.append("=== 关键信息（必填字段） ===")
    for key in required_keys:
        label = field_labels.get(key, key)
        value = parsed_data.get(key)
        if value:
            lines.append(f"{label}: {value}")
        else:
            lines.append(f"{label}: （未解析到该字段）")

    # 其余解析字段单独罗列，避免关键信息被淹没
    other_items = [(k, v) for k, v in parsed_data.items() if k not in required_keys and v]
    if other_items:
        lines.append("")
        lines.append("=== 其他解析字段 ===")
        for key, value in other_items:
            lines.append(f"{key}: {value}")

    # 添加威胁情报上下文（ThreatBook）
    if ti_result:
        lines.append("")
        lines.append("=== 威胁情报（ThreatBook） ===")

        def fmt_ti(prefix: str, ti: Dict) -> None:
            if not ti:
                return
            ip = ti.get('ip')
            is_mal = ti.get('is_malicious')
            labels = ti.get('labels') or []
            sev = ti.get('severity')
            conf = ti.get('confidence_level')
            loc = ti.get('location') or {}
            loc_parts = [loc.get('country'), loc.get('province'), loc.get('city')]
            loc_text = " / ".join([p for p in loc_parts if p])

            lines.append(f"{prefix} IP: {ip}；是否恶意: {'是' if is_mal else '否'}")
            if labels:
                lines.append(f"  威胁标签: {', '.join(labels)}")
            if sev:
                lines.append(f"  严重级别(severity): {sev}")
            if conf:
                lines.append(f"  可信度(confidence_level): {conf}")
            if loc_text:
                lines.append(f"  地理位置: {loc_text}")

        if ti_result.get('src_ip_ti'):
            fmt_ti("源", ti_result['src_ip_ti'])
        if ti_result.get('dst_ip_ti'):
            fmt_ti("目的", ti_result['dst_ip_ti'])

    # -------- O: Objective --------
    lines.append("")
    lines.append("【O: Objective】")
    lines.append(objective)

    # -------- S: Style --------
    lines.append("")
    lines.append("【S: Style】")
    lines.append("采用专业安全威胁分析人员的风格，结构清晰、分点说明，避免闲聊和无关内容。")

    # -------- T: Tone --------
    lines.append("")
    lines.append("【T: Tone】")
    lines.append("语气保持专业、客观、审慎，基于证据进行判断，不夸大也不过度保守。")

    # -------- A: Audience --------
    lines.append("")
    lines.append("【A: Audience】")
    if audience == 'customer':
        lines.append(
            "受众为业务方/客户：使用少量必要的安全术语，并用通俗语言解释其含义，重点说明对业务的影响和处置建议。"
        )
    elif audience == 'beginner':
        lines.append(
            "受众为安全初学者：尽量避免晦涩缩写，如必须使用（如 C2、Botnet 等），请在首次出现时用括号简要解释。"
        )
    else:
        lines.append(
            "受众为专业安全人员：可以使用专业术语（如 ATT&CK、C2、漏洞利用链等），不必解释基础概念，重点突出技术细节和研判依据。"
        )

    # -------- R: Response --------
    lines.append("")
    lines.append("【R: Response】")
    if response_mode == 'brief':
        lines.append(
            "请先用一行给出总体结论（例如：“本次告警风险偏高，建议封禁源IP”），"
            "随后用不超过3行列出支撑结论的关键原因。"
        )
    elif response_mode == 'report':
        lines.append(
            "请以 Markdown 二级标题分段输出完整报告，结构为："
            "“## 摘要”、“## 威胁分析”、“## 处置建议”。"
        )
    else:
        # structured
        lines.append(
            "请使用如下中文结构化格式输出（字段名保持不变，每行一项）：\n"
            "威胁等级：<高/中/低/信息>\n"
            "是否建议封禁：<是/否>（如有必要，可以区分源IP和目的IP）\n"
            "原因：<用1-2句话概括主要依据>\n"
            "风险分析：<从攻击者视角、受害者视角或业务影响等角度进行稍详细分析>"
        )

    return "\n".join(lines)


def validate_log_format(text: str, cfg: Dict) -> bool:
    """
    验证日志格式是否可被解析
    
    Args:
        text: 日志文本
        cfg: 配置字典
    
    Returns:
        bool: 是否可被解析
    """
    try:
        parsed = parse_log(text, cfg)
        data = parsed.get('data', {})
        if data:
            return True

        parsed = parse_text(text)
        return bool(parsed)
    except:
        return False
