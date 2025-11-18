"""后台工作线程模块"""
from datetime import datetime
from .ui_common import QObject, Signal, QThread
from app.logic import process_log_data, _call_ai_analysis, _call_ai_batch_analysis
from output.formatter import render_chat
from integration.webhook import send_record

class Worker(QObject):
    """异步工作线程基类"""
    done = Signal(dict)
    error = Signal(str)


class AIWorker(Worker):
    """AI分析工作线程"""
    def __init__(self, text, cfg, enable_ti, enable_ai, manual_fields=None):
        super().__init__()
        self.text = text
        self.cfg = cfg
        self.enable_ti = enable_ti
        self.enable_ai = enable_ai
        self.manual_fields = manual_fields or {}
    
    def run(self):
        try:
            result = process_log_data(self.text, self.cfg, self.enable_ti, self.enable_ai)
            # 合并人工字段到解析结果（若存在）
            if result.get('parsed_data') and self.manual_fields:
                pd = result['parsed_data']
                pd.update(self.manual_fields)
                # 重新生成格式化输出
                static_fields = self.cfg.get('static_fields', {})
                out_data = dict(pd)
                out_data.update(static_fields)
                result['formatted_output'] = render_chat(out_data, self.cfg)
            self.done.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class SendWorker(Worker):
    """消息发送工作线程"""
    def __init__(self, text, cfg):
        super().__init__()
        self.text = text
        self.cfg = cfg
    
    def run(self):
        try:
            result = send_record(self.text, self.cfg)
            self.done.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class TIWorker(Worker):
    """威胁情报测试工作线程（用于ConfigPage的测试按钮）"""
    def __init__(self, ip: str, cfg: dict, provider: str, api_key: str):
        super().__init__()
        self.ip = ip
        self.cfg = cfg
        self.provider = provider
        self.api_key = api_key

    def run(self):
        try:
            # 延迟导入以避免循环依赖
            from core.ti_service import ThreatIntelService

            if not self.ip:
                self.error.emit('未提供IP')
                return

            # 目前仅支持 ThreatBook
            if self.provider == 'threatbook':
                providers_cfg = self.cfg.get("providers", {}) or {}
                tb_cfg = providers_cfg.get("threatbook", {}) or {}
                request_mode = tb_cfg.get("request_mode", "api")
                if request_mode == "http":
                    cookie = tb_cfg.get("http_cookie", "")
                    res = ThreatIntelService.query_threatbook_http(self.ip, cookie)
                else:
                    api_key = self.api_key or tb_cfg.get("api_key", "")
                    res = ThreatIntelService.query_threatbook(self.ip, api_key)
            else:
                res = None

            # 标准化返回
            if res:
                self.done.emit({'provider': self.provider, 'result': res})
            else:
                self.done.emit({'provider': self.provider, 'result': None})

        except Exception as e:
            self.error.emit(str(e))


class LogTIWorker(Worker):
    """日志处理页用的威胁情报查询线程：根据源/目的IP查询 ThreatBook"""

    def __init__(self, src_ip: str | None, dst_ip: str | None, cfg: dict):
        super().__init__()
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.cfg = cfg

    def run(self):
        try:
            from core.ti_service import query_pair
            ti_result = query_pair(self.src_ip, self.dst_ip, self.cfg)
            self.done.emit({'ti_result': ti_result})
        except Exception as e:
            self.error.emit(str(e))


class LogAIWorker(Worker):
    """日志处理页用的 AI 研判线程：基于已解析字段和 TI 结果调用 AI"""

    def __init__(self, parsed_data: dict, ti_result: dict, cfg: dict):
        super().__init__()
        self.parsed_data = parsed_data or {}
        self.ti_result = ti_result or {}
        self.cfg = cfg

    def run(self):
        try:
            ai_text = _call_ai_analysis(self.parsed_data, self.ti_result, self.cfg)
            self.done.emit(
                {
                    "parsed_data": self.parsed_data,
                    "ti_result": self.ti_result,
                    "ai_result": ai_text,
                }
            )
        except Exception as e:
            self.error.emit(str(e))


class BatchAIWorker(Worker):
    """批量告警研判工作线程（用于 HistoryPage 多选告警）"""

    def __init__(self, entries: list[dict], cfg: dict):
        super().__init__()
        self.entries = entries or []
        self.cfg = cfg or {}

    def run(self):
        try:
            ai_text = _call_ai_batch_analysis(self.entries, self.cfg)
            self.done.emit({"ai_batch_result": ai_text})
        except Exception as e:
            self.error.emit(str(e))
