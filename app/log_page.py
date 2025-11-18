"""日志处理页面"""
from pathlib import Path
from datetime import datetime
import json as pyjson

from .ui_common import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QTextEdit,
    QLabel, QPushButton, QTabWidget, QListWidget, QListWidgetItem,
    QMessageBox, QInputDialog, QApplication, Qt, QThread, QToolTip
)
from core.regex import load_engine
from app.logic import process_log_data
from output.formatter import render_chat, render_excel, render_ai_result
from .workers import SendWorker, LogTIWorker, LogAIWorker

class LogPage(QWidget):
    """日志处理页面"""
    def __init__(self, cfg):
        super().__init__()
        self.cfg = cfg
        self.current_result = {}
        self.engine = load_engine(cfg)
        self.theme = "light"
        # 运行时总开关（由主窗口控制）
        self.enable_ti = True
        self.enable_ai = True
        self.enable_webhook = True
        self.history_file = Path("output/log_history.json")
        self.history_limit = 200
        self.history = []
        self._load_history_config()
        self.history = self._load_history()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # 上半部分：输入区域
        input_group = QGroupBox("原始日志")
        input_layout = QVBoxLayout()
        
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("粘贴原始告警日志...")
        input_layout.addWidget(self.input_text)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group, 2)
        # 按钮行
        button_layout = QHBoxLayout()
        
        self.parse_btn = QPushButton("处理日志")
        self.parse_btn.clicked.connect(self.on_parse)
        button_layout.addWidget(self.parse_btn)
        
        self.ai_btn = QPushButton("告警研判")
        self.ai_btn.clicked.connect(self.on_ai_analysis)
        button_layout.addWidget(self.ai_btn)
        
        self.send_btn = QPushButton("发送到群聊")
        self.send_btn.clicked.connect(self.on_send_webhook)
        button_layout.addWidget(self.send_btn)
        
        self.clear_btn = QPushButton("清空")
        self.clear_btn.clicked.connect(self.on_clear)
        button_layout.addWidget(self.clear_btn)
        
        layout.addLayout(button_layout)
        
        # 标签页：结果显示
        self.tab_widget = QTabWidget()
        
        # 解析结果标签页（拆分为消息/Excel格式）
        parse_container = QWidget()
        parse_layout = QVBoxLayout()
        parse_layout.addWidget(QLabel("消息格式"))
        self.parse_msg_text = QTextEdit()
        self.parse_msg_text.setReadOnly(True)
        parse_layout.addWidget(self.parse_msg_text)
        parse_layout.addWidget(QLabel("Excel格式"))
        self.parse_excel_text = QTextEdit()
        self.parse_excel_text.setReadOnly(True)
        parse_layout.addWidget(self.parse_excel_text)
        parse_container.setLayout(parse_layout)
        self.tab_widget.addTab(parse_container, "解析结果")
        
        # 威胁情报标签页
        self.ti_result_text = QTextEdit()
        self.ti_result_text.setReadOnly(True)
        # 让源/目的IP情报区域整体看起来更对称：统一左右内边距
        self.ti_result_text.setStyleSheet(
            "QTextEdit { padding-left: 4px; padding-right: 4px; }"
        )
        self.tab_widget.addTab(self.ti_result_text, "威胁情报")
        
        # AI研判结果标签页
        self.ai_result_text = QTextEdit()
        self.ai_result_text.setReadOnly(True)
        self.tab_widget.addTab(self.ai_result_text, "AI研判结果")
        
        layout.addWidget(self.tab_widget, 3)
        
        # 输出格式区域
        output_layout = QHBoxLayout()
        self.copy_msg_btn = QPushButton("复制消息格式化结果")
        self.copy_msg_btn.clicked.connect(self.on_copy_msg_output)
        output_layout.addWidget(self.copy_msg_btn)
        self.copy_excel_btn = QPushButton("复制Excel格式化结果")
        self.copy_excel_btn.clicked.connect(self.on_copy_excel_output)
        output_layout.addWidget(self.copy_excel_btn)
        output_layout.addStretch()
        
        layout.addLayout(output_layout)

        self.setLayout(layout)
        # 初始按钮样式
        self._set_btn_state(self.parse_btn, "idle")
        self._set_btn_state(self.ai_btn, "idle")
        self._set_btn_state(self.send_btn, "idle")
    
    def set_feature_toggles(self, ti_enabled: bool, ai_enabled: bool, webhook_enabled: bool):
        """由主窗口调用，更新 TI / AI / Webhook 的运行时总开关"""
        self.enable_ti = bool(ti_enabled)
        self.enable_ai = bool(ai_enabled)
        self.enable_webhook = bool(webhook_enabled)
    
    def on_parse(self):
        """解析日志"""
        text = self.input_text.toPlainText().strip()
        if not text:
            QMessageBox.warning(self, "警告", "请输入日志内容")
            return
        
        # 禁用按钮
        self.parse_btn.setEnabled(False)
        self._set_btn_state(self.parse_btn, "busy")
        
        try:
            result = process_log_data(text, self.cfg, enable_ti=False, enable_ai=False)
            self.current_result = result
            
            if result['success']:
                # 显示解析结果
                self._update_outputs(result['parsed_data'])
                self._save_history_entry(text, result)
                self._show_ip_list_alerts(result.get('ip_list_alerts'))
                
                self.tab_widget.setCurrentIndex(0)
            else:
                QMessageBox.critical(self, "错误", f"解析失败: {result.get('error', '未知错误')}")
        
        except Exception as e:
            QMessageBox.critical(self, "异常", f"处理异常: {str(e)}")
        
        finally:
            self.parse_btn.setEnabled(True)
            self._set_btn_state(self.parse_btn, "idle")
    
    def on_ai_analysis(self):
        """执行AI研判"""
        if not self.current_result.get('parsed_data'):
            QMessageBox.warning(self, "警告", "请先解析日志")
            return
        
        # 若 TI 和 AI 都未启用，则直接提示
        if not self.enable_ti and not self.enable_ai:
            QMessageBox.information(self, "提示", "已关闭威胁情报和AI分析，请先在顶部开关中启用其中至少一项。")
            return
        
        # 禁用按钮
        self.ai_btn.setEnabled(False)
        self.ai_btn.setText("查询情报中...")
        self._set_btn_state(self.ai_btn, "busy")

        parsed = self.current_result.get("parsed_data") or {}
        src_ip = parsed.get("src_ip")
        dst_ip = parsed.get("dst_ip")
        
        # 若启用 TI，则先异步查询威胁情报，之后视情况启动 AI；
        # 若未启用 TI 但启用 AI，则直接启动 AI（无 TI 上下文）。
        if self.enable_ti:
            self.ti_worker_for_log = LogTIWorker(src_ip, dst_ip, self.cfg)
            self.ti_thread_for_log = QThread()
            self.ti_worker_for_log.moveToThread(self.ti_thread_for_log)
            self.ti_worker_for_log.done.connect(self.on_ti_for_ai_done)
            self.ti_worker_for_log.error.connect(self.on_ti_for_ai_error)
            self.ti_thread_for_log.started.connect(self.ti_worker_for_log.run)
            self.ti_thread_for_log.start()
        else:
            # 只做 AI 分析
            self._start_ai_worker(parsed, {})

    def on_ti_for_ai_done(self, payload: dict):
        """威胁情报查询完成后，先展示情报，再启动AI分析"""
        try:
            self.ti_thread_for_log.quit()
            self.ti_thread_for_log.wait()
        except Exception:
            pass

        ti_result = payload.get("ti_result") or {}
        self.current_result["ti_result"] = ti_result

        # 展示威胁情报（立即反馈给用户）
        if ti_result:
            ti_html = self._render_ti_html(ti_result)
            self.ti_result_text.setHtml(ti_html)
            self.tab_widget.setCurrentIndex(1)  # 切到“威胁情报”标签
        
        # 如启用 AI，则继续启动 AI 分析；否则只展示 TI
        parsed = self.current_result.get("parsed_data") or {}
        if self.enable_ai:
            self._start_ai_worker(parsed, ti_result)
        else:
            self.ai_btn.setEnabled(True)
            self.ai_btn.setText("告警研判")
            self._set_btn_state(self.ai_btn, "idle")

    def _start_ai_worker(self, parsed: dict, ti_result: dict):
        """启动 AI 分析线程"""
        self.ai_btn.setText("AI分析中...")
        self.ai_worker_for_log = LogAIWorker(parsed or {}, ti_result or {}, self.cfg)
        self.ai_thread_for_log = QThread()
        self.ai_worker_for_log.moveToThread(self.ai_thread_for_log)
        self.ai_worker_for_log.done.connect(self.on_ai_done)
        self.ai_worker_for_log.error.connect(self.on_ai_error)
        self.ai_thread_for_log.started.connect(self.ai_worker_for_log.run)
        self.ai_thread_for_log.start()

    def on_ti_for_ai_error(self, error: str):
        """威胁情报查询失败"""
        try:
            self.ti_thread_for_log.quit()
            self.ti_thread_for_log.wait()
        except Exception:
            pass

        QMessageBox.critical(self, "错误", f"威胁情报查询异常: {error}")

        # 即便 TI 失败，如启用 AI，也允许继续尝试 AI（但上下文会缺少 TI）
        if self.enable_ai:
            parsed = self.current_result.get("parsed_data") or {}
            self._start_ai_worker(parsed, {})
        else:
            self.ai_btn.setEnabled(True)
            self.ai_btn.setText("告警研判")
            self._set_btn_state(self.ai_btn, "idle")

    def on_ai_done(self, payload: dict):
        """AI分析完成"""
        try:
            self.ai_thread_for_log.quit()
            self.ai_thread_for_log.wait()
        except Exception:
            pass

        self.ai_btn.setEnabled(True)
        self.ai_btn.setText("告警研判")
        self._set_btn_state(self.ai_btn, "idle")

        parsed = payload.get("parsed_data") or self.current_result.get("parsed_data") or {}
        ti_result = payload.get("ti_result") or self.current_result.get("ti_result") or {}
        ai_result = payload.get("ai_result") or ""

        self.current_result["parsed_data"] = parsed
        self.current_result["ti_result"] = ti_result
        self.current_result["ai_result"] = ai_result

        if ti_result:
            ti_html = self._render_ti_html(ti_result)
            self.ti_result_text.setHtml(ti_html)

        if ai_result:
            ai_text = render_ai_result(ai_result)
            self.ai_result_text.setText(ai_text)

        if parsed:
            self._update_outputs(parsed)

    def on_ai_error(self, error):
        """AI分析出错"""
        try:
            self.ai_thread_for_log.quit()
            self.ai_thread_for_log.wait()
        except Exception:
            pass

        self.ai_btn.setEnabled(True)
        self.ai_btn.setText("告警研判")
        self._set_btn_state(self.ai_btn, "idle")

        QMessageBox.critical(self, "错误", f"AI分析异常: {error}")
    
    def on_send_webhook(self):
        """发送到群聊"""
        if not self.current_result.get('formatted_output'):
            QMessageBox.warning(self, "警告", "请先处理日志")
            return
        if not self.enable_webhook:
            QMessageBox.information(self, "提示", "消息推送已关闭，请在顶部开关中启用后再发送。")
            return
        
        # 禁用按钮
        self.send_btn.setEnabled(False)
        self.send_btn.setText("发送中...")
        self._set_btn_state(self.send_btn, "busy")
        
        # 在发送前合并人工字段并重新生成输出
        text = self.current_result.get('formatted_message', '') or self.current_result.get('formatted_output', '')

        self.send_worker = SendWorker(text, self.cfg)
        self.send_thread = QThread()
        self.send_worker.moveToThread(self.send_thread)
        self.send_worker.done.connect(self.on_send_done)
        self.send_worker.error.connect(self.on_send_error)
        self.send_thread.started.connect(self.send_worker.run)
        
        self.send_thread.start()
    
    def on_send_done(self, result):
        """发送完成"""
        self.send_thread.quit()
        self.send_thread.wait()
        
        self.send_btn.setEnabled(True)
        self.send_btn.setText("发送到群聊")
        self._set_btn_state(self.send_btn, "idle")
        
        details = result.get('details', {})
        msg = f"成功: {result['success']}, 失败: {result['failed']}"
        
        QMessageBox.information(self, "发送结果", msg)
    
    def on_send_error(self, error):
        """发送出错"""
        self.send_thread.quit()
        self.send_thread.wait()
        
        self.send_btn.setEnabled(True)
        self.send_btn.setText("发送到群聊")
        self._set_btn_state(self.send_btn, "idle")
        
        QMessageBox.critical(self, "错误", f"发送异常: {error}")
    
    def on_copy_msg_output(self):
        """复制消息格式化输出"""
        if not self.current_result.get('formatted_message'):
            QMessageBox.warning(self, "警告", "请先处理日志")
            return
        clipboard = QApplication.clipboard()
        clipboard.setText(self.current_result['formatted_message'])
        # 使用轻量提示而非阻塞对话框
        pos = self.copy_msg_btn.mapToGlobal(self.copy_msg_btn.rect().center())
        QToolTip.showText(pos, "已复制消息格式化结果")

    def on_copy_excel_output(self):
        """复制Excel格式化输出"""
        if not self.current_result.get('formatted_excel'):
            QMessageBox.warning(self, "警告", "请先处理日志")
            return
        clipboard = QApplication.clipboard()
        clipboard.setText(self.current_result['formatted_excel'])
        pos = self.copy_excel_btn.mapToGlobal(self.copy_excel_btn.rect().center())
        QToolTip.showText(pos, "已复制Excel格式化结果")
    
    def on_clear(self):
        """清空"""
        self.input_text.clear()
        self.parse_msg_text.clear()
        self.parse_excel_text.clear()
        self.ti_result_text.clear()
        self.ai_result_text.clear()
        self.current_result = {}
    
    def reload_config(self, cfg):
        """重新加载配置"""
        self.cfg = cfg
        self.engine = load_engine(cfg)

    def set_theme(self, theme: str):
        """由主窗口调用，切换浅色/深色模式时同步给TI渲染"""
        self.theme = theme
        # 重新渲染当前TI结果，使卡片背景随主题更新
        ti_result = self.current_result.get("ti_result")
        if ti_result:
            self.ti_result_text.setHtml(self._render_ti_html(ti_result))

    def _update_outputs(self, parsed_data: dict):
        """根据解析结果生成消息/Excel格式输出并刷新显示"""
        base = dict(parsed_data or {})
        static_fields = self.cfg.get('static_fields', {})
        base.update(static_fields)
        msg_fmt = render_chat(base, self.cfg)
        excel_fmt = render_excel(base, self.cfg)
        self.current_result['parsed_data'] = base
        self.current_result['formatted_message'] = msg_fmt
        self.current_result['formatted_excel'] = excel_fmt
        # 保留兼容字段
        self.current_result['formatted_output'] = msg_fmt
        self.parse_msg_text.setText(msg_fmt)
        self.parse_excel_text.setText(excel_fmt)

    def _set_btn_state(self, btn: QPushButton, state: str = "idle"):
        """统一控制按钮状态颜色，区分运行中/空闲"""
        palettes = {
            "idle": "background-color: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #6fe3b2, stop:1 #43c28d);"
                    "color: #ffffff; border-radius: 10px; padding: 10px 14px; font-weight:600;",
            "busy": "background-color: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #ffb347, stop:1 #ff7b5a);"
                    "color: #ffffff; border-radius: 10px; padding: 10px 14px; font-weight:600;"
        }
        btn.setStyleSheet(palettes.get(state, palettes["idle"]))

    def _render_ti_html(self, ti_result: dict) -> str:
        """将TI结果渲染为富文本，恶意标红"""
        if not ti_result:
            return "<p>无威胁情报数据</p>"

        src = ti_result.get('src_ip_ti') or {}
        dst = ti_result.get('dst_ip_ti') or {}

        # 若两侧都没有查询结果，给出更明确的提示，避免误解为接口异常
        if not src and not dst:
            return "<p>未查询到源/目的IP的威胁情报（可能未解析出IP或情报源无记录）。</p>"

        def zh_severity(sev: str | None) -> str:
            mapping = {
                "critical": "严重",
                "high": "高",
                "medium": "中",
                "low": "低",
                "info": "无威胁"
            }
            return mapping.get((sev or "").lower(), sev or "")

        def zh_confidence(conf: str | None) -> str:
            mapping = {
                "high": "高",
                "medium": "中",
                "low": "低"
            }
            return mapping.get((conf or "").lower(), conf or "")

        def fmt_one(title, ti):
            if not ti:
                return ""
            malicious = ti.get('is_malicious')
            color = "#ff4d4f" if malicious else "#4caf50"
            labels = ", ".join(ti.get('labels') or [])
            severity = zh_severity(ti.get('severity'))
            confidence = zh_confidence(ti.get('confidence_level'))
            loc = ti.get('location') or {}
            loc_parts = [loc.get('country'), loc.get('province'), loc.get('city')]
            loc_text = " / ".join([p for p in loc_parts if p])
            if loc.get('carrier'):
                loc_text = f"{loc_text} ({loc['carrier']})" if loc_text else loc['carrier']
            sources = ", ".join(ti.get('sources') or [])
            raw_json = pyjson.dumps(ti.get('raw') or {}, ensure_ascii=False, indent=2)
            if self.theme == "dark":
                card_bg = "#111827"
                card_border = "#374151"
                pre_bg = "#020617"
            else:
                card_bg = "#fafbff"
                card_border = "#e4e8f0"
                pre_bg = "#f5f7fb"
            return f"""
            <div style='margin-bottom:12px; padding:10px; border:1px solid {card_border}; border-radius:10px; background:{card_bg};'>
              <div style='font-weight:600;'>{title}</div>
              <div>IP: {ti.get('ip')}</div>
              <div>是否恶意: <span style='color:{color};'>{'是' if malicious else '否'}</span></div>
              {'<div>威胁等级: ' + severity + '</div>' if severity else ''}
              {'<div>置信度: ' + confidence + '</div>' if confidence else ''}
              {'<div>威胁标签: ' + labels + '</div>' if labels else ''}
              {'<div>地理位置: ' + loc_text + '</div>' if loc_text else ''}
              {'<div>来源: ' + sources + '</div>' if sources else ''}
              <pre style='background:{pre_bg}; padding:8px; border-radius:8px; margin-top:8px; white-space:pre-wrap; word-wrap:break-word;'>{raw_json}</pre>
            </div>
            """

        # 顶部总体概览
        summary_parts = []
        if src:
            sev = zh_severity(src.get('severity'))
            conf = zh_confidence(src.get('confidence_level'))
            summary_parts.append(
                f"源IP {src.get('ip','')}：{'恶意' if src.get('is_malicious') else '非恶意'}"
                f"{'，等级 ' + sev if sev else ''}"
                f"{'，置信度 ' + conf if conf else ''}"
            )
        if dst:
            sev = zh_severity(dst.get('severity'))
            conf = zh_confidence(dst.get('confidence_level'))
            summary_parts.append(
                f"目的IP {dst.get('ip','')}：{'恶意' if dst.get('is_malicious') else '非恶意'}"
                f"{'，等级 ' + sev if sev else ''}"
                f"{'，置信度 ' + conf if conf else ''}"
            )

        summary_html = ""
        if summary_parts:
            if self.theme == "dark":
                s_bg = "#064e3b"
                s_border = "#10b981"
            else:
                s_bg = "#eefdf5"
                s_border = "#bbf7d0"
            summary_html = (
                "<div style='margin-bottom:12px; padding:10px; border-radius:8px; "
                f"background:{s_bg}; border:1px solid {s_border}; font-size:13px;'>"
                "<b>总体概览：</b><br>" + "<br>".join(summary_parts) + "</div>"
            )

        # 下层：分别展示源/目的IP威胁情报（上下两块，不再左右并排，避免横向滚动）
        src_html = fmt_one("源IP威胁情报", src)
        dst_html = fmt_one("目的IP威胁情报", dst)
        body = src_html + dst_html

        html = summary_html + body
        return html or "<p>无威胁情报数据</p>"

    def _show_ip_list_alerts(self, alerts: dict):
        """IP命中白/黑名单提醒"""
        if not alerts:
            return
        msg_parts = []
        if 'src_ip_status' in alerts:
            status, ip = alerts['src_ip_status']
            list_name = '白名单' if status == 'whitelist' else '黑名单'
            msg_parts.append(f"源IP {ip} 已在{list_name}中")
        if 'dst_ip_status' in alerts:
            status, ip = alerts['dst_ip_status']
            list_name = '白名单' if status == 'whitelist' else '黑名单'
            msg_parts.append(f"目的IP {ip} 已在{list_name}中")
        if msg_parts:
            QMessageBox.information(self, "IP列表提醒", "\n".join(msg_parts))

    # ---------- 历史记录 ----------
    def _load_history_config(self):
        """从配置加载历史记录设置"""
        hist_cfg = self.cfg.get('history', {}) or {}
        file_path = hist_cfg.get('file') or "output/log_history.json"
        self.history_file = Path(file_path)
        try:
            self.history_limit = int(hist_cfg.get('max_entries', 200)) or 200
        except Exception:
            self.history_limit = 200

    def _load_history(self):
        """加载历史记录列表"""
        try:
            if self.history_file.exists():
                data = pyjson.loads(self.history_file.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    return data[: self.history_limit]
        except Exception:
            pass
        return []

    def _save_history(self):
        """保存历史记录到文件"""
        try:
            self.history_file.parent.mkdir(parents=True, exist_ok=True)
            self.history = self.history[: self.history_limit]
            self.history_file.write_text(pyjson.dumps(self.history, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _save_history_entry(self, raw_text: str, result: dict):
        """在每次解析成功后记录历史"""
        hist_cfg = self.cfg.get('history', {}) or {}
        if not hist_cfg.get('enabled', True):
            return
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        parsed = result.get('parsed_data') or {}
        entry = {
            "detected_at": ts,
            "raw_text": raw_text,
            "parsed_data": parsed,
            "ti_result": result.get('ti_result'),
            "ai_result": result.get('ai_result'),
        }
        # 最新在前
        self.history.insert(0, entry)
        self._save_history()
        self._refresh_history_list()

    def _refresh_history_list(self):
        """刷新历史列表显示"""
        if not hasattr(self, "history_list"):
            return
        self.history_list.clear()
        for entry in self.history:
            ts = entry.get("detected_at", "")
            pd = entry.get("parsed_data") or {}
            src = pd.get("src_ip") or ""
            dst = pd.get("dst_ip") or ""
            ev = pd.get("event_type") or pd.get("event_name") or ""
            text = f"{ts}  {src}->{dst}  {ev}".strip()
            item = QListWidgetItem(text)
            item.setData(Qt.UserRole, entry)
            self.history_list.addItem(item)

    def on_history_restore(self, item: QListWidgetItem):
        """双击历史记录恢复当时场景"""
        entry = item.data(Qt.UserRole) or {}
        self.restore_from_entry(entry)

    def restore_from_entry(self, entry: dict):
        """外部恢复入口：用于 HistoryPage/主窗口调用"""
        raw = entry.get("raw_text") or ""
        parsed = entry.get("parsed_data") or {}
        ti_result = entry.get("ti_result")
        ai_result = entry.get("ai_result")

        self.input_text.setPlainText(raw)
        self._update_outputs(parsed)

        if ti_result:
            self.ti_result_text.setHtml(self._render_ti_html(ti_result))
        else:
            self.ti_result_text.clear()

        if ai_result:
            self.ai_result_text.setText(render_ai_result(ai_result))
        else:
            self.ai_result_text.clear()
