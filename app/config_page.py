"""配置管理页面"""
from datetime import datetime
import json

from .ui_common import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QPushButton,
    QGroupBox, QFormLayout, QLineEdit, QCheckBox, QTextEdit,
    QLabel, QMessageBox, QInputDialog, QSpinBox, QThread, QComboBox
)
from core.config import load_config, save_config
from .workers import TIWorker

class ConfigPage(QWidget):
    """配置管理页面"""
    def __init__(self, cfg, on_config_changed=None):
        super().__init__()
        self.cfg = cfg
        self.on_config_changed = on_config_changed
        self.init_ui()
        self.load_config()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # 配置标签页
        self.tab_widget = QTabWidget()
        
        # 提供商配置
        providers_widget = self.create_providers_widget()
        self.tab_widget.addTab(providers_widget, "威胁情报")
        
        # AI配置
        ai_widget = self.create_ai_widget()
        self.tab_widget.addTab(ai_widget, "AI配置")
        
        # Webhook配置
        webhook_widget = self.create_webhook_widget()
        self.tab_widget.addTab(webhook_widget, "消息推送")
        
        # 解析配置
        fields_widget = self.create_fields_widget()
        self.tab_widget.addTab(fields_widget, "解析配置")
        
        layout.addWidget(self.tab_widget)
        
        # 按钮
        button_layout = QHBoxLayout()
        
        self.reload_btn = QPushButton("重新加载")
        self.reload_btn.clicked.connect(self.on_reload)
        button_layout.addWidget(self.reload_btn)
        
        self.save_btn = QPushButton("保存配置")
        self.save_btn.setStyleSheet("background-color: #7bdcb5; color: white;")
        self.save_btn.clicked.connect(self.on_save)
        button_layout.addWidget(self.save_btn)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def create_providers_widget(self) -> QWidget:
        """创建威胁情报配置页（仅微步 ThreatBook）"""
        widget = QWidget()
        layout = QVBoxLayout()

        threatbook_group = QGroupBox("微步（ThreatBook）")
        threatbook_layout = QFormLayout()

        # 请求模式：使用类似主题切换的按钮，在禁用/API/HTTP 间循环切换
        self.threatbook_request_mode = QPushButton()
        # 可选模式列表: (显示文本, 配置值)
        self._request_modes = [
            ("禁用", "off"),
            ("API 请求", "api"),
            ("HTTP 请求", "http"),
        ]
        self._current_request_mode_index = 0
        self._update_request_mode_btn()
        self.threatbook_request_mode.clicked.connect(self._on_toggle_request_mode)

        self.threatbook_key = QLineEdit()
        self.threatbook_key.setEchoMode(QLineEdit.Password)
        # HTTP Cookie（从浏览器复制，用于 HTTP 请求模式）
        self.threatbook_http_cookie = QTextEdit()
        self.threatbook_http_cookie.setFixedHeight(80)
        self.threatbook_http_cookie.setPlaceholderText("仅在 HTTP 请求模式下使用：在浏览器登录微步后，复制完整 Cookie 粘贴到此处。")
        self.threatbook_mode = QComboBox()
        self.threatbook_mode.addItem("查询源+目的IP", "both")
        self.threatbook_mode.addItem("仅查询源IP", "src")
        self.threatbook_mode.addItem("仅查询目的IP", "dst")

        threatbook_layout.addRow("请求模式:", self.threatbook_request_mode)
        threatbook_layout.addRow("API Key:", self.threatbook_key)
        threatbook_layout.addRow("HTTP Cookie:", self.threatbook_http_cookie)
        threatbook_layout.addRow("查询模式:", self.threatbook_mode)

        threatbook_group.setLayout(threatbook_layout)
        layout.addWidget(threatbook_group)

        # 测试按钮
        test_layout = QHBoxLayout()
        self.test_threatbook_btn = QPushButton("测试查询")
        test_layout.addWidget(self.test_threatbook_btn)
        test_layout.addStretch()
        layout.addLayout(test_layout)

        self.test_threatbook_btn.clicked.connect(self.on_test_threatbook)

        # 测试结果面板（历史记录）
        self.test_result_area = QTextEdit()
        self.test_result_area.setReadOnly(True)
        self.test_result_area.setPlaceholderText("测试结果将显示在此处，最近测试会追加在顶部。")
        self.test_result_area.setFixedHeight(180)
        layout.addWidget(self.test_result_area)

        # 清空记录按钮
        result_btn_layout = QHBoxLayout()
        self.clear_test_history_btn = QPushButton("清空记录")
        self.clear_test_history_btn.clicked.connect(self.on_clear_test_history)
        result_btn_layout.addStretch()
        result_btn_layout.addWidget(self.clear_test_history_btn)
        layout.addLayout(result_btn_layout)

        layout.addStretch()
        widget.setLayout(layout)
        return widget
    
    def create_ai_widget(self) -> QWidget:
        """创建AI配置页"""
        widget = QWidget()
        layout = QFormLayout()

        self.ai_model = QLineEdit()
        self.ai_model.setMinimumWidth(260)
        self.ai_key = QLineEdit()
        self.ai_key.setEchoMode(QLineEdit.Password)
        self.ai_key.setMinimumWidth(260)
        self.ai_base_url = QLineEdit()
        self.ai_base_url.setMinimumWidth(260)
        self.ai_objective = QTextEdit()
        self.ai_objective.setFixedHeight(80)
        self.ai_objective.setPlaceholderText("例如：对该告警进行专业安全研判，给出威胁等级、是否需要封禁以及风险分析。")

        self.ai_audience = QComboBox()
        self.ai_audience.addItem("面向客户", "customer")
        self.ai_audience.addItem("面向专业安全人员", "expert")
        self.ai_audience.addItem("面向安全初学者", "beginner")

        self.ai_response_mode = QComboBox()
        self.ai_response_mode.addItem("结构化：威胁等级/是否封禁/原因/风险分析", "structured")
        self.ai_response_mode.addItem("简要模式：一行结论 + 要点", "brief")
        self.ai_response_mode.addItem("报告模式：分段Markdown报告", "report")

        layout.addRow("模型:", self.ai_model)
        layout.addRow("API Key:", self.ai_key)
        layout.addRow("API地址:", self.ai_base_url)
        layout.addRow("分析目标（Objective）:", self.ai_objective)
        layout.addRow("受众（Audience）:", self.ai_audience)
        layout.addRow("输出模式（Response）:", self.ai_response_mode)
        
        widget.setLayout(layout)
        return widget
    
    def create_webhook_widget(self) -> QWidget:
        """创建Webhook配置页"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # 钉钉
        dingtalk_group = QGroupBox("钉钉")
        dingtalk_layout = QFormLayout()
        
        self.dingtalk_enabled = QCheckBox()
        self.dingtalk_url = QLineEdit()
        self.dingtalk_url.setMinimumWidth(260)
        self.dingtalk_secret = QLineEdit()
        self.dingtalk_secret.setEchoMode(QLineEdit.Password)
        self.dingtalk_secret.setMinimumWidth(260)
        
        dingtalk_layout.addRow("启用:", self.dingtalk_enabled)
        dingtalk_layout.addRow("Webhook URL:", self.dingtalk_url)
        dingtalk_layout.addRow("Secret:", self.dingtalk_secret)
        
        dingtalk_group.setLayout(dingtalk_layout)
        layout.addWidget(dingtalk_group)
        
        # 企业微信
        wecom_group = QGroupBox("企业微信")
        wecom_layout = QFormLayout()
        
        self.wecom_enabled = QCheckBox()
        self.wecom_url = QLineEdit()
        self.wecom_url.setMinimumWidth(260)
        
        wecom_layout.addRow("启用:", self.wecom_enabled)
        wecom_layout.addRow("Webhook URL:", self.wecom_url)
        
        wecom_group.setLayout(wecom_layout)
        layout.addWidget(wecom_group)
        
        # 飞书
        feishu_group = QGroupBox("飞书")
        feishu_layout = QFormLayout()
        
        self.feishu_enabled = QCheckBox()
        self.feishu_url = QLineEdit()
        self.feishu_url.setMinimumWidth(260)
        
        feishu_layout.addRow("启用:", self.feishu_enabled)
        feishu_layout.addRow("Webhook URL:", self.feishu_url)
        
        feishu_group.setLayout(feishu_layout)
        layout.addWidget(feishu_group)
        
        layout.addStretch()
        widget.setLayout(layout)
        return widget
    
    def create_fields_widget(self) -> QWidget:
        """创建字段配置页"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        layout.addWidget(QLabel("字段顺序（每行一个）:"))
        self.fields_order = QTextEdit()
        layout.addWidget(self.fields_order)
        
        history_group = QGroupBox("日志记录设置")
        history_layout = QFormLayout()
        self.history_enabled = QCheckBox()
        self.history_max_entries = QSpinBox()
        self.history_max_entries.setRange(10, 10000)
        self.history_max_entries.setSingleStep(10)
        self.history_max_entries.setValue(200)
        history_layout.addRow("启用日志记录:", self.history_enabled)
        history_layout.addRow("最大保存条数:", self.history_max_entries)
        history_group.setLayout(history_layout)
        layout.addWidget(history_group)
        
        widget.setLayout(layout)
        return widget

    def load_config(self):
        """加载配置到UI"""
        providers_cfg = self.cfg.get('providers', {})
        
        # 加载微步 ThreatBook 配置
        threatbook = providers_cfg.get('threatbook', {}) or {}
        # 启用/请求模式
        request_mode = threatbook.get('request_mode')
        enabled = threatbook.get('enabled', False)
        if not request_mode:
            request_mode = 'api' if enabled else 'off'
        self._set_threatbook_request_mode(request_mode)
        self.threatbook_key.setText(threatbook.get('api_key', ''))
        self.threatbook_http_cookie.setPlainText(threatbook.get('http_cookie', ''))
        mode = threatbook.get('mode', 'both')
        for i in range(self.threatbook_mode.count()):
            if self.threatbook_mode.itemData(i) == mode:
                self.threatbook_mode.setCurrentIndex(i)
                break
        
        # 加载AI配置
        ai_cfg = self.cfg.get('ai', {})
        self.ai_model.setText(ai_cfg.get('model', ''))
        self.ai_key.setText(ai_cfg.get('api_key', ''))
        self.ai_base_url.setText(ai_cfg.get('base_url', ''))
        self.ai_objective.setText(ai_cfg.get('objective', ''))
        # 受众
        aud = ai_cfg.get('audience', 'expert')
        for i in range(self.ai_audience.count()):
            if self.ai_audience.itemData(i) == aud:
                self.ai_audience.setCurrentIndex(i)
                break
        # 输出模式
        mode = ai_cfg.get('response_mode', 'structured')
        for i in range(self.ai_response_mode.count()):
            if self.ai_response_mode.itemData(i) == mode:
                self.ai_response_mode.setCurrentIndex(i)
                break
        
        # 加载Webhook配置
        webhook_cfg = self.cfg.get('webhook', {}) or {}

        dingtalk = webhook_cfg.get('dingtalk', {})
        self.dingtalk_enabled.setChecked(dingtalk.get('enabled', False))
        self.dingtalk_url.setText(dingtalk.get('url', ''))
        self.dingtalk_secret.setText(dingtalk.get('secret', ''))
        
        wecom = webhook_cfg.get('wecom', {})
        self.wecom_enabled.setChecked(wecom.get('enabled', False))
        self.wecom_url.setText(wecom.get('url', ''))
        
        feishu = webhook_cfg.get('feishu', {})
        self.feishu_enabled.setChecked(feishu.get('enabled', False))
        self.feishu_url.setText(feishu.get('url', ''))
        
        # 加载字段配置
        fields_cfg = self.cfg.get('fields', {})
        fields_order = fields_cfg.get('order', [])
        self.fields_order.setText('\n'.join(fields_order))
        # 日志记录配置
        hist_cfg = self.cfg.get('history', {}) or {}
        self.history_enabled.setChecked(hist_cfg.get('enabled', True))
        try:
            self.history_max_entries.setValue(int(hist_cfg.get('max_entries', 200)))
        except Exception:
            self.history_max_entries.setValue(200)

    def on_reload(self):
        """重新加载"""
        self.cfg = load_config()
        self.load_config()
        QMessageBox.information(self, "成功", "已重新加载配置")
    
    def on_save(self):
        """保存配置"""
        try:
            # 更新微步 ThreatBook 配置
            self.cfg['providers'].setdefault('threatbook', {})
            tb_cfg = self.cfg['providers']['threatbook']
            req_mode = self._get_threatbook_request_mode()
            tb_cfg['request_mode'] = req_mode
            tb_cfg['enabled'] = req_mode != 'off'
            tb_cfg['api_key'] = self.threatbook_key.text()
            tb_cfg['mode'] = self.threatbook_mode.currentData()
            tb_cfg['http_cookie'] = self.threatbook_http_cookie.toPlainText().strip()
            
            # 更新AI配置（启用状态仅由主界面顶部按钮控制，此处只保存参数）
            self.cfg['ai']['model'] = self.ai_model.text()
            self.cfg['ai']['api_key'] = self.ai_key.text()
            self.cfg['ai']['base_url'] = self.ai_base_url.text()
            self.cfg['ai']['objective'] = self.ai_objective.toPlainText().strip()
            self.cfg['ai']['audience'] = self.ai_audience.currentData()
            self.cfg['ai']['response_mode'] = self.ai_response_mode.currentData()
            
            # 更新Webhook配置
            self.cfg.setdefault('webhook', {})
            self.cfg['webhook'].setdefault('dingtalk', {})
            self.cfg['webhook'].setdefault('wecom', {})
            self.cfg['webhook'].setdefault('feishu', {})

            self.cfg['webhook']['dingtalk']['enabled'] = self.dingtalk_enabled.isChecked()
            self.cfg['webhook']['dingtalk']['url'] = self.dingtalk_url.text()
            self.cfg['webhook']['dingtalk']['secret'] = self.dingtalk_secret.text()
            
            self.cfg['webhook']['wecom']['enabled'] = self.wecom_enabled.isChecked()
            self.cfg['webhook']['wecom']['url'] = self.wecom_url.text()
            
            self.cfg['webhook']['feishu']['enabled'] = self.feishu_enabled.isChecked()
            self.cfg['webhook']['feishu']['url'] = self.feishu_url.text()
            
            # 更新字段配置
            fields_order = [f.strip() for f in self.fields_order.toPlainText().split('\n') if f.strip()]
            self.cfg['fields']['order'] = fields_order
            # 更新日志记录配置
            hist_cfg = self.cfg.get('history') or {}
            hist_cfg['enabled'] = self.history_enabled.isChecked()
            hist_cfg['max_entries'] = int(self.history_max_entries.value())
            hist_cfg.setdefault('file', 'output/log_history.json')
            self.cfg['history'] = hist_cfg
            # 保存到文件
            save_config(self.cfg)
            if self.on_config_changed:
                try:
                    self.on_config_changed()
                except Exception:
                    pass
            
            QMessageBox.information(self, "成功", "配置已保存")
        
        except Exception as e:
            QMessageBox.critical(self, "错误", f"保存失败: {str(e)}")

    def on_clear_test_history(self):
        """清空测试结果面板"""
        self.test_result_area.clear()


    def _update_request_mode_btn(self):
        """根据当前索引更新请求模式按钮文本"""
        label, _ = self._request_modes[self._current_request_mode_index]
        self.threatbook_request_mode.setText(label)

    def _get_threatbook_request_mode(self) -> str:
        """获取当前请求模式配置值（off/api/http）"""
        return self._request_modes[self._current_request_mode_index][1]

    def _set_threatbook_request_mode(self, mode: str):
        """根据配置值设置当前请求模式，并刷新按钮显示"""
        for i, (_, value) in enumerate(self._request_modes):
            if value == mode:
                self._current_request_mode_index = i
                break
        self._update_request_mode_btn()
        self._on_threatbook_request_mode_changed()

    def _on_toggle_request_mode(self):
        """点击按钮时在模式列表中循环切换"""
        self._current_request_mode_index = (self._current_request_mode_index + 1) % len(self._request_modes)
        self._update_request_mode_btn()
        self._on_threatbook_request_mode_changed()

    def _on_threatbook_request_mode_changed(self):
        """根据请求模式切换 API Key / Cookie 输入框的可用状态"""
        mode = self._get_threatbook_request_mode()
        if mode == 'api':
            self.threatbook_key.setEnabled(True)
            self.threatbook_http_cookie.setEnabled(False)
        elif mode == 'http':
            self.threatbook_key.setEnabled(False)
            self.threatbook_http_cookie.setEnabled(True)
        else:  # off
            self.threatbook_key.setEnabled(False)
            self.threatbook_http_cookie.setEnabled(False)

    def _start_ti_test(self, provider: str, api_key: str):
        """启动微步 TI 测试：弹窗输入IP，后台查询，结果展示"""
        # 弹出输入IP对话框
        ip, ok = QInputDialog.getText(self, f"测试 {provider}", "输入要测试的IP地址:")
        if not ok or not ip.strip():
            return
        ip = ip.strip()
        # 记录本次测试的 IP，便于在 HTTP 请求返回空结果时给出可点击链接
        self._last_ti_test_ip = ip

        # 禁用对应按钮并显示状态
        self.test_threatbook_btn.setEnabled(False)
        self.test_threatbook_btn.setText('测试中...')

        # 在当前内存配置中同步 ThreatBook 相关设置，确保测试线程使用的是界面上的最新值
        self.cfg.setdefault('providers', {})
        self.cfg['providers'].setdefault('threatbook', {})
        tb_cfg = self.cfg['providers']['threatbook']
        tb_cfg['request_mode'] = self._get_threatbook_request_mode()
        tb_cfg['enabled'] = tb_cfg['request_mode'] != 'off'
        tb_cfg['api_key'] = self.threatbook_key.text().strip()
        tb_cfg['mode'] = self.threatbook_mode.currentData()
        tb_cfg['http_cookie'] = self.threatbook_http_cookie.toPlainText().strip()

        # 创建并启动线程
        self.ti_worker = TIWorker(ip, self.cfg, provider, api_key)
        self.ti_thread = QThread()
        self.ti_worker.moveToThread(self.ti_thread)
        self.ti_worker.done.connect(self._on_ti_done)
        self.ti_worker.error.connect(self._on_ti_error)
        self.ti_thread.started.connect(self.ti_worker.run)
        self.ti_thread.start()

    def on_test_threatbook(self):
        """测试 微步(ThreatBook) 配置"""
        mode = self._get_threatbook_request_mode()
        if mode == 'api':
            api_key = self.threatbook_key.text().strip()
            if not api_key:
                QMessageBox.warning(self, "警告", "请先填写 微步 ThreatBook 的 API Key")
                return
            self._start_ti_test('threatbook', api_key)
        elif mode == 'http':
            cookie = self.threatbook_http_cookie.toPlainText().strip()
            if not cookie:
                QMessageBox.warning(self, "警告", "请先在浏览器登录微步后，复制完整 Cookie 粘贴到 HTTP Cookie 字段")
                return
            # HTTP 模式下，api_key 不参与请求，传空字符串占位即可
            self._start_ti_test('threatbook', "")
        else:
            QMessageBox.warning(self, "警告", "请先选择请求模式（API 或 HTTP）")

    def _on_ti_done(self, payload: dict):
        """TI测试完成回调，显示简要信息并恢复按钮"""
        # 终止线程
        try:
            self.ti_thread.quit()
            self.ti_thread.wait()
        except Exception:
            pass
        # 恢复按钮和文本
        self.test_threatbook_btn.setEnabled(True)
        self.test_threatbook_btn.setText('测试查询')

        provider = payload.get('provider')
        provider_name = '微步(ThreatBook)'
        result = payload.get('result')

        # 将结果追加到结果面板，包含时间戳与摘要
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        header = f"[{ts}] {provider_name} 测试结果:\n"

        if not result:
            entry = header + "未返回威胁情报（可能无可疑信息或请求失败）\n\n"
            # 追加到顶部
            current = self.test_result_area.toPlainText()
            self.test_result_area.setPlainText(entry + current)
            return

        try:
            summary = {
                'provider': provider,
                'is_malicious': result.get('is_malicious'),
                'labels': result.get('labels') or result.get('malicious_label') or result.get('categories') or [],
            }
        except Exception:
            summary = {'provider': provider, 'raw': result}

        pretty = json.dumps(summary, ensure_ascii=False, indent=2)
        entry = header + pretty + "\n\n"
        current = self.test_result_area.toPlainText()
        self.test_result_area.setPlainText(entry + current)

        # 若在 HTTP 请求模式下仅得到“无情报”的默认结果，则提示用户手动打开网页以防触发机器人校验
        try:
            mode = self._get_threatbook_request_mode()
        except Exception:
            mode = None
        if (
            mode == 'http'
            and provider == 'threatbook'
            and summary.get('is_malicious') is False
            and not summary.get('labels')
        ):
            ip = getattr(self, "_last_ti_test_ip", "").strip()
            if ip:
                url = f"https://x.threatbook.com/v5/ip/{ip}"
                dlg = QDialog(self)
                dlg.setWindowTitle("HTTP 请求提示")
                vbox = QVBoxLayout(dlg)
                text = (
                    "HTTP 请求返回为空结果，可能触发了机器人校验。\n"
                    "请在浏览器中打开以下链接进行人工查看：\n"
                    f'<a href="{url}">{url}</a>'
                )
                label = QLabel(text)
                label.setTextFormat(Qt.RichText)
                label.setOpenExternalLinks(True)
                label.setWordWrap(True)
                vbox.addWidget(label)
                btn = QPushButton("关闭")
                btn.clicked.connect(dlg.accept)
                vbox.addWidget(btn)
                vbox.setAlignment(btn, Qt.AlignRight)
                dlg.exec()

    def _on_ti_error(self, error: str):
        """TI测试出错回调，显示错误并恢复按钮"""
        try:
            self.ti_thread.quit()
            self.ti_thread.wait()
        except Exception:
            pass

        self.test_threatbook_btn.setEnabled(True)
        self.test_threatbook_btn.setText('测试查询')

        QMessageBox.critical(self, "错误", f"TI测试异常: {error}")
