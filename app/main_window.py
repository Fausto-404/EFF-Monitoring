"""主窗口模块"""
from .ui_common import (
    QApplication, QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QLabel, QPushButton, QStackedWidget, QSize, Qt
)
from core.config import ensure_config, load_config
from .log_page import LogPage
from .history_page import HistoryPage
from .ip_page import IPPage
from .rule_page import RulePage
from .config_page import ConfigPage

class MainWindow(QMainWindow):
    """主窗口"""
    def __init__(self):
        super().__init__()
        
        # 加载配置
        self.cfg = ensure_config()
        
        self.setWindowTitle("EFF-Monitoring")
        self.setGeometry(100, 100, 1200, 800)
        
        # 主布局
        main_widget = QWidget()
        main_layout = QHBoxLayout()
        
        # 左侧导航（对称大按钮）
        nav_layout = QVBoxLayout()
        nav_layout.setContentsMargins(8, 8, 8, 8)
        nav_layout.setSpacing(12)

        title = QLabel("功能")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-weight:600; font-size:14px;")
        nav_layout.addWidget(title)

        # 顶部控制按钮：主题切换 + 功能开关
        self.theme = "light"
        self.theme_btn = QPushButton("深色模式")
        self.theme_btn.setObjectName("themeToggle")
        self.theme_btn.setCheckable(True)
        self.theme_btn.setCursor(Qt.PointingHandCursor)
        self.theme_btn.setFixedSize(80, 24)
        self.theme_btn.clicked.connect(self.on_toggle_theme)
        # 运行时总开关：TI / AI / Webhook 消息推送
        self.ti_toggle_btn = QPushButton()
        self.ai_toggle_btn = QPushButton()
        self.webhook_toggle_btn = QPushButton()
        # 保证顶部功能开关按钮有足够宽度，避免文字被截断
        for btn in (self.ti_toggle_btn, self.ai_toggle_btn, self.webhook_toggle_btn):
            btn.setFixedHeight(24)
            btn.setMinimumWidth(68)
        # 绑定顶部功能开关点击事件
        self.ti_toggle_btn.clicked.connect(self.on_toggle_ti_enabled)
        self.ai_toggle_btn.clicked.connect(self.on_toggle_ai_enabled)
        self.webhook_toggle_btn.clicked.connect(self.on_toggle_webhook_enabled)

        self.btn_log = QPushButton("日志处理")
        self.btn_history = QPushButton("解析历史")
        self.btn_ip = QPushButton("IP管理")
        self.btn_rule = QPushButton("规则管理")
        self.btn_cfg = QPushButton("配置管理")

        for btn in (self.btn_log, self.btn_history, self.btn_ip, self.btn_rule, self.btn_cfg):
            btn.setMinimumSize(QSize(120, 48))
            btn.setCursor(Qt.PointingHandCursor)
            btn.setCheckable(True)
            btn.setStyleSheet(
                "QPushButton{ background-color:#7bdcb5; color:#ffffff; border-radius:8px; font-size:13px;}"
                "QPushButton:checked{ background-color:#43c28d;}"
                "QPushButton:hover{ background-color:#6fd6b8;}"
            )
            nav_layout.addWidget(btn)

        self.btn_log.clicked.connect(lambda: self.on_nav_button(0))
        self.btn_history.clicked.connect(lambda: self.on_nav_button(1))
        self.btn_ip.clicked.connect(lambda: self.on_nav_button(2))
        self.btn_rule.clicked.connect(lambda: self.on_nav_button(3))
        self.btn_cfg.clicked.connect(lambda: self.on_nav_button(4))

        nav_layout.addStretch()

        left_widget = QWidget()
        left_widget.setLayout(nav_layout)
        left_widget.setMaximumWidth(160)

        main_layout.addWidget(left_widget)
        
        # 右侧内容
        self.content_stack = QStackedWidget()
        
        self.log_page = LogPage(self.cfg)
        self.history_page = HistoryPage(self.cfg, on_restore=self.on_history_restore_from_page)
        self.ip_page = IPPage(self.cfg)
        self.rule_page = RulePage(self.cfg, on_config_changed=self.on_config_changed)
        self.config_page = ConfigPage(self.cfg, on_config_changed=self.on_config_changed)
        
        self.content_stack.addWidget(self.log_page)      # 0
        self.content_stack.addWidget(self.history_page)  # 1
        self.content_stack.addWidget(self.ip_page)       # 2
        self.content_stack.addWidget(self.rule_page)     # 3
        self.content_stack.addWidget(self.config_page)   # 4

        # 右侧带标题栏的布局
        right_widget = QWidget()
        right_layout = QVBoxLayout()
        right_layout.setContentsMargins(0, 8, 8, 8)
        right_layout.setSpacing(8)

        header_layout = QHBoxLayout()
        header_label = QLabel("安全监测研判提效工具")
        header_label.setStyleSheet("font-weight:600; font-size:15px;")
        header_layout.addWidget(header_label)
        header_layout.addStretch()
        # 顶部功能开关按钮：TI / AI / Webhook / 主题
        header_layout.addWidget(self.ti_toggle_btn)
        header_layout.addWidget(self.ai_toggle_btn)
        header_layout.addWidget(self.webhook_toggle_btn)
        header_layout.addWidget(self.theme_btn)

        right_layout.addLayout(header_layout)
        right_layout.addWidget(self.content_stack, 1)

        right_widget.setLayout(right_layout)
        main_layout.addWidget(right_widget, 1)
        
        # 设置主布局
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
        
        # 设置默认样式（浅色）
        self._apply_theme("light")
        # 初始化顶部功能开关（根据配置）
        self._init_feature_toggles()
        
        # 默认显示第一个页面
        self.on_nav_button(0)
    
    def on_nav_changed(self, row):
        """导航改变"""
        self.content_stack.setCurrentIndex(row)

    def on_nav_button(self, index: int):
        """按钮式导航切换，更新按钮选中状态"""
        # 更新堆栈页面
        self.content_stack.setCurrentIndex(index)
        # 更新按钮状态
        self.btn_log.setChecked(index == 0)
        self.btn_history.setChecked(index == 1)
        self.btn_ip.setChecked(index == 2)
        self.btn_rule.setChecked(index == 3)
        self.btn_cfg.setChecked(index == 4)

    def on_history_restore_from_page(self, entry: dict):
        """从 HistoryPage 跳转并还原到日志处理界面"""
        self.on_nav_button(0)
        try:
            self.log_page.restore_from_entry(entry)
        except Exception:
            pass

    def on_config_changed(self):
        """配置变更时同步到各页面"""
        try:
            self.cfg = load_config()
        except Exception:
            pass
        self.log_page.reload_config(self.cfg)
        self.history_page.reload_config(self.cfg)
        self.ip_page.cfg = self.cfg
        self.rule_page.cfg = self.cfg
        self.config_page.cfg = self.cfg
        try:
            self.rule_page.load_rules()
            self.config_page.load_config()
        except Exception:
            pass
        # 配置变更后重新初始化顶部功能开关
        try:
            self._init_feature_toggles()
        except Exception:
            pass

    # ---- 主题切换 ----
    def _apply_theme(self, theme: str):
        """根据 theme 应用浅色/深色样式"""
        self.theme = theme
        # 通知日志处理页以便调整TI卡片配色
        try:
            self.log_page.set_theme(theme)
        except Exception:
            pass
        if theme == "dark":
            qss = """
                QMainWindow { background-color: #111827; }
                QWidget { font-family: "Helvetica Neue", Arial; color: #e5e7eb; }
                QGroupBox { background: #1f2937; border: 1px solid #374151; border-radius: 10px; margin-top: 8px; padding: 10px; }
                QTabWidget::pane { border: 1px solid #374151; border-radius: 8px; background:#111827; }
                QTabBar::tab {
                    background: #111827;
                    color: #9ca3af;
                    padding: 6px 12px;
                    border-top-left-radius: 6px;
                    border-top-right-radius: 6px;
                }
                QTabBar::tab:selected {
                    background: #1f2937;
                    color: #e5e7eb;
                }
                QTabBar::tab:hover {
                    background: #111827;
                    color: #f9fafb;
                }
                QLabel { color: #e5e7eb; font-weight: 500; }
                QLineEdit, QTextEdit, QPlainTextEdit, QComboBox {
                    background: #111827;
                    border: 1px solid #4b5563;
                    border-radius: 8px;
                    padding: 8px;
                    color: #e5e7eb;
                }
                QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus {
                    border: 1px solid #10b981;
                }
                QComboBox QAbstractItemView {
                    background-color: #111827;
                    border: 1px solid #4b5563;
                    color: #e5e7eb;
                    selection-background-color: #1d4ed8;
                    selection-color: #f9fafb;
                }
                QComboBox::drop-down {
                    border: none;
                    background: transparent;
                }
                QTableView, QTableWidget {
                    background-color: #111827;
                    alternate-background-color: #020617;
                    gridline-color: #374151;
                    color: #e5e7eb;
                    selection-background-color: #1d4ed8;
                    selection-color: #f9fafb;
                }
                QHeaderView::section {
                    background-color: #1f2937;
                    color: #e5e7eb;
                    border: 1px solid #4b5563;
                    padding: 4px;
                }
                QMessageBox, QDialog {
                    background-color: #1f2937;
                    color: #e5e7eb;
                }
                QMessageBox QLabel, QDialog QLabel {
                    color: #e5e7eb;
                }
                QToolTip {
                    background-color: #111827;
                    color: #e5e7eb;
                    border: 1px solid #4b5563;
                    padding: 4px 8px;
                    border-radius: 4px;
                }
                QPushButton {
                    padding: 10px 14px;
                    border-radius: 10px;
                    background-color: #10b981;
                    color: #0b1120;
                    font-weight:600;
                }
                QPushButton:hover { background-color: #059669; }
                QPushButton:checked { background-color: #065f46; color:#e5e7eb; }
                QPushButton#themeToggle {
                    font-size: 11px;
                    padding: 2px 8px;
                    border-radius: 6px;
                    background-color: #111827;
                    color: #e5e7eb;
                    border: 1px solid #4b5563;
                }
                QPushButton#themeToggle:hover {
                    background-color: #1f2937;
                }
            """
            self.theme_btn.setText("浅色模式")
            self.theme_btn.setChecked(True)
        else:
            qss = """
                QMainWindow { background-color: #f7f8fb; }
                QWidget { font-family: "Helvetica Neue", Arial; color: #1f2d3d; }
                QGroupBox { background: #ffffff; border: 1px solid #e4e8f0; border-radius: 10px; margin-top: 8px; padding: 10px; }
                QTabWidget::pane { border: 1px solid #e4e8f0; border-radius: 8px; background:#ffffff; }
                QTabBar::tab {
                    background: #e5e7eb;
                    color: #4b5563;
                    padding: 6px 12px;
                    border-top-left-radius: 6px;
                    border-top-right-radius: 6px;
                }
                QTabBar::tab:selected {
                    background: #ffffff;
                    color: #111827;
                }
                QTabBar::tab:hover {
                    background: #f3f4f6;
                }
                QLabel { color: #1f2d3d; font-weight: 500; }
                QLineEdit, QTextEdit, QPlainTextEdit, QComboBox {
                    background: #ffffff;
                    border: 1px solid #d5d9e0;
                    border-radius: 8px;
                    padding: 8px;
                }
                QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus {
                    border: 1px solid #5ec3a2;
                }
                QComboBox QAbstractItemView {
                    background-color: #ffffff;
                    border: 1px solid #d5d9e0;
                    color: #111827;
                    selection-background-color: #e0f2fe;
                    selection-color: #0f172a;
                }
                QComboBox::drop-down {
                    border: none;
                    background: transparent;
                }
                QTableView, QTableWidget {
                    background-color: #ffffff;
                    alternate-background-color: #f3f4f6;
                    gridline-color: #e5e7eb;
                    color: #1f2933;
                    selection-background-color: #e0f2fe;
                    selection-color: #0f172a;
                }
                QHeaderView::section {
                    background-color: #f3f4f6;
                    color: #4b5563;
                    border: 1px solid #e5e7eb;
                    padding: 4px;
                }
                QMessageBox, QDialog {
                    background-color: #ffffff;
                    color: #1f2d3d;
                }
                QMessageBox QLabel, QDialog QLabel {
                    color: #1f2d3d;
                }
                QToolTip {
                    background-color: #f9fafb;
                    color: #111827;
                    border: 1px solid #e5e7eb;
                    padding: 4px 8px;
                    border-radius: 4px;
                }
                QPushButton {
                    padding: 10px 14px;
                    border-radius: 10px;
                    background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #6fe3b2, stop:1 #43c28d);
                    color: #ffffff;
                    font-weight:600;
                }
                QPushButton:hover { background-color: #6fd6b8; }
                QPushButton:checked { background-color: #43c28d; }
                QPushButton#themeToggle {
                    font-size: 11px;
                    padding: 2px 8px;
                    border-radius: 6px;
                    background-color: #e5e7eb;
                    color: #111827;
                    border: 1px solid #cbd5e1;
                }
                QPushButton#themeToggle:hover {
                    background-color: #d1d5db;
                }
            """
            self.theme_btn.setText("深色模式")
            self.theme_btn.setChecked(False)

        self.setStyleSheet(qss)

    def on_toggle_theme(self):
        """主题切换按钮回调"""
        new_theme = "dark" if self.theme != "dark" else "light"
        self._apply_theme(new_theme)

    # ---- 顶部功能总开关（TI / AI / Webhook） ----
    def _apply_toggle_style(self, btn: QPushButton, enabled: bool):
        """根据启用状态设置按钮颜色（绿色=启用，红色=关闭）"""
        if enabled:
            style = (
                "QPushButton {"
                "background-color: #16a34a;"
                "color: #f9fafb;"
                "border-radius: 8px;"
                "padding: 2px 10px;"
                "font-size: 11px;"
                "}"
                "QPushButton:hover { background-color: #15803d; }"
            )
        else:
            style = (
                "QPushButton {"
                "background-color: #b91c1c;"
                "color: #f9fafb;"
                "border-radius: 8px;"
                "padding: 2px 10px;"
                "font-size: 11px;"
                "}"
                "QPushButton:hover { background-color: #991b1b; }"
            )
        btn.setStyleSheet(style)

    def _init_feature_toggles(self):
        """根据当前配置初始化 TI / AI / Webhook 总开关，并同步到日志页"""
        providers_cfg = self.cfg.get("providers", {}) or {}
        tb_cfg = providers_cfg.get("threatbook", {}) or {}
        ai_cfg = self.cfg.get("ai", {}) or {}
        webhook_cfg = self.cfg.get("webhook", {}) or {}

        self.ti_enabled = bool(tb_cfg.get("enabled", False))
        self.ai_enabled = bool(ai_cfg.get("enabled", False))
        self.webhook_enabled = bool(webhook_cfg.get("enabled", True))

        self._apply_toggle_style(self.ti_toggle_btn, self.ti_enabled)
        self._apply_toggle_style(self.ai_toggle_btn, self.ai_enabled)
        self._apply_toggle_style(self.webhook_toggle_btn, self.webhook_enabled)

        self.ti_toggle_btn.setText("TI:开" if self.ti_enabled else "TI:关")
        self.ai_toggle_btn.setText("AI:开" if self.ai_enabled else "AI:关")
        self.webhook_toggle_btn.setText("推送:开" if self.webhook_enabled else "推送:关")

        # 同步到日志页
        try:
            self.log_page.set_feature_toggles(
                ti_enabled=self.ti_enabled,
                ai_enabled=self.ai_enabled,
                webhook_enabled=self.webhook_enabled,
            )
        except Exception:
            pass

    def _update_log_page_feature_toggles(self):
        """将当前开关状态同步到日志处理页"""
        try:
            self.log_page.set_feature_toggles(
                ti_enabled=self.ti_enabled,
                ai_enabled=self.ai_enabled,
                webhook_enabled=self.webhook_enabled,
            )
        except Exception:
            pass

    def on_toggle_ti_enabled(self):
        """切换威胁情报总开关"""
        self.ti_enabled = not getattr(self, "ti_enabled", False)
        self._apply_toggle_style(self.ti_toggle_btn, self.ti_enabled)
        self.ti_toggle_btn.setText("TI:开" if self.ti_enabled else "TI:关")
        self._update_log_page_feature_toggles()

    def on_toggle_ai_enabled(self):
        """切换 AI 总开关"""
        self.ai_enabled = not getattr(self, "ai_enabled", False)
        self._apply_toggle_style(self.ai_toggle_btn, self.ai_enabled)
        self.ai_toggle_btn.setText("AI:开" if self.ai_enabled else "AI:关")
        self._update_log_page_feature_toggles()

    def on_toggle_webhook_enabled(self):
        """切换消息推送总开关"""
        self.webhook_enabled = not getattr(self, "webhook_enabled", True)
        self._apply_toggle_style(self.webhook_toggle_btn, self.webhook_enabled)
        self.webhook_toggle_btn.setText("推送:开" if self.webhook_enabled else "推送:关")
        self._update_log_page_feature_toggles()
