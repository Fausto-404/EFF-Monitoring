"""解析历史页面"""
from pathlib import Path
import json as pyjson
import csv

from .ui_common import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox,
    Qt, QAbstractItemView, QFileDialog, QDialog, QTextEdit, QThread
)
from .workers import BatchAIWorker


class HistoryPage(QWidget):
    """解析历史大模块"""

    def __init__(self, cfg, on_restore=None):
        super().__init__()
        self.cfg = cfg
        self.on_restore = on_restore  # 回调到主窗口/LogPage 进行还原
        self.history_file = Path("output/log_history.json")
        self.history_limit = 200
        self.history = []
        self._load_history_config()
        self.init_ui()
        self.load_history()

    def _load_history_config(self):
        hist_cfg = self.cfg.get("history", {}) or {}
        file_path = hist_cfg.get("file") or "output/log_history.json"
        self.history_file = Path(file_path)
        try:
            self.history_limit = int(hist_cfg.get("max_entries", 200)) or 200
        except Exception:
            self.history_limit = 200

    def init_ui(self):
        layout = QVBoxLayout()

        header = QLabel("解析历史")
        header.setStyleSheet("font-size:16px; font-weight:600; margin-bottom:4px;")
        layout.addWidget(header)

        sub = QLabel("双击记录可跳转并还原到日志处理界面")
        sub.setStyleSheet("color:#7d8a99; font-size:12px;")
        layout.addWidget(sub)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["研判时间", "源IP", "目的IP", "事件类型"])
        header_view = self.table.horizontalHeader()
        header_view.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header_view.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header_view.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header_view.setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.itemDoubleClicked.connect(self.on_row_double_clicked)
        layout.addWidget(self.table, 1)

        btn_layout = QHBoxLayout()
        self.refresh_btn = QPushButton("刷新")
        self.refresh_btn.clicked.connect(self.load_history)
        self.export_btn = QPushButton("导出为Excel")
        self.export_btn.clicked.connect(self.on_export_excel)
        self.clear_btn = QPushButton("清空历史")
        self.clear_btn.clicked.connect(self.on_clear_history)
        self.batch_ai_btn = QPushButton("批量研判")
        self.batch_ai_btn.clicked.connect(self.on_batch_ai_analysis)
        btn_layout.addWidget(self.refresh_btn)
        btn_layout.addWidget(self.export_btn)
        btn_layout.addWidget(self.clear_btn)
        btn_layout.addWidget(self.batch_ai_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        self.setLayout(layout)

    def load_history(self):
        """从文件加载历史并刷新表格"""
        self.history = []
        try:
            if self.history_file.exists():
                data = pyjson.loads(self.history_file.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    self.history = data[: self.history_limit]
        except Exception:
            QMessageBox.warning(self, "提示", "加载历史记录失败")
        self._refresh_table()

    def _refresh_table(self):
        self.table.setRowCount(0)
        for entry in self.history:
            ts = entry.get("detected_at", "")
            pd = entry.get("parsed_data") or {}
            src = pd.get("src_ip") or ""
            dst = pd.get("dst_ip") or ""
            ev = pd.get("event_type") or pd.get("event_name") or ""
            row = self.table.rowCount()
            self.table.insertRow(row)
            item0 = QTableWidgetItem(ts)
            item0.setData(Qt.UserRole, entry)
            self.table.setItem(row, 0, item0)
            self.table.setItem(row, 1, QTableWidgetItem(src))
            self.table.setItem(row, 2, QTableWidgetItem(dst))
            self.table.setItem(row, 3, QTableWidgetItem(ev))

    def on_row_double_clicked(self, item: QTableWidgetItem):
        row = item.row()
        entry_item = self.table.item(row, 0)
        entry = entry_item.data(Qt.UserRole) if entry_item else None
        if not entry:
            return
        if self.on_restore:
            self.on_restore(entry)

    def on_export_excel(self):
        """将解析历史导出为可在Excel中打开的CSV"""
        if not self.history:
            QMessageBox.information(self, "提示", "当前没有可导出的解析历史记录")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "导出解析历史", "", "Excel CSV 文件 (*.csv);;所有文件 (*)"
        )
        if not file_path:
            return

        if not file_path.lower().endswith(".csv"):
            file_path += ".csv"

        try:
            # 使用 utf-8-sig 以便 Excel 正常识别中文
            with open(file_path, "w", encoding="utf-8-sig", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["研判发现时间", "源IP", "目的IP", "事件类型", "是否有TI结果", "是否有AI结果", "原始日志"])
                for entry in self.history:
                    ts = entry.get("detected_at", "")
                    pd = entry.get("parsed_data") or {}
                    src = pd.get("src_ip") or ""
                    dst = pd.get("dst_ip") or ""
                    ev = pd.get("event_type") or pd.get("event_name") or ""
                    has_ti = "是" if entry.get("ti_result") else "否"
                    has_ai = "是" if entry.get("ai_result") else "否"
                    raw = entry.get("raw_text") or ""
                    writer.writerow([ts, src, dst, ev, has_ti, has_ai, raw])

            QMessageBox.information(self, "成功", f"已导出解析历史到:\n{file_path}")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"导出失败: {e}")

    def on_clear_history(self):
        """清空历史记录文件与表格"""
        if QMessageBox.question(self, "确认", "确定要清空所有历史记录吗？") != QMessageBox.Yes:
            return
        self.history = []
        try:
            if self.history_file.exists():
                self.history_file.unlink()
        except Exception:
            pass
        self._refresh_table()

    def reload_config(self, cfg):
        """配置变更时刷新历史设置与内容"""
        self.cfg = cfg
        self._load_history_config()
        self.load_history()

    # ---------- 批量 AI 研判 ----------
    def on_batch_ai_analysis(self):
        """对选中的多条历史记录进行批量 AI 研判"""
        selected_rows = sorted({idx.row() for idx in self.table.selectedIndexes()})
        if not selected_rows:
            QMessageBox.information(self, "提示", "请先在历史记录中选择至少一条告警")
            return

        entries = []
        for row in selected_rows:
            item = self.table.item(row, 0)
            if not item:
                continue
            entry = item.data(Qt.UserRole)
            if entry:
                entries.append(entry)

        if not entries:
            QMessageBox.information(self, "提示", "未能获取选中告警的详细记录")
            return

        # 限制数量，避免提示词过长
        max_entries = 20
        if len(entries) > max_entries:
            entries = entries[:max_entries]

        # 简单检查 AI 配置是否有 Key
        ai_cfg = self.cfg.get("ai", {}) or {}
        if not ai_cfg.get("api_key"):
            QMessageBox.warning(self, "警告", "AI API Key 未配置，请先在配置管理中填写。")
            return

        # 启动批量 AI 研判线程
        self.batch_ai_btn.setEnabled(False)
        self.batch_ai_btn.setText("批量研判中...")

        self.batch_ai_worker = BatchAIWorker(entries, self.cfg)
        self.batch_ai_thread = QThread()
        self.batch_ai_worker.moveToThread(self.batch_ai_thread)
        self.batch_ai_worker.done.connect(self.on_batch_ai_done)
        self.batch_ai_worker.error.connect(self.on_batch_ai_error)
        self.batch_ai_thread.started.connect(self.batch_ai_worker.run)
        self.batch_ai_thread.start()

    def on_batch_ai_done(self, payload: dict):
        """批量 AI 研判完成"""
        try:
            self.batch_ai_thread.quit()
            self.batch_ai_thread.wait()
        except Exception:
            pass

        self.batch_ai_btn.setEnabled(True)
        self.batch_ai_btn.setText("批量研判")

        result_text = payload.get("ai_batch_result") or "未获取到批量研判结果。"

        dlg = QDialog(self)
        dlg.setWindowTitle("批量告警研判结果")
        vbox = QVBoxLayout(dlg)
        info_label = QLabel("以下为本次选中多条告警的整体研判结果：")
        info_label.setWordWrap(True)
        vbox.addWidget(info_label)
        text = QTextEdit()
        text.setReadOnly(True)
        text.setPlainText(result_text)
        text.setMinimumSize(600, 400)
        vbox.addWidget(text)
        close_btn = QPushButton("关闭")
        close_btn.clicked.connect(dlg.accept)
        hbox = QHBoxLayout()
        hbox.addStretch()
        hbox.addWidget(close_btn)
        vbox.addLayout(hbox)
        dlg.exec()

    def on_batch_ai_error(self, error: str):
        """批量 AI 研判出错"""
        try:
            self.batch_ai_thread.quit()
            self.batch_ai_thread.wait()
        except Exception:
            pass

        self.batch_ai_btn.setEnabled(True)
        self.batch_ai_btn.setText("批量研判")

        QMessageBox.critical(self, "错误", f"批量 AI 研判异常: {error}")
