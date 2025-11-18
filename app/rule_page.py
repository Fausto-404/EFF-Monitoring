"""规则管理页面

设计思路（对标常见安全产品的规则配置）:
    - 表格按「字段 / 匹配方式 / 匹配规则」三列展示；
    - 每一行代表一个字段的一组规则，第三列支持多行文本（每行一条正则或固定值）；
    - 添加/编辑通过多行输入对话框完成，避免在表格里嵌套复杂下拉控件；
    - 保存时将多行拆成列表写回 config.json，兼容 existing five_tuple/extra_fields/static_fields 结构；
    - 必填字段（src_ip、dst_ip、event_type、request、response、payload）至少保留一行，不能全部删除。
"""
from datetime import datetime
import json

from .ui_common import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QTextEdit, QMessageBox,
    QFileDialog, QInputDialog, QColor
)
from core.config import load_config, save_config
from core.parser import extract_with_patterns


class RulePage(QWidget):
    """规则管理页面"""

    def __init__(self, cfg, on_config_changed=None):
        super().__init__()
        self.cfg = cfg
        self.on_config_changed = on_config_changed
        # 必填字段，至少保留一条匹配规则
        self.required_fields = ["src_ip", "dst_ip", "event_type", "request", "response", "payload"]
        self.init_ui()
        self.load_rules()

    def init_ui(self):
        layout = QVBoxLayout()

        self.pattern_table = QTableWidget(0, 3)
        self.pattern_table.setHorizontalHeaderLabels(["字段", "匹配方式", "匹配规则（每行一条）"])
        header = self.pattern_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        self.pattern_table.verticalHeader().setVisible(False)
        self.pattern_table.setWordWrap(True)
        # 禁止直接双击编辑单元格，所有编辑统一走“编辑”按钮弹窗
        self.pattern_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.pattern_table, 1)

        # 操作按钮
        btn_layout = QHBoxLayout()
        self.pattern_add_btn = QPushButton("添加")
        self.pattern_edit_btn = QPushButton("编辑")
        self.pattern_delete_btn = QPushButton("删除选中")
        self.pattern_import_btn = QPushButton("导入")
        self.pattern_export_btn = QPushButton("导出")
        self.pattern_test_btn = QPushButton("测试选中")
        btn_layout.addWidget(self.pattern_add_btn)
        btn_layout.addWidget(self.pattern_edit_btn)
        btn_layout.addWidget(self.pattern_delete_btn)
        btn_layout.addWidget(self.pattern_import_btn)
        btn_layout.addWidget(self.pattern_export_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(self.pattern_test_btn)
        layout.addLayout(btn_layout)

        control_layout = QHBoxLayout()
        self.save_btn = QPushButton("保存规则")
        control_layout.addStretch()
        control_layout.addWidget(self.save_btn)
        layout.addLayout(control_layout)

        self.pattern_add_btn.clicked.connect(self.on_pattern_add)
        self.pattern_edit_btn.clicked.connect(self.on_pattern_edit)
        self.pattern_delete_btn.clicked.connect(self.on_pattern_delete)
        self.pattern_import_btn.clicked.connect(self.on_pattern_import)
        self.pattern_export_btn.clicked.connect(self.on_pattern_export)
        self.pattern_test_btn.clicked.connect(self.on_pattern_test)
        self.save_btn.clicked.connect(self.on_save)

        self.pattern_test_result = QTextEdit()
        self.pattern_test_result.setReadOnly(True)
        self.pattern_test_result.setFixedHeight(140)
        layout.addWidget(self.pattern_test_result)

        self.setLayout(layout)

    # ---------- 核心数据加载 / 保存 ----------
    def _resize_rows(self):
        """根据内容自动调整行高，保证多行规则完整可见"""
        self.pattern_table.resizeRowsToContents()

    def load_rules(self):
        """从配置加载规则列表"""
        try:
            self.cfg = load_config()
        except Exception:
            pass
        regex_cfg = self.cfg.get("regex", {})
        try:
            self.pattern_table.setRowCount(0)
            # 五元组
            for field, pats in (regex_cfg.get("five_tuple", {}) or {}).items():
                vals = pats if isinstance(pats, list) else [pats]
                vals = [str(v) for v in vals if v is not None]
                if vals:
                    self._append_pattern_row(str(field), "regex", vals)
            # 额外字段
            for field, conf in (regex_cfg.get("extra_fields", {}) or {}).items():
                enabled = (conf or {}).get("enabled", True)
                pats = (conf or {}).get("patterns")
                if pats is None and conf:
                    pats = [conf.get("pattern")]
                if not enabled:
                    continue
                vals = pats if isinstance(pats, list) else [pats]
                vals = [str(v) for v in vals if v is not None]
                if vals:
                    self._append_pattern_row(str(field), "regex", vals)
            # 自定义规则（兼容老字段）
            custom = regex_cfg.get("custom_patterns", {}) or {}
            for field, pats in custom.items():
                vals = pats if isinstance(pats, list) else [pats]
                vals = [str(v) for v in vals if v is not None]
                if vals:
                    self._append_pattern_row(str(field), "regex", vals)
            # 静态字段（手动输入）
            for field, val in (self.cfg.get("static_fields", {}) or {}).items():
                vals = val if isinstance(val, list) else [val]
                vals = [str(v) for v in vals if v is not None]
                if vals:
                    self._append_pattern_row(str(field), "manual", vals)
            # 确保必填字段存在
            self._ensure_required_rules()
            # 将必填字段行置顶，且与其他规则做颜色区分
            self._rebuild_required_on_top()
            self._resize_rows()
        except Exception:
            pass

    def on_save(self):
        """保存规则配置到 config.json"""
        try:
            known = {"src_ip", "dst_ip", "dst_ip_port", "protocol", "event_name"}
            known.update(self.required_fields)
            five = {}
            extra = {}
            static = {}

            for r in range(self.pattern_table.rowCount()):
                fi = self.pattern_table.item(r, 0)
                mi = self.pattern_table.item(r, 1)
                vi = self.pattern_table.item(r, 2)
                if not fi or not mi or not vi:
                    continue
                field = fi.text().strip()
                mode = (mi.text().strip() or "regex")
                value_text = (vi.text() or "").strip()
                vals = [line.strip() for line in value_text.splitlines() if line.strip()]
                if not field or not vals:
                    continue
                if mode == "manual":
                    static[field] = vals[0] if len(vals) == 1 else vals
                else:
                    if field in known:
                        five.setdefault(field, []).extend(vals)
                    else:
                        conf = extra.setdefault(field, {"enabled": True, "patterns": []})
                        conf["patterns"].extend(vals)

            # 压缩五元组单值
            for k, v in list(five.items()):
                if len(v) == 1:
                    five[k] = v[0]

            self.cfg.setdefault("regex", {})["five_tuple"] = five
            self.cfg["regex"]["extra_fields"] = extra
            # 静态字段：未填写则置空
            self.cfg["static_fields"] = static
            # 清理旧 custom_patterns
            self.cfg["regex"].pop("custom_patterns", None)
            save_config(self.cfg)

            if self.on_config_changed:
                try:
                    self.on_config_changed()
                except Exception:
                    pass

            QMessageBox.information(self, "成功", "规则已保存")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"保存失败: {str(e)}")

    # ---------- 表格操作 ----------
    def _style_row_for_field(self, row: int, field: str):
        """根据字段是否必填，对整行做颜色区分展示"""
        is_required = field in getattr(self, "required_fields", [])
        if not is_required:
            return
        for col in range(self.pattern_table.columnCount()):
            item = self.pattern_table.item(row, col)
            if not item:
                continue
            # 必填字段：浅橙色背景 + 深色字体，确保在深色模式下也清晰可见
            item.setBackground(QColor(255, 248, 220))
            item.setForeground(QColor(0, 0, 0))

    def _append_pattern_row(self, field: str, mode: str, values):
        field = (field or "").strip()
        mode = mode if mode in ("regex", "manual") else "regex"
        if not field:
            return
        if isinstance(values, str):
            values = [values]
        values = [str(v).strip() for v in (values or []) if str(v).strip()]
        if not values:
            return
        row = self.pattern_table.rowCount()
        self.pattern_table.insertRow(row)
        self.pattern_table.setItem(row, 0, QTableWidgetItem(field))
        self.pattern_table.setItem(row, 1, QTableWidgetItem(mode))
        text = "\n".join(values)
        item = QTableWidgetItem(text)
        item.setToolTip(text)
        self.pattern_table.setItem(row, 2, item)
        # 必填字段高亮显示，便于用户识别
        self._style_row_for_field(row, field)

    def on_pattern_add(self):
        existing_fields = []
        for r in range(self.pattern_table.rowCount()):
            item = self.pattern_table.item(r, 0)
            if item:
                existing_fields.append(item.text())
        field_choices = list(dict.fromkeys(self.required_fields + existing_fields))

        field, ok1 = QInputDialog.getItem(self, "添加规则", "字段名:", field_choices, 0, True)
        if not ok1 or not field.strip():
            return
        field = field.strip()

        # 必填字段固定为 regex，且匹配方式不可更改
        if field in self.required_fields:
            mode = "regex"
            label = "正则表达式（每行一条）"
        else:
            mode, ok2 = QInputDialog.getItem(self, "匹配方式", "选择匹配方式:", ["regex", "manual"], 0, False)
            if not ok2:
                return
            label = "正则表达式（每行一条）" if mode == "regex" else "固定值（每行一条）"

        val, ok3 = QInputDialog.getMultiLineText(self, "添加规则", label + ":")
        if not ok3:
            return
        values = [v.strip() for v in val.splitlines() if v.strip()]
        if not values:
            return
        self._append_pattern_row(field, mode, values)
        self._resize_rows()

    def on_pattern_edit(self):
        sel = self.pattern_table.selectedIndexes()
        if not sel:
            QMessageBox.information(self, "提示", "请先选择要编辑的行")
            return
        row = sel[0].row()
        f0 = self.pattern_table.item(row, 0)
        m1 = self.pattern_table.item(row, 1)
        v2 = self.pattern_table.item(row, 2)
        field = f0.text() if f0 else ""
        mode = m1.text() if m1 else "regex"
        text = v2.text() if v2 else ""

        # 必填字段：字段名和匹配方式均不可修改，只允许调整规则内容
        if field in self.required_fields:
            label = "正则表达式（每行一条）"
            nval, ok3 = QInputDialog.getMultiLineText(self, "编辑规则", label + ":", text=text)
            if not ok3:
                return
            values = [v.strip() for v in nval.splitlines() if v.strip()]
            if not values:
                return
            item = QTableWidgetItem("\n".join(values))
            item.setToolTip("\n".join(values))
            self.pattern_table.setItem(row, 2, item)
            self._resize_rows()
            return

        # 非必填字段：允许修改字段名和匹配方式
        field_choices = self.required_fields + [field]
        # 默认选中当前行的字段名，而不是固定的第一个（如 src_ip）
        default_index = field_choices.index(field) if field in field_choices else 0
        nf, ok1 = QInputDialog.getItem(self, "编辑规则", "字段名:", field_choices, default_index, True)
        if not ok1:
            return
        nmode, ok2 = QInputDialog.getItem(self, "匹配方式", "选择匹配方式:", ["regex", "manual"], 0, False)
        if not ok2:
            return
        label = "正则表达式（每行一条）" if nmode == "regex" else "固定值（每行一条）"
        nval, ok3 = QInputDialog.getMultiLineText(self, "编辑规则", label + ":", text=text)
        if not ok3:
            return
        values = [v.strip() for v in nval.splitlines() if v.strip()]
        if not values:
            return
        nf = nf.strip()
        self.pattern_table.setItem(row, 0, QTableWidgetItem(nf))
        self.pattern_table.setItem(row, 1, QTableWidgetItem(nmode))
        item = QTableWidgetItem("\n".join(values))
        item.setToolTip("\n".join(values))
        self.pattern_table.setItem(row, 2, item)
        # 编辑后根据最新字段名重新设置行样式（必填/非必填颜色）
        self._style_row_for_field(row, nf)
        self._resize_rows()

    def on_pattern_delete(self):
        selected = set(idx.row() for idx in self.pattern_table.selectedIndexes())
        if not selected:
            QMessageBox.information(self, "提示", "请选择要删除的行")
            return
        # 至少保留必填字段的一行
        field_count = {}
        for r in range(self.pattern_table.rowCount()):
            fi = self.pattern_table.item(r, 0)
            if fi:
                field_count[fi.text()] = field_count.get(fi.text(), 0) + 1
        for row in sorted(selected, reverse=True):
            fi = self.pattern_table.item(row, 0)
            fname = fi.text() if fi else ""
            if fname in self.required_fields and field_count.get(fname, 0) <= 1:
                QMessageBox.information(self, "提示", f"{fname} 为必填字段，至少保留一条规则")
                continue
            self.pattern_table.removeRow(row)
        self._resize_rows()

    # ---------- 导入 / 导出 / 测试 ----------
    def on_pattern_import(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "导入规则文件", "", "文本文件 (*.txt);;JSON 文件 (*.json)")
        if not file_path:
            return
        try:
            if file_path.lower().endswith(".json"):
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        iterable = data.items()
                    elif isinstance(data, list):
                        iterable = [
                            (entry.get("field") or entry.get("key") or entry.get("name") or "event_name", entry)
                            for entry in data
                            if isinstance(entry, dict)
                        ]
                    else:
                        iterable = []

                    for field, payload in iterable:
                        entries = payload if isinstance(payload, list) else [payload]
                        for entry in entries:
                            if isinstance(entry, dict):
                                mode = entry.get("mode") or entry.get("type") or "regex"
                                raw_vals = entry.get("value") or entry.get("pattern") or entry.get("regex") or entry.get(
                                    "values"
                                )
                                vals = raw_vals if isinstance(raw_vals, list) else [raw_vals]
                                vals = [v for v in vals if v is not None]
                                self._append_pattern_row(field, mode, vals)
                            else:
                                self._append_pattern_row(field, "regex", [entry])
            else:
                with open(file_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if "\t" in line:
                            parts = line.split("\t")
                            if len(parts) >= 3:
                                field, mode, value = parts[0], parts[1], "\t".join(parts[2:])
                            elif len(parts) == 2:
                                field, mode, value = parts[0], "regex", parts[1]
                            else:
                                continue
                        elif line.count("|") >= 2:
                            field, mode, value = line.split("|", 2)
                        elif "|" in line:
                            field, value = line.split("|", 1)
                            mode = "regex"
                        else:
                            field, mode, value = "event_name", "regex", line
                        vals = [v.strip() for v in value.split("||")] if "||" in value else [value]
                        self._append_pattern_row(field, mode, vals)

            self._resize_rows()
            QMessageBox.information(self, "成功", "导入完成")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"导入失败: {e}")

    def on_pattern_export(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "导出规则", "", "JSON 文件 (*.json);;文本文件 (*.txt)")
        if not file_path:
            return
        try:
            if file_path.lower().endswith(".json"):
                out = {}
                for r in range(self.pattern_table.rowCount()):
                    f0 = self.pattern_table.item(r, 0)
                    m1 = self.pattern_table.item(r, 1)
                    v2 = self.pattern_table.item(r, 2)
                    if not f0 or not m1 or not v2:
                        continue
                    field = f0.text().strip()
                    mode = m1.text().strip() or "regex"
                    value_text = (v2.text() or "").strip()
                    vals = [line.strip() for line in value_text.splitlines() if line.strip()]
                    if not field or not vals:
                        continue
                    out.setdefault(field, []).append({"mode": mode, "value": vals if len(vals) > 1 else vals[0]})

                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(out, f, ensure_ascii=False, indent=2)
            else:
                with open(file_path, "w", encoding="utf-8") as f:
                    for r in range(self.pattern_table.rowCount()):
                        f0 = self.pattern_table.item(r, 0)
                        m1 = self.pattern_table.item(r, 1)
                        v2 = self.pattern_table.item(r, 2)
                        if not f0 or not m1 or not v2:
                            continue
                        field = f0.text().strip()
                        mode = (m1.text() or "regex").strip()
                        value_text = (v2.text() or "").strip()
                        vals = [line.strip() for line in value_text.splitlines() if line.strip()]
                        if not field or not vals:
                            continue
                        f.write(f"{field}\t{mode}\t{'||'.join(vals)}\n")
            QMessageBox.information(self, "成功", "导出完成")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"导出失败: {e}")

    def on_pattern_test(self):
        sel = self.pattern_table.selectedIndexes()
        if not sel:
            QMessageBox.information(self, "提示", "请先选择要测试的行")
            return
        row = sel[0].row()
        mode_item = self.pattern_table.item(row, 1)
        val_item = self.pattern_table.item(row, 2)
        if not mode_item or not val_item:
            QMessageBox.warning(self, "警告", "所选行数据不完整")
            return
        mode = mode_item.text().strip()
        value_text = (val_item.text() or "").strip()
        values = [line.strip() for line in value_text.splitlines() if line.strip()]
        if not values:
            QMessageBox.warning(self, "警告", "未填写匹配规则")
            return
        if mode != "regex":
            QMessageBox.information(self, "提示", "手动输入规则无需测试（直接作为固定值使用）")
            return
        sample, ok = QInputDialog.getMultiLineText(self, "测试规则", "输入测试日志:")
        if not ok:
            return
        try:
            res = extract_with_patterns(values, sample)
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            entry = f"[{ts}] 规则测试: {values}\n结果: {res}\n\n"
            cur = self.pattern_test_result.toPlainText()
            self.pattern_test_result.setPlainText(entry + cur)
            QMessageBox.information(self, "测试结果", f"匹配: {res}")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"测试异常: {e}")

    # ---------- 必填字段默认规则 ----------
    def _ensure_required_rules(self):
        """确保必填字段至少一条规则，不存在时注入默认正则"""
        existing = set()
        for r in range(self.pattern_table.rowCount()):
            fi = self.pattern_table.item(r, 0)
            if fi:
                existing.add(fi.text())
        defaults = {
            "src_ip": [
                r"源IP[:：]?\s*([\d\.]{7,})",
                r"源[:：]?\s*([\d\.]{7,})",
                r"攻击者\s*([\d\.]{7,})",
            ],
            "dst_ip": [
                r"目的IP[:：]?\s*([\d\.]{7,})",
                r"目[:：]?\s*([\d\.]{7,})",
                r"受害者视角\s*([\d\.]{7,})",
            ],
            "event_type": [
                r"事件名称[:：]\s*([^\n]+)",
                r"事件分类[:：]\s*([^\n]+)",
                r"攻击链阶段\s*[:：]\s*([^\n]+)",
            ],
            "request": [
                r"请求内容[:：]\s*([\s\S]+?)\n\s*响应内容",
                r"请求体[:：]\s*([\s\S]+?)\n\s*响应体",
                r"GET\s+[^\n]+?HTTP/1\.[01][\s\S]+?(?=\n{2,}|响应内容|响应体)",
            ],
            "response": [
                r"响应内容[:：]\s*([\s\S]+?)(?:\n{2,}|\Z)",
                r"响应体[:：]\s*([\s\S]+?)(?:\n{2,}|\Z)",
                r"HTTP/\d\.\d\s+\d{3}[^\n]*[\s\S]*?(?=\n{2,}|\Z)",
            ],
            "payload": [
                r"载荷\s*([\s\S]+?)\n\s*流量上下文",
                r"载荷\s*([\s\S]+?)(?:请求内容|响应内容)",
                r"载荷\s*([\s\S]+?)\n{2,}",
            ],
        }
        for field in self.required_fields:
            if field not in existing:
                vals = defaults.get(field, [".+"])
                self._append_pattern_row(field, "regex", vals)

    def _rebuild_required_on_top(self):
        """重排表格行：6个必填字段固定置顶，其他规则保持原有顺序"""
        rows = []
        for r in range(self.pattern_table.rowCount()):
            fi = self.pattern_table.item(r, 0)
            mi = self.pattern_table.item(r, 1)
            vi = self.pattern_table.item(r, 2)
            if not fi or not mi or not vi:
                continue
            field = fi.text().strip()
            mode = mi.text().strip() or "regex"
            value_text = (vi.text() or "").strip()
            values = [line.strip() for line in value_text.splitlines() if line.strip()]
            if not field or not values:
                continue
            rows.append((field, mode, values))

        # 先清空再按“必填字段在前”的顺序重新插入
        self.pattern_table.setRowCount(0)

        # 先插入必填字段，按 required_fields 顺序
        for req_field in self.required_fields:
            for field, mode, values in rows:
                if field == req_field:
                    self._append_pattern_row(field, mode, values)

        # 再插入非必填字段，保持原始相对顺序
        for field, mode, values in rows:
            if field not in self.required_fields:
                self._append_pattern_row(field, mode, values)
