"""IP 列表管理页面"""
from .ui_common import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTableWidget, QTableWidgetItem, QMessageBox,
    QFileDialog, QInputDialog
)
from core.lists import read_lines, write_lines, import_ips, export_ips, search_ips
from core import ipdb as ipdb

class IPPage(QWidget):
    """IP列表管理页面"""
    def __init__(self, cfg):
        super().__init__()
        self.cfg = cfg
        self.current_list_type = 'whitelist'
        self.current_ips = []
        self.init_ui()
        self.load_lists()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # 列表类型选择
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("列表类型:"))
        # 使用类似主题切换的按钮在白名单/黑名单之间切换
        self.list_type_btn = QPushButton("白名单")
        self.list_type_btn.setCheckable(False)
        self.list_type_btn.clicked.connect(self.on_toggle_list_type)
        type_layout.addWidget(self.list_type_btn)
        
        type_layout.addStretch()
        layout.addLayout(type_layout)
        # 搜索和过滤
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("搜索:"))

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("输入IP或关键词...")
        self.search_input.textChanged.connect(self.on_search)
        search_layout.addWidget(self.search_input)

        layout.addLayout(search_layout)
        
        # IP列表显示（表格）
        self.ip_table = QTableWidget(0, 1)
        self.ip_table.setHorizontalHeaderLabels(["IP / CIDR / Range"])
        self.ip_table.horizontalHeader().setStretchLastSection(True)
        self.ip_table.verticalHeader().setVisible(False)
        self.ip_table.setSelectionBehavior(QTableWidget.SelectRows)
        layout.addWidget(self.ip_table, 1)

        # 按钮行
        button_layout = QHBoxLayout()

        self.add_btn = QPushButton("添加")
        self.add_btn.clicked.connect(self.on_add_ip)
        button_layout.addWidget(self.add_btn)

        self.delete_btn = QPushButton("删除选中")
        self.delete_btn.clicked.connect(self.on_delete_ip)
        button_layout.addWidget(self.delete_btn)

        self.import_btn = QPushButton("导入")
        self.import_btn.clicked.connect(self.on_import)
        button_layout.addWidget(self.import_btn)

        self.export_btn = QPushButton("导出")
        self.export_btn.clicked.connect(self.on_export)
        button_layout.addWidget(self.export_btn)

        self.save_btn = QPushButton("保存")
        self.save_btn.setStyleSheet("background-color: #7bdcb5; color: white;")
        self.save_btn.clicked.connect(self.on_save)
        button_layout.addWidget(self.save_btn)

        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def load_lists(self):
        """加载列表"""
        self.on_list_type_changed()
    
    def on_toggle_list_type(self):
        """点击按钮在白名单/黑名单之间切换"""
        self.current_list_type = 'blacklist' if self.current_list_type == 'whitelist' else 'whitelist'
        self.list_type_btn.setText("黑名单" if self.current_list_type == 'blacklist' else "白名单")
        self.on_list_type_changed()

    def on_list_type_changed(self):
        """列表类型改变"""
        lists_cfg = self.cfg.get('lists', {})
        db_path = lists_cfg.get('db_path')
        cfg_key = 'blocked_path' if self.current_list_type == 'blacklist' else 'whitelist_path'
        path = lists_cfg.get(cfg_key)

        try:
            if db_path:
                # 使用DB后端
                self.current_ips = ipdb.get_ips(db_path, self.current_list_type)
            elif path:
                self.current_ips = read_lines(path)
            else:
                self.current_ips = []
            self.display_ips(self.current_ips)
        except Exception:
            self.ip_table.setRowCount(0)
            self.current_ips = []
    
    def display_ips(self, ips):
        """显示IP列表到表格"""
        self.ip_table.setRowCount(0)
        for ip in ips:
            row = self.ip_table.rowCount()
            self.ip_table.insertRow(row)
            self.ip_table.setItem(row, 0, QTableWidgetItem(ip))

    def on_search(self):
        """搜索IP"""
        keyword = self.search_input.text().strip()
        if not keyword:
            self.display_ips(self.current_ips)
            return

        results = search_ips(self.current_ips, keyword)
        self.display_ips(results)
    
    def on_add_ip(self):
        """添加IP"""
        # 弹出输入对话框
        text, ok = QInputDialog.getText(self, "添加IP", "输入IP/CIDR/范围:")
        if ok and text.strip():
            ip = text.strip()
            row = self.ip_table.rowCount()
            self.ip_table.insertRow(row)
            self.ip_table.setItem(row, 0, QTableWidgetItem(ip))
            self.current_ips.append(ip)
    
    def on_delete_ip(self):
        """删除选中行"""
        selected = set([idx.row() for idx in self.ip_table.selectedIndexes()])
        for row in sorted(selected, reverse=True):
            self.ip_table.removeRow(row)
        # rebuild current_ips
        ips = []
        for r in range(self.ip_table.rowCount()):
            item = self.ip_table.item(r, 0)
            if item:
                ips.append(item.text())
        self.current_ips = ips
    
    def on_import(self):
        """导入"""
        file_path, _ = QFileDialog.getOpenFileName(self, "选择导入文件", "", "文本文件 (*.txt)")
        if file_path:
            try:
                lists_cfg = self.cfg.get('lists', {})
                db_path = lists_cfg.get('db_path')
                if db_path:
                    cnt = ipdb.import_from_file(db_path, self.current_list_type, file_path)
                    self.current_ips = ipdb.get_ips(db_path, self.current_list_type)
                    self.display_ips(self.current_ips)
                    QMessageBox.information(self, "成功", f"导入{cnt}条IP到DB")
                else:
                    ips = import_ips(file_path)
                    self.current_ips = ips
                    self.display_ips(ips)
                    QMessageBox.information(self, "成功", f"导入{len(ips)}条IP")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"导入失败: {str(e)}")
    
    def on_export(self):
        """导出"""
        file_path, _ = QFileDialog.getSaveFileName(self, "保存为", "", "文本文件 (*.txt)")
        if file_path:
            try:
                lists_cfg = self.cfg.get('lists', {})
                db_path = lists_cfg.get('db_path')
                if db_path:
                    cnt = ipdb.export_to_file(db_path, self.current_list_type, file_path)
                    QMessageBox.information(self, "成功", f"导出{cnt}条IP")
                else:
                    ips = [self.ip_table.item(r, 0).text() for r in range(self.ip_table.rowCount())]
                    ips = [ip.strip() for ip in ips if ip.strip()]
                    export_ips(ips, file_path)
                    QMessageBox.information(self, "成功", f"导出{len(ips)}条IP")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"导出失败: {str(e)}")
    
    def on_save(self):
        """保存"""
        ips = [self.ip_table.item(r, 0).text() for r in range(self.ip_table.rowCount())]
        ips = [ip.strip() for ip in ips if ip.strip()]
        
        cfg_key = 'blocked_path' if self.current_list_type == 'blacklist' else 'whitelist_path'
        lists_cfg = self.cfg.get('lists', {})
        path = lists_cfg.get(cfg_key)
        
        if not path:
            QMessageBox.warning(self, "警告", "路径未配置")
            return
        
        try:
            lists_cfg = self.cfg.get('lists', {})
            db_path = lists_cfg.get('db_path')
            if db_path:
                # 将表格内容写入DB: 先清理同类型条目（简单实现）并写入
                # 这里使用 remove/add per ip
                existing = ipdb.get_ips(db_path, self.current_list_type)
                # remove those not in new ips
                for eip in existing:
                    if eip not in ips:
                        try:
                            ipdb.remove_ip(db_path, eip)
                        except Exception:
                            pass
                # add new ones
                for ip in ips:
                    try:
                        ipdb.add_ip(db_path, self.current_list_type, ip)
                    except Exception:
                        pass
                QMessageBox.information(self, "成功", "已保存到DB")
            else:
                write_lines(path, ips)
                QMessageBox.information(self, "成功", "已保存")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"保存失败: {str(e)}")
