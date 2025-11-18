"""UI 公共模块: 统一 Qt 导入和 PYSIDE_AVAILABLE"""
import sys

try:
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
        QListWidget, QListWidgetItem, QStackedWidget, QTabWidget,
        QLabel, QLineEdit, QTextEdit, QPushButton, QMessageBox,
        QFileDialog, QTableWidget, QTableWidgetItem, QHeaderView,
        QComboBox, QCheckBox, QGroupBox, QSpinBox, QAbstractItemView,
        QFormLayout, QDialog, QInputDialog, QToolTip
    )
    from PySide6.QtCore import Qt, QThread, Signal, QObject, QSize
    from PySide6.QtGui import QColor
    PYSIDE_AVAILABLE = True
except ImportError:
    # 提供哑对象以便在无 PySide6 环境下仍可导入模块
    PYSIDE_AVAILABLE = False
    class _Dummy:  # type: ignore
        pass
    QApplication = QMainWindow = QWidget = QHBoxLayout = QVBoxLayout = \
        QListWidget = QListWidgetItem = QStackedWidget = QTabWidget = \
        QLabel = QLineEdit = QTextEdit = QPushButton = QMessageBox = \
        QFileDialog = QTableWidget = QTableWidgetItem = QHeaderView = \
        QComboBox = QCheckBox = QGroupBox = QSpinBox = QFormLayout = \
        QDialog = QInputDialog = QAbstractItemView = QToolTip = _Dummy
    Qt = QThread = Signal = QObject = QSize = QColor = _Dummy
    print("警告: PySide6未安装，应用将以非GUI模式运行", file=sys.stderr)
