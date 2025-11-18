"""
主应用入口
职责: 启动 PySide6 应用并加载主窗口
"""
import sys

from app.ui_common import QApplication, PYSIDE_AVAILABLE
from app.main_window import MainWindow


def main():
    """启动 GUI 主程序"""
    if not PYSIDE_AVAILABLE:
        print("PySide6未安装，请运行: pip install -r requirements.txt")
        sys.exit(1)

    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

