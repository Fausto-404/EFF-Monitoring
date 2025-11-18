#!/usr/bin/env python
"""
EFF-Monitoring 启动脚本
"""
import sys
from pathlib import Path

# 添加项目根目录到Python路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from app.main import main, PYSIDE_AVAILABLE

if __name__ == "__main__":
    if not PYSIDE_AVAILABLE:
        print("警告: PySide6未安装")
        print("请运行: pip install -r requirements.txt")
        sys.exit(1)
    
    main()
