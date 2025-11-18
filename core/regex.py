"""
正则引擎模块
职责: 编译用户定义的正则规则，进行日志字段提取
"""
import re
from .config import ensure_config


class RegexEngine:
    """正则引擎，管理编译后的正则模式"""
    
    def __init__(self):
        self.five_tuple_patterns = {}  # {field: [compiled_patterns]}
        self.extra_patterns = {}  # {field: [compiled_patterns]}
        self.extra_enabled = {}  # {field: enabled}
    
    def load_from_config(self, cfg):
        """从配置加载并编译正则模式"""
        # 编译五元组
        five_tuple = cfg.get('regex', {}).get('five_tuple', {})
        for field, patterns in five_tuple.items():
            self.five_tuple_patterns[field] = self._compile_patterns(patterns)
        
        # 编译额外字段
        extra_fields = cfg.get('regex', {}).get('extra_fields', {})
        for field, config in extra_fields.items():
            enabled = config.get('enabled', True)
            self.extra_enabled[field] = enabled
            
            if enabled:
                # 处理 patterns 或 pattern
                patterns = config.get('patterns') or [config.get('pattern')]
                self.extra_patterns[field] = self._compile_patterns(patterns)
    
    def _compile_patterns(self, patterns):
        """
        编译正则模式
        
        Args:
            patterns: 字符串或字符串列表
        
        Returns:
            list: 编译后的regex对象列表
        """
        if isinstance(patterns, str):
            patterns = [patterns]
        
        compiled = []
        for pattern in patterns:
            try:
                compiled.append(re.compile(pattern))
            except re.error as e:
                print(f"正则编译失败: {pattern}, 错误: {e}")
        
        return compiled
    
    def extract_fields(self, text):
        """
        使用引擎提取文本中的字段
        
        Args:
            text: 原始日志文本
        
        Returns:
            dict: 提取的字段 {field: value}
        """
        result = {}
        
        if not text:
            return result
        
        # 提取五元组
        for field, patterns in self.five_tuple_patterns.items():
            value = self._match_patterns(text, patterns)
            if value:
                result[field] = value
        
        # 提取额外字段
        for field, patterns in self.extra_patterns.items():
            if self.extra_enabled.get(field, True):
                value = self._match_patterns(text, patterns)
                if value:
                    result[field] = value
        
        return result
    
    def _match_patterns(self, text, patterns):
        """
        使用多个正则模式匹配
        返回第一个匹配的结果
        
        Args:
            text: 原始文本
            patterns: 编译后的regex对象列表
        
        Returns:
            str: 匹配的值，或None
        """
        for pattern in patterns:
            match = pattern.search(text)
            if match:
                # 如果有分组，返回第一个分组；否则返回整个匹配
                if match.groups():
                    return match.group(1)
                else:
                    return match.group(0)
        
        return None


def load_engine(cfg=None):
    """
    加载并初始化正则引擎
    
    Args:
        cfg: 配置字典，如果为None则从ensure_config()获取
    
    Returns:
        RegexEngine: 初始化后的引擎
    """
    if cfg is None:
        cfg = ensure_config()
    
    engine = RegexEngine()
    engine.load_from_config(cfg)
    return engine


def extract_fields(text, engine):
    """
    使用给定的引擎提取字段
    
    Args:
        text: 原始文本
        engine: RegexEngine实例
    
    Returns:
        dict: 提取的字段
    """
    return engine.extract_fields(text)
