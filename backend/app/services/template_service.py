import re
from typing import Any


def render_template(content: str, data: dict[str, Any]) -> str:
    def replace(match: re.Match[str]) -> str:
        key = match.group(1).strip()
        return str(data.get(key, ""))

    return re.sub(r"\{\{\s*([^{}]+)\s*\}\}", replace, content or "")
