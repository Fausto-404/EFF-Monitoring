from datetime import datetime, timedelta
from fastapi import HTTPException


def parse_day(value: str, end_of_day: bool = False) -> datetime:
    try:
        if " " in value:
            return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        day = datetime.strptime(value, "%Y-%m-%d")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="日期格式应为 YYYY-MM-DD 或 YYYY-MM-DD HH:mm:ss") from exc
    return day + timedelta(days=1) if end_of_day else day
