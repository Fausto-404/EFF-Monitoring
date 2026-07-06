from datetime import datetime, timedelta
from typing import Any
from sqlalchemy import func, desc, text
from sqlalchemy.orm import Session
from app.models.entities import Alert, AuditLog, User, Asset
from app.services.workflow_constants import STATUS_FALSE_POSITIVE, TERMINAL_STATUSES, normalize_status

def format_duration(seconds: float | None) -> str:
    if seconds is None: return "0秒"
    if seconds < 60: return f"{int(seconds)}秒"
    mins = int(seconds // 60)
    if mins < 60: return f"{mins}分{int(seconds % 60)}秒"
    hours = mins // 60
    return f"{hours}小时{mins % 60}分"

def get_aggregate_stats(db: Session, workspace_id: int) -> dict[str, Any]:
    # 默认统计范围：今日 (UTC 0点开始)
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    
    # 1. 基础数量统计
    base_query = db.query(Alert).filter(Alert.workspace_id == workspace_id, Alert.created_at >= today_start)
    all_alerts = base_query.all()
    total_count = len(all_alerts)
    
    pending_count = sum(1 for a in all_alerts if normalize_status(a.status) not in TERMINAL_STATUSES)
    completed_count = sum(1 for a in all_alerts if normalize_status(a.status) in TERMINAL_STATUSES)
    fp_count = sum(1 for a in all_alerts if normalize_status(a.status) == STATUS_FALSE_POSITIVE)
    
    # 2. 比例计算
    disposal_rate = f"{(completed_count / total_count * 100):.1f}%" if total_count > 0 else "0.0%"
    fp_rate = f"{(fp_count / completed_count * 100):.1f}%" if completed_count > 0 else "0.0%"
    
    # 3. 资产命中率
    asset_hit_count = sum(1 for a in all_alerts if a.src_asset_context or a.dst_asset_context)
    asset_hit_rate = f"{(asset_hit_count / total_count * 100):.1f}%" if total_count > 0 else "0.0%"
    
    # 4. 高危占比
    high_sev_count = sum(1 for a in all_alerts if a.severity in {"high", "critical"})
    high_sev_rate = f"{(high_sev_count / total_count * 100):.1f}%" if total_count > 0 else "0.0%"

    # 5. MTTR 计算
    mttr_samples = []
    for a in all_alerts:
        if normalize_status(a.status) in TERMINAL_STATUSES:
            diff = (a.updated_at - a.created_at).total_seconds()
            if diff >= 0: mttr_samples.append(diff)
    
    avg_mttr = sum(mttr_samples) / len(mttr_samples) if mttr_samples else None
    
    # 6. 排行榜 (Top 5)
    def _get_top_5(column):
        rows = db.query(column, func.count(Alert.id).label('cnt'))\
            .filter(Alert.workspace_id == workspace_id, Alert.created_at >= today_start, column != "")\
            .group_by(column).order_by(desc('cnt')).limit(5).all()
        return rows

    top_src_rows = _get_top_5(Alert.source_ip)
    top_dst_rows = _get_top_5(Alert.destination_ip)

    res = {
        "当前总数": str(total_count),
        "待处理数": str(pending_count),
        "已办结数": str(completed_count),
        "当前处置率": disposal_rate,
        "误报率": fp_rate,
        "平均处置耗时": format_duration(avg_mttr),
        "资产命中率": asset_hit_rate,
        "高危告警占比": high_sev_rate,
        "今日新增总数": str(total_count),
        "当前日期": datetime.now().strftime("%Y-%m-%d"),
    }

    # 注入 Top 5 攻击源
    src_lines = []
    for i in range(5):
        val = top_src_rows[i][0] if i < len(top_src_rows) else "无"
        cnt = top_src_rows[i][1] if i < len(top_src_rows) else 0
        res[f"Top{i+1}_攻击源IP"] = val
        if val != "无":
            src_lines.append(f"{i+1}. {val} ({cnt}次)")
    res["Top5_攻击源排行"] = "\n".join(src_lines) if src_lines else "暂无数据"

    # 注入 Top 5 受攻击资产
    dst_lines = []
    for i in range(5):
        val = top_dst_rows[i][0] if i < len(top_dst_rows) else "无"
        cnt = top_dst_rows[i][1] if i < len(top_dst_rows) else 0
        res[f"Top{i+1}_受攻击资产"] = val
        if val != "无":
            dst_lines.append(f"{i+1}. {val} ({cnt}次)")
    res["Top5_受攻击资产排行"] = "\n".join(dst_lines) if dst_lines else "暂无数据"

    return res
