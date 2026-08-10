from __future__ import annotations

import json
import uuid
from typing import Any

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models.entities import Asset, AssetSegment

VALID_CRITICALITIES = {"low", "medium", "high", "critical"}


def lookup_asset_by_segment(db: Session, workspace_id: int, ip: str | None) -> AssetSegment | None:
    from core.lists import is_ip_in_list
    value = (ip or "").strip()
    if not value:
        return None
    
    # 获取该工作区所有的网段定义
    segments = db.query(AssetSegment).filter(AssetSegment.workspace_id == workspace_id).all()
    for seg in segments:
        # 复用 core.lists 中的范围检测逻辑
        if is_ip_in_list(value, [seg.segment]):
            return seg
    return None


def build_segment_context(seg: AssetSegment | None) -> dict[str, Any]:
    if not seg:
        return {}
    return {
        "id": f"seg-{seg.id}",
        "ip": seg.segment,
        "name": f"[网段] {seg.name}",
        "area": seg.area,
        "owner": seg.owner,
        "department": seg.department,
        "criticality": seg.criticality,
        "environment": seg.environment,
        "tags": ["网段匹配"],
        "fingerprints": {},
        "description": seg.description,
        "is_segment": True
    }


def normalize_asset_payload(data: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(data)
    for key in ("ip", "domain", "name", "area", "owner", "department", "criticality", "environment", "description"):
        if key in normalized:
            normalized[key] = str(normalized.get(key) or "").strip()

    if not normalized.get("ip") and not normalized.get("domain"):
        raise HTTPException(status_code=400, detail="IP 和域名至少填写一个")

    criticality = normalized.get("criticality") or "medium"
    if criticality not in VALID_CRITICALITIES:
        raise HTTPException(status_code=400, detail="资产重要性必须是 low / medium / high / critical")
    normalized["criticality"] = criticality

    tags = normalized.get("tags") or []
    if isinstance(tags, str):
        tags = [item.strip() for item in tags.replace("，", ",").split(",") if item.strip()]
    normalized["tags"] = list(dict.fromkeys(str(item).strip() for item in tags if str(item).strip()))

    fingerprints = normalized.get("fingerprints") or {}
    normalized["fingerprints"] = fingerprints if isinstance(fingerprints, dict) else {}
    return normalized


def make_asset_key(workspace_id: int) -> str:
    return f"asset-{workspace_id}-{uuid.uuid4().hex[:12]}"


def find_duplicate_asset(db: Session, workspace_id: int, ip: str = "", domain: str = "", exclude_id: int | None = None) -> Asset | None:
    ip = (ip or "").strip()
    domain = (domain or "").strip()
    query = db.query(Asset).filter(Asset.workspace_id == workspace_id)
    if exclude_id:
        query = query.filter(Asset.id != exclude_id)
    if ip and domain:
        query = query.filter(Asset.ip == ip, Asset.domain == domain)
    elif ip:
        query = query.filter(Asset.ip == ip, Asset.domain == "")
    elif domain:
        query = query.filter(Asset.ip == "", Asset.domain == domain)
    else:
        return None
    return query.first()


def build_asset_context(asset: Asset | None) -> dict[str, Any]:
    if not asset:
        return {}
    return {
        "id": asset.id,
        "ip": asset.ip,
        "domain": asset.domain,
        "name": asset.name,
        "area": asset.area,
        "owner": asset.owner,
        "department": asset.department,
        "criticality": asset.criticality,
        "environment": asset.environment,
        "tags": asset.tags or [],
        "fingerprints": asset.fingerprints or {},
        "description": asset.description,
    }


def lookup_asset_by_ip(db: Session, workspace_id: int, ip: str | None) -> Asset | None:
    value = (ip or "").strip()
    if not value:
        return None
    return db.query(Asset).filter(Asset.workspace_id == workspace_id, Asset.ip == value).order_by(Asset.updated_at.desc()).first()


def lookup_asset_by_domain(db: Session, workspace_id: int, domain: str | None) -> Asset | None:
    value = (domain or "").strip()
    if not value:
        return None
    return db.query(Asset).filter(Asset.workspace_id == workspace_id, Asset.domain == value).order_by(Asset.updated_at.desc()).first()


def asset_summary_fields(prefix: str, context: dict[str, Any]) -> dict[str, Any]:
    fingerprints = context.get("fingerprints") or {}
    return {
        f"{prefix}_asset_name": context.get("name", ""),
        f"{prefix}_asset_area": context.get("area", ""),
        f"{prefix}_asset_owner": context.get("owner", ""),
        f"{prefix}_asset_criticality": context.get("criticality", ""),
        f"{prefix}_asset_environment": context.get("environment", ""),
        f"{prefix}_asset_fingerprints": json.dumps(fingerprints, ensure_ascii=False) if fingerprints else "",
    }
