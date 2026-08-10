from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import current_user, require_admin, require_not_viewer
from app.models.database import get_db
from app.models.entities import ParseRule, User
import re

from app.models.entities import Setting
from app.schemas.common import RegexTestRequest, RuleCreate, RuleGenerateRequest, RuleOut, RuleTestRequest, RuleUpdate
from app.services.ai_gateway import generate_regex, generate_match_regex
from app.services.parser_service import generate_candidate_rules, parse_text_for_user

router = APIRouter(prefix="/rules", tags=["rules"])


@router.get("", response_model=list[RuleOut])
def list_rules(db: Session = Depends(get_db), user: User = Depends(current_user)):
    return db.query(ParseRule).filter_by(workspace_id=user.workspace_id).order_by(ParseRule.priority.asc()).all()


@router.post("", response_model=RuleOut)
def create_rule(payload: RuleCreate, db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    exists = db.query(ParseRule).filter(ParseRule.workspace_id == user.workspace_id, ParseRule.name == payload.name).first()
    if exists:
        raise HTTPException(status_code=400, detail="规则名称已存在")
    rule = ParseRule(workspace_id=user.workspace_id, **payload.model_dump())
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


@router.patch("/{rule_id}", response_model=RuleOut)
def update_rule(rule_id: int, payload: RuleUpdate, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    rule = db.get(ParseRule, rule_id)
    if not rule or rule.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="规则不存在")

    data = payload.model_dump(exclude_unset=True)
    if rule.is_meta:
        # 元规则仅允许修改匹配规则和设备
        allowed = {"pattern", "device_id", "enabled", "priority", "sample_log"}
        data = {k: v for k, v in data.items() if k in allowed}
        if not data:
            return rule

    if "name" in data and data["name"] != rule.name:
        exists = db.query(ParseRule).filter(ParseRule.workspace_id == user.workspace_id, ParseRule.name == data["name"], ParseRule.id != rule.id).first()
        if exists:
            raise HTTPException(status_code=400, detail="规则名称已存在")

    for key, value in data.items():
        setattr(rule, key, value)
    db.commit()
    db.refresh(rule)
    return rule


@router.delete("/{rule_id}")
def delete_rule(rule_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    rule = db.get(ParseRule, rule_id)
    if not rule or rule.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="规则不存在")
    if rule.is_meta:
        raise HTTPException(status_code=400, detail="元规则不可删除")
    db.delete(rule)
    db.commit()
    return {"ok": True}


@router.post("/test")
def test_rules(payload: RuleTestRequest, db: Session = Depends(get_db), user: User = Depends(current_user)):
    return parse_text_for_user(db, user, payload.text, payload.device_id)


@router.post("/generate")
def generate_rules(payload: RuleGenerateRequest, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    if payload.mode == "ai":
        setting = db.query(Setting).filter_by(workspace_id=user.workspace_id, key="ai").first()
        regex = generate_regex(payload.sample_log, payload.field_name, setting.value if setting else {}, payload.expected_output)
        return {"regex": regex}
    
    # 规则匹配模式: 使用启发式前缀/后缀匹配
    regex = generate_match_regex(payload.sample_log, payload.field_name, payload.expected_output)
    return {"regex": regex}


@router.post("/regex-test")
def regex_test(payload: RegexTestRequest):
    try:
        pattern = re.compile(payload.regex, re.S)
    except re.error as exc:
        raise HTTPException(status_code=400, detail=f"正则表达式无效: {exc}") from exc
    values = []
    seen = set()
    for match in pattern.finditer(payload.sample_log):
        value = match.group(1) if match.groups() else match.group(0)
        if value not in seen:
            seen.add(value)
            values.append(value)
    return {"matches": values}
