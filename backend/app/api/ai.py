from typing import Any
import json

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sse_starlette.sse import EventSourceResponse

from app.api.deps import current_user, require_admin, require_not_viewer
from app.models.database import SessionLocal, get_db
from app.models.entities import AiConversation, AiExperience, AiMessage, AiPrompt, Alert, User
from app.schemas.common import (
    AiChatRequest,
    AiConversationCreate,
    AiConversationOut,
    AiExperienceCreate,
    AiExperienceExtractRequest,
    AiExperienceOut,
    AiExperienceUpdate,
    AiMessageOut,
    AiPromptCreate,
    AiPromptOut,
    AiPromptUpdate,
    TemplateAiGenerateRequest,
)
from app.services.ai_agent import stream_chat_agent, safe_sse_event
from app.services.ai_service import experience_from_ste, extract_ste_experience
from app.services.audit_service import write_audit

router = APIRouter(prefix="/ai", tags=["ai"])

PROMPT_KEYS = {"alert_analysis", "ste_extract", "evidence_extract", "template_generate", "chat", "regex_generate"}

# --- Prompt 职责分层定义 (Usage Metadata) ---
# 1. alert_analysis: 只用于告警研判文本/结构化结果生成。不负责查询工具。
# 2. ste_extract: 只用于从闭环告警提取 STE 候选经验。AI 生成经验默认应为 draft 状态。
# 3. evidence_extract: 只用于证据提取或特定字段抽取逻辑。
# 4. template_generate: 只用于在已知变量目录和模板规则证据下生成模板。严禁编造变量。
# 5. chat: 只用于 Agent 最终回答的语言风格、语气和格式组织。不负责工具规划。
# 6. regex_generate: 只用于内容解析规则或正则辅助生成。

EXPERIENCE_STATUSES = {"draft", "pending_generation", "pending_publish", "published", "archived"}


def _experience_dict(row: AiExperience | None) -> dict[str, Any] | None:
    if not row:
        return None
    return {
        "id": row.id,
        "knowledge_id": row.knowledge_id,
        "source_alert_id": row.source_alert_id,
        "alert_hash": row.alert_hash,
        "title": row.title,
        "tags": row.tags or [],
        "index_data": row.index_data or {},
        "ste": row.ste or {},
        "action": row.action or {},
        "quality": row.quality or {},
        "status": row.status,
        "created_by_id": row.created_by_id,
        "updated_by_id": row.updated_by_id,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


@router.get("/prompts", response_model=list[AiPromptOut])
def list_prompts(prompt_key: str | None = None, db: Session = Depends(get_db), user: User = Depends(current_user)):
    query = db.query(AiPrompt).filter_by(workspace_id=user.workspace_id)
    if prompt_key:
        query = query.filter(AiPrompt.prompt_key == prompt_key)
    return query.order_by(AiPrompt.prompt_key.asc(), AiPrompt.updated_at.desc()).all()


@router.post("/prompts", response_model=AiPromptOut)
def create_prompt(payload: AiPromptCreate, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    if payload.prompt_key not in PROMPT_KEYS:
        raise HTTPException(status_code=400, detail="不支持的提示词类型")
    exists = db.query(AiPrompt).filter_by(workspace_id=user.workspace_id, prompt_key=payload.prompt_key, name=payload.name).first()
    if exists:
        raise HTTPException(status_code=409, detail="同类型下提示词名称已存在")
    if payload.is_default:
        db.query(AiPrompt).filter_by(workspace_id=user.workspace_id, prompt_key=payload.prompt_key).update({"is_default": False})
    row = AiPrompt(workspace_id=user.workspace_id, created_by_id=user.id, updated_by_id=user.id, **payload.model_dump())
    db.add(row)
    db.flush()
    write_audit(db, user, "ai_prompt.create", "ai_prompt", row.id, {"prompt_key": row.prompt_key, "name": row.name})
    db.commit()
    db.refresh(row)
    return row


@router.patch("/prompts/{prompt_id}", response_model=AiPromptOut)
def update_prompt(prompt_id: int, payload: AiPromptUpdate, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    row = db.get(AiPrompt, prompt_id)
    if not row or row.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="提示词不存在")
    data = payload.model_dump(exclude_unset=True)
    if data.get("prompt_key") and data["prompt_key"] not in PROMPT_KEYS:
        raise HTTPException(status_code=400, detail="不支持的提示词类型")
    if data.get("is_default"):
        db.query(AiPrompt).filter(AiPrompt.workspace_id == user.workspace_id, AiPrompt.prompt_key == data.get("prompt_key", row.prompt_key), AiPrompt.id != row.id).update({"is_default": False})
    for key, value in data.items():
        setattr(row, key, value)
    row.updated_by_id = user.id
    write_audit(db, user, "ai_prompt.update", "ai_prompt", row.id, {"prompt_key": row.prompt_key, "name": row.name, "fields": list(data.keys())})
    db.commit()
    db.refresh(row)
    return row


@router.delete("/prompts/{prompt_id}")
def delete_prompt(prompt_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    row = db.get(AiPrompt, prompt_id)
    if not row or row.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="提示词不存在")
    write_audit(db, user, "ai_prompt.delete", "ai_prompt", row.id, {"prompt_key": row.prompt_key, "name": row.name})
    db.delete(row)
    db.commit()
    return {"ok": True}


@router.get("/experiences", response_model=list[AiExperienceOut])
def list_experiences(
    q: str | None = None,
    status: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    query = db.query(AiExperience).filter_by(workspace_id=user.workspace_id)
    if user.role in {"monitor", "viewer"}:
        query = query.filter(AiExperience.status == "published")
    elif status:
        query = query.filter(AiExperience.status == status)
    if q:
        like = f"%{q}%"
        query = query.filter((AiExperience.knowledge_id.like(like)) | (AiExperience.alert_hash.like(like)) | (AiExperience.title.like(like)))
    return query.order_by(AiExperience.updated_at.desc()).limit(limit).all()


@router.post("/experiences/{experience_id}/generate", response_model=AiExperienceOut)
def generate_experience_content(experience_id: int, db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    row = db.get(AiExperience, experience_id)
    if not row or row.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="经验记录不存在")

    alert = db.get(Alert, row.source_alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="原始告警已不存在，无法生成经验")

    from app.services.ai_service import extract_ste_experience
    ste_data = extract_ste_experience(db, user, alert)

    row.title = ste_data.get("meta", {}).get("title") or row.title
    row.tags = ste_data.get("meta", {}).get("tags") or row.tags
    row.index_data = ste_data.get("index") or {}
    row.ste = ste_data.get("ste") or {}
    row.action = ste_data.get("action") or {}
    row.quality = ste_data.get("quality") or {}
    row.status = "pending_publish"
    row.updated_by_id = user.id

    db.commit()
    db.refresh(row)
    return row


@router.post("/experiences/batch-generate")
def batch_generate_experiences(payload: dict[str, Any], db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    ids = payload.get("ids", [])
    updated = 0
    errors = []

    from app.services.ai_service import extract_ste_experience
    for eid in ids:
        row = db.get(AiExperience, eid)
        if not row or row.workspace_id != user.workspace_id: continue
        alert = db.get(Alert, row.source_alert_id)
        if not alert:
            errors.append({"id": eid, "error": "告警缺失"})
            continue
        try:
            ste_data = extract_ste_experience(db, user, alert)
            row.title = ste_data.get("meta", {}).get("title") or row.title
            row.tags = ste_data.get("meta", {}).get("tags") or row.tags
            row.index_data = ste_data.get("index") or {}
            row.ste = ste_data.get("ste") or {}
            row.action = ste_data.get("action") or {}
            row.quality = ste_data.get("quality") or {}
            row.status = "pending_publish"
            row.updated_by_id = user.id
            updated += 1
        except Exception as e:
            errors.append({"id": eid, "error": str(e)})

    db.commit()
    return {"updated": updated, "errors": errors}


@router.post("/experiences/batch-publish")
def batch_publish_experiences(payload: dict[str, Any], db: Session = Depends(get_db), user: User = Depends(require_admin)):
    ids = payload.get("ids", [])
    rows = db.query(AiExperience).filter(AiExperience.id.in_(ids), AiExperience.workspace_id == user.workspace_id).all()
    for row in rows:
        if row.status == "pending_publish":
            row.status = "published"
            row.updated_by_id = user.id
    db.commit()
    return {"updated": len(rows)}


@router.post("/experiences/batch-delete")
def batch_delete_experiences(payload: dict[str, Any], db: Session = Depends(get_db), user: User = Depends(require_admin)):
    ids = payload.get("ids", [])
    rows = db.query(AiExperience).filter(AiExperience.id.in_(ids), AiExperience.workspace_id == user.workspace_id).all()
    for row in rows:
        db.delete(row)
    db.commit()
    return {"deleted": len(rows)}


@router.post("/experiences", response_model=AiExperienceOut)
def create_experience(payload: AiExperienceCreate, db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    if payload.status not in EXPERIENCE_STATUSES:
        raise HTTPException(status_code=400, detail="不支持的经验状态")
    row = AiExperience(workspace_id=user.workspace_id, created_by_id=user.id, updated_by_id=user.id, **payload.model_dump())
    db.add(row)
    db.flush()
    write_audit(db, user, "ai_experience.create", "ai_experience", row.id, {"knowledge_id": row.knowledge_id, "title": row.title})
    db.commit()
    db.refresh(row)
    return row


@router.patch("/experiences/{experience_id}", response_model=AiExperienceOut)
def update_experience(experience_id: int, payload: AiExperienceUpdate, db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    row = db.get(AiExperience, experience_id)
    if not row or row.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="经验不存在")
    if user.role not in {"admin", "analyst", "disposer"} and row.created_by_id != user.id:
        raise HTTPException(status_code=403, detail="无权修改该经验")
    data = payload.model_dump(exclude_unset=True)
    if data.get("status") and data["status"] not in EXPERIENCE_STATUSES:
        raise HTTPException(status_code=400, detail="不支持的经验状态")
    for key, value in data.items():
        setattr(row, key, value)
    row.updated_by_id = user.id
    write_audit(db, user, "ai_experience.update", "ai_experience", row.id, {"knowledge_id": row.knowledge_id, "fields": list(data.keys())})
    db.commit()
    db.refresh(row)
    return row


@router.post("/experiences/{experience_id}/publish", response_model=AiExperienceOut)
def publish_experience(experience_id: int, db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    row = db.get(AiExperience, experience_id)
    if not row or row.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="经验不存在")
    if user.role not in {"admin", "analyst"}:
        raise HTTPException(status_code=403, detail="只有管理员或研判组可发布经验")
    row.status = "published"
    row.updated_by_id = user.id
    write_audit(db, user, "ai_experience.publish", "ai_experience", row.id, {"knowledge_id": row.knowledge_id})
    db.commit()
    db.refresh(row)
    return row


@router.delete("/experiences/{experience_id}")
def delete_experience(experience_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    row = db.get(AiExperience, experience_id)
    if not row or row.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="经验不存在")
    write_audit(db, user, "ai_experience.delete", "ai_experience", row.id, {"knowledge_id": row.knowledge_id, "title": row.title})
    db.delete(row)
    db.commit()
    return {"ok": True}


@router.post("/test-connection")
def test_ai_connection(payload: dict[str, Any], db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    """
    测试 AI 服务商连接性
    """
    from app.services.ai_gateway import chat_completion
    try:
        messages = [{"role": "user", "content": "Hello, are you ready?"}]
        response = chat_completion(messages, payload, timeout=20)
        return {"ok": True, "response": response}
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"连接测试失败: {str(e)}")


@router.post("/models")
def list_ai_models(payload: dict[str, Any], db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    """
    从服务商处获取可用的模型列表
    """
    from app.services.ai_gateway import fetch_models
    models = fetch_models(payload)
    return {"models": models}


@router.post("/template-generate")
def generate_template(payload: TemplateAiGenerateRequest, db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    from app.services.ai_service import generate_template_suggestion
    try:
        result = generate_template_suggestion(db, user, payload)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"生成失败：{str(e)}")


@router.post("/experiences/extract")
def extract_experience(payload: AiExperienceExtractRequest, db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    alert = db.get(Alert, payload.alert_id)
    if not alert or alert.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="告警不存在")
    from app.services.ai_service import extract_ste_experience, experience_from_ste
    data = extract_ste_experience(db, user, alert)
    row = None
    if payload.save or payload.publish:
        status = "draft"
        if payload.publish:
            if user.role in {"admin", "analyst"}:
                status = "published"
            else:
                status = "pending_publish" # 普通用户申请发布，进入待审核
        
        row = experience_from_ste(db, user, alert, data, status)
        write_audit(db, user, "ai_experience.extract", "alert", alert.id, {"alert_hash": alert.alert_hash, "knowledge_id": row.knowledge_id, "saved": True, "status": row.status})
        db.commit()
        db.refresh(row)
    else:
        write_audit(db, user, "ai_experience.extract", "alert", alert.id, {"alert_hash": alert.alert_hash, "saved": False})
        db.commit()
    return {"experience": _experience_dict(row), "ste": data}


@router.get("/conversations", response_model=list[AiConversationOut])
def list_conversations(db: Session = Depends(get_db), user: User = Depends(current_user)):
    query = db.query(AiConversation).filter_by(workspace_id=user.workspace_id)
    if user.role != "admin":
        query = query.filter(AiConversation.created_by_id == user.id)
    return query.order_by(AiConversation.updated_at.desc()).limit(100).all()


@router.post("/conversations", response_model=AiConversationOut)
def create_conversation(payload: AiConversationCreate, db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    row = AiConversation(workspace_id=user.workspace_id, title=payload.title or "新的对话", created_by_id=user.id)
    db.add(row)
    db.flush()
    write_audit(db, user, "ai_chat.create", "ai_conversation", row.id, {"title": row.title})
    db.commit()
    db.refresh(row)
    return row


def _get_conversation(db: Session, user: User, conversation_id: int) -> AiConversation:
    row = db.get(AiConversation, conversation_id)
    if not row or row.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="对话不存在")
    if user.role != "admin" and row.created_by_id != user.id:
        raise HTTPException(status_code=403, detail="无权访问该对话")
    return row


@router.get("/conversations/{conversation_id}/messages", response_model=list[AiMessageOut])
def list_conversation_messages(conversation_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    _get_conversation(db, user, conversation_id)
    return db.query(AiMessage).filter_by(workspace_id=user.workspace_id, conversation_id=conversation_id).order_by(AiMessage.created_at.asc()).all()


@router.delete("/conversations/{conversation_id}")
def delete_conversation(conversation_id: int, db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    row = _get_conversation(db, user, conversation_id)
    write_audit(db, user, "ai_chat.delete", "ai_conversation", row.id, {"title": row.title})
    db.delete(row)
    db.commit()
    return {"ok": True}


@router.post("/conversations/{conversation_id}/messages")
async def send_chat_message(conversation_id: int, payload: AiChatRequest, db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    conv = _get_conversation(db, user, conversation_id)
    
    # 立即保存用户消息
    user_msg = AiMessage(workspace_id=user.workspace_id, conversation_id=conv.id, role="user", content=payload.content, created_by_id=user.id)
    db.add(user_msg)
    db.commit()

    # 预先提取基础变量
    conv_id = conv.id
    user_id = user.id
    workspace_id = user.workspace_id

    async def event_generator():
        from app.models.database import SessionLocal
        stream_db = SessionLocal()
        try:
            from app.models.entities import User as EntityUser
            stream_user = stream_db.get(EntityUser, user_id)
            
            final_answer = ""
            full_trace = []
            evidences = []
            
            async for raw_data in stream_chat_agent(stream_db, stream_user, conv_id, payload.content):
                data = json.loads(raw_data)
                if data["event"] == "trace":
                    full_trace.append(data["data"])
                elif data["event"] == "evidences":
                    evidences = data["data"]
                elif data["event"] == "final_answer":
                    final_answer = data["data"]
                yield raw_data

            # 保存 AI 最终消息
            if final_answer:
                ai_msg = AiMessage(
                    workspace_id=workspace_id,
                    conversation_id=conv_id,
                    role="assistant",
                    content=final_answer,
                    tool_calls=[
                        {"tool": "agent_trace", "data": full_trace},
                        {"tool": "agent_evidences", "data": evidences}
                    ],
                    created_by_id=user_id
                )
                stream_db.add(ai_msg)
                conv_row = stream_db.get(AiConversation, conv_id)
                if conv_row:
                    conv_row.title = conv_row.title if conv_row.title != "新的对话" else payload.content[:40]
                stream_db.commit()
            
            ev = safe_sse_event("completion", "done")
            if ev: yield ev
        finally:
            stream_db.close()

    return EventSourceResponse(event_generator())
