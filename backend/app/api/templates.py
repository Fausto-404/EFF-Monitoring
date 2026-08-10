from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import current_user, require_admin, require_not_viewer
from app.models.database import get_db
from app.models.entities import Device, Template, User
from app.schemas.common import TemplateCreate, TemplateOut, TemplateUpdate

router = APIRouter(prefix="/templates", tags=["templates"])


@router.get("", response_model=list[TemplateOut])
def list_templates(device_id: int | None = None, db: Session = Depends(get_db), user: User = Depends(current_user)):
    query = db.query(Template).filter_by(workspace_id=user.workspace_id)
    if device_id:
        query = query.filter((Template.device_id == device_id) | (Template.device_id.is_(None)))
    return query.order_by(Template.updated_at.desc()).all()


@router.post("", response_model=TemplateOut)
def create_template(payload: TemplateCreate, db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    exists = db.query(Template).filter(Template.workspace_id == user.workspace_id, Template.name == payload.name).first()
    if exists:
        raise HTTPException(status_code=400, detail="模板名称已存在")
    if payload.device_id:
        device = db.get(Device, payload.device_id)
        if not device or device.workspace_id != user.workspace_id:
            raise HTTPException(status_code=400, detail="设备不存在")
    tpl = Template(workspace_id=user.workspace_id, **payload.model_dump())
    if tpl.is_default:
        db.query(Template).filter_by(workspace_id=user.workspace_id, type=tpl.type).update({"is_default": False})
    db.add(tpl)
    db.commit()
    db.refresh(tpl)
    return tpl


@router.patch("/{template_id}", response_model=TemplateOut)
def update_template(template_id: int, payload: TemplateUpdate, db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    tpl = db.get(Template, template_id)
    if not tpl or tpl.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="模板不存在")
    if payload.name and payload.name != tpl.name:
        exists = db.query(Template).filter(Template.workspace_id == user.workspace_id, Template.name == payload.name, Template.id != tpl.id).first()
        if exists:
            raise HTTPException(status_code=400, detail="模板名称已存在")
    if payload.device_id:
        device = db.get(Device, payload.device_id)
        if not device or device.workspace_id != user.workspace_id:
            raise HTTPException(status_code=400, detail="设备不存在")
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(tpl, key, value)
    if tpl.is_default:
        db.query(Template).filter(Template.workspace_id == user.workspace_id, Template.type == tpl.type, Template.id != tpl.id).update({"is_default": False})
    db.commit()
    db.refresh(tpl)
    return tpl


@router.delete("/{template_id}")
def delete_template(template_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    tpl = db.get(Template, template_id)
    if not tpl or tpl.workspace_id != user.workspace_id:
        raise HTTPException(status_code=404, detail="模板不存在")
    db.delete(tpl)
    db.commit()
    return {"ok": True}
