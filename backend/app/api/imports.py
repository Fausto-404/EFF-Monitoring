import json
from fastapi import APIRouter, Depends, UploadFile
from sqlalchemy.orm import Session

from app.api.deps import require_admin, require_not_viewer
from app.models.database import get_db
from app.models.entities import ParseRule, Setting, User
from app.services.alert_service import create_alert, find_duplicate_alert
from app.services.audit_service import write_audit

router = APIRouter(prefix="/import", tags=["import"])


@router.post("/config")
async def import_config(file: UploadFile, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    data = json.loads((await file.read()).decode("utf-8"))
    for key in ("ai", "providers", "webhook", "fields", "lists"):
        if key in data:
            row = db.query(Setting).filter_by(workspace_id=user.workspace_id, key=key).first()
            if not row:
                db.add(Setting(workspace_id=user.workspace_id, key=key, value=data[key]))
            else:
                row.value = data[key]
    regex = data.get("regex", {})
    for field, pats in (regex.get("five_tuple") or {}).items():
        for pattern in (pats if isinstance(pats, list) else [pats]):
            db.add(ParseRule(workspace_id=user.workspace_id, name=f"导入-{field}", field_key=field, pattern=str(pattern)))
    write_audit(db, user, "config.import", "setting", "import", {"keys": list(data.keys())})
    db.commit()
    return {"ok": True}


@router.post("/history")
async def import_history(file: UploadFile, db: Session = Depends(get_db), user: User = Depends(require_not_viewer)):
    data = json.loads((await file.read()).decode("utf-8"))
    count = 0
    skipped = 0
    alert_hashes = []
    for entry in data if isinstance(data, list) else []:
        parsed_fields = entry.get("parsed_data") or {}
        if find_duplicate_alert(db, user, parsed_fields, entry.get("device_id")):
            skipped += 1
            continue
        alert = create_alert(
            db,
            user,
            entry.get("raw_text") or "",
            parsed_fields,
            project_id=entry.get("project_id"),
            device_id=entry.get("device_id"),
            tags=["imported"],
            commit=False,
        )
        alert_hashes.append(alert.alert_hash)
        count += 1
    write_audit(db, user, "history.import", "alert", "import", {"created": count, "skipped": skipped, "alert_hashes": alert_hashes})
    db.commit()
    return {"ok": True, "count": count, "skipped": skipped}
