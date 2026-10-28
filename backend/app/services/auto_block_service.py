"""Queue and execute a single device block; never retry an uncertain network action."""

import hashlib
import json
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

from app.core.settings import get_settings
from app.core.timezone import now
from app.models.database import SessionLocal
from app.models.entities import Alert, Device, TaskRecord, User
from app.services.audit_service import write_audit
from app.services.workflow_service import transition_alert


def recover_interrupted_auto_blocks() -> None:
    with SessionLocal() as db:
        for task in db.query(TaskRecord).filter(TaskRecord.task_type == "block_ip", TaskRecord.status == "running").all():
            task.status = "failed"
            task.error = "执行器中断，设备状态未知；为避免重复封堵，不会自动重试，请人工核查"
            task.output = {"unknown": True}
        db.commit()


def claim_auto_block() -> int | None:
    with SessionLocal() as db:
        task = db.query(TaskRecord).filter(
            TaskRecord.task_type == "block_ip", TaskRecord.status == "queued",
        ).order_by(TaskRecord.id.asc()).with_for_update(skip_locked=True).first()
        if not task:
            return None
        task.status = "running"
        task.updated_at = now(db, task.workspace_id)
        task_id = task.id
        db.commit()
        return task_id


def _runner_call(script: str, ip: str, alert_id: int, device_id: int) -> dict:
    cfg = get_settings()
    request = Request(
        cfg.block_runner_url,
        data=json.dumps({"script": script, "ip": ip, "alert_id": alert_id, "device_id": device_id}).encode(),
        headers={"Content-Type": "application/json", "X-Block-Runner-Token": cfg.block_runner_token},
        method="POST",
    )
    try:
        with build_opener(ProxyHandler({})).open(request, timeout=18) as response:
            result = json.loads(response.read(8192))
    except (HTTPError, URLError, TimeoutError, ValueError) as exc:
        raise RuntimeError("联动执行器不可用或响应超时，设备状态未知，请人工核查") from exc
    if not isinstance(result, dict) or type(result.get("ok")) is not bool:
        raise RuntimeError("联动执行器返回无效结果，设备状态未知，请人工核查")
    return result


def _mark_failed(task_id: int, message: str, *, unknown: bool) -> None:
    with SessionLocal() as db:
        task = db.get(TaskRecord, task_id)
        if task:
            task.status = "failed"
            task.error = message[:1000]
            task.output = {"unknown": unknown}
            task.updated_at = now(db, task.workspace_id)
            actor = db.get(User, task.actor_id) if task.actor_id else None
            if actor:
                write_audit(db, actor, "alert.auto_block_failed", "alert", task.target_id,
                            {"task_id": task.id, "unknown": unknown, "error": task.error})
            db.commit()


def run_auto_block(task_id: int) -> None:
    with SessionLocal() as db:
        task = db.get(TaskRecord, task_id)
        if not task or task.status != "running":
            return
        actor = db.get(User, task.actor_id) if task.actor_id else None
        alert = db.get(Alert, int(task.target_id))
        device = db.get(Device, task.input.get("device_id"))
        ip = task.input.get("ip")
        invalid = not actor or not actor.is_active or not alert or not device or any((
            actor.workspace_id != task.workspace_id,
            alert.workspace_id != task.workspace_id,
            device.workspace_id != task.workspace_id,
            alert.status != "disposal",
            alert.assignee_id != actor.id,
            alert.disposal_action != "block",
            alert.disposal_ip != ip,
            device.device_role != "block",
            hashlib.sha256(device.block_script.encode()).hexdigest() != task.input.get("script_sha256"),
        ))
        if not invalid:
            script = device.block_script
            alert_id = alert.id
            device_id = device.id

    if invalid:
        _mark_failed(task_id, "告警、设备或脚本已变化，联动未执行；请人工核查", unknown=False)
        return

    try:
        result = _runner_call(script, ip, alert_id, device_id)
    except RuntimeError as exc:
        _mark_failed(task_id, str(exc), unknown=True)
        return
    if not result["ok"]:
        message = str(result.get("message") or "设备未确认封堵成功")[:500]
        unknown = bool(result.get("unknown"))
        _mark_failed(task_id, message, unknown=unknown)
        return

    try:
        with SessionLocal() as db:
            task = db.get(TaskRecord, task_id)
            actor = db.get(User, task.actor_id)
            alert = db.query(Alert).filter(Alert.id == alert_id, Alert.workspace_id == task.workspace_id).with_for_update().first()
            if not alert or alert.status != "disposal" or alert.assignee_id != actor.id or alert.disposal_ip != ip:
                raise RuntimeError("设备已返回成功，但告警状态已变化；请人工核查")
            transition_alert(db, actor, alert, target_status="disposed", block_device_ids=[device_id], block_at=now(db, task.workspace_id))
            task.status = "success"
            task.output = {"device_id": device_id, "ip": ip, "message": str(result.get("message", ""))[:500]}
            task.updated_at = now(db, task.workspace_id)
            write_audit(db, actor, "alert.auto_block_success", "alert", alert.id, {"task_id": task.id, "device_id": device_id, "ip": ip})
            db.commit()
    except Exception:
        _mark_failed(task_id, "设备已返回成功，但告警闭环失败；请人工核查，勿重复封堵", unknown=True)
        raise
