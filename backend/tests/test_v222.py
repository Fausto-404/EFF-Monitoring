"""Focused regression checks for the v2.2.2 list, backup and IP workflow."""

import json
import hashlib
import os
import tempfile
import unittest
import uuid
from datetime import datetime
from unittest.mock import patch

_test_directory = tempfile.TemporaryDirectory(prefix="eff-v222-smoke-")
os.environ["DATABASE_URL"] = f"sqlite:///{_test_directory.name}/smoke.db"
os.environ["BACKUP_DIR"] = f"{_test_directory.name}/backups"
os.environ.setdefault("JWT_SECRET", "v222-test-only-secret")
os.environ.setdefault("INITIAL_ADMIN_PASSWORD", "v222-test-only-password")
os.environ.setdefault("BLOCK_RUNNER_TOKEN", "v222-test-only-runner-token-long-enough")

from fastapi.testclient import TestClient

from app.block_runner import app as runner_app
from app.core.security import create_access_token
from app.main import create_app
from app.models.database import Base, SessionLocal, engine
from app.models.entities import Alert, AuditLog, BackupJob, Device, Message, PluginAccessToken, TaskRecord, User, Workspace
from app.services.auto_block_service import claim_auto_block, run_auto_block
from app.services.backup_job_service import backup_path, claim_backup_job, run_backup_job
from app.services.ip_list_service import add_to_whitelist, block_ip, get_ip_list_setting


class V222SmokeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)
        with SessionLocal() as db:
            workspace = Workspace(name="v222-smoke")
            db.add(workspace)
            db.flush()
            user = User(
                workspace_id=workspace.id, username="v222-smoke-admin",
                display_name="Smoke Admin", password_hash="test-only",
                role="admin", roles=["admin"], is_active=True,
            )
            db.add(user)
            db.flush()
            alert = Alert(
                workspace_id=workspace.id, raw_text="test raw log " * 1000,
                parsed_fields={"src_ip": "192.0.2.10", "data": "x" * 100000},
                source_ip="192.0.2.10", event_type="smoke test",
                created_by_id=user.id,
            )
            db.add(alert)
            db.commit()
            cls.user_id = user.id
            cls.alert_id = alert.id
        cls.client = TestClient(create_app())
        cls.headers = {"Authorization": f"Bearer {create_access_token(str(cls.user_id))}"}

    def test_light_list_and_detail(self):
        response = self.client.get("/api/alerts?limit=50", headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text[:300])
        row = next(item for item in response.json() if item["id"] == self.alert_id)
        self.assertNotIn("raw_text", row)
        self.assertNotIn("parsed_fields", row)
        self.assertTrue(row["alert_code"])
        self.assertLess(len(response.content), 4096)
        detail = self.client.get(f"/api/alerts/{self.alert_id}", headers=self.headers)
        self.assertEqual(detail.status_code, 200, detail.text[:300])
        self.assertIn("test raw log", detail.json()["raw_text"])
        self.assertGreater(len(detail.content), 100000)

    def test_whitelist_block_keeps_label(self):
        with SessionLocal() as db:
            user = db.get(User, self.user_id)
            alert = db.get(Alert, self.alert_id)
            add_to_whitelist(db, user, "192.0.2.0/24")
            before_messages = db.query(Message).count()
            first = block_ip(db, user, "192.0.2.10", alert=alert, reason="smoke")
            second = block_ip(db, user, "192.0.2.10", alert=alert, reason="smoke")
            ordinary = block_ip(db, user, "198.51.100.20", alert=alert, reason="smoke")
            db.commit()
            value = get_ip_list_setting(db, user.workspace_id).value
            self.assertEqual(value["whitelist"], ["192.0.2.0/24"])
            self.assertEqual(value["blacklist"], ["198.51.100.20"])
            self.assertEqual(value["pending_hosts"], ["192.0.2.10"])
            self.assertTrue(first["created"])
            self.assertFalse(second["created"])
            self.assertTrue(ordinary["blocked"])
            recipients = db.query(User).filter_by(workspace_id=user.workspace_id, is_active=True).count()
            self.assertEqual(db.query(Message).count() - before_messages, recipients)
            self.assertIn("疑似失陷", db.query(Message).order_by(Message.id.desc()).first().title)

    def test_z_auto_block_success_and_no_retry_on_failure(self):
        created = self.client.post("/api/devices", json={"name": "v222-script-test-device", "device_role": "block"}, headers=self.headers)
        self.assertEqual(created.status_code, 200, created.text[:300])
        device_id = created.json()["id"]
        script = 'import json, sys\nrequest = json.load(sys.stdin)\nprint(json.dumps({"ok": True, "message": request["ip"]}))'
        saved = self.client.put(f"/api/devices/{device_id}/block-script", json={"script": script}, headers=self.headers)
        self.assertEqual(saved.status_code, 200, saved.text[:300])
        device_row = next(row for row in self.client.get("/api/devices", headers=self.headers).json() if row["id"] == device_id)
        self.assertTrue(device_row["has_block_script"])
        self.assertNotIn("block_script", device_row)
        with SessionLocal() as db:
            admin = db.get(User, self.user_id)
            viewer = User(workspace_id=admin.workspace_id, username="v222-script-viewer",
                          display_name="Script Viewer", password_hash="test-only",
                          role="viewer", roles=["viewer"], is_active=True)
            db.add(viewer)
            db.commit()
            viewer_headers = {"Authorization": f"Bearer {create_access_token(str(viewer.id))}"}
        self.assertEqual(self.client.get(f"/api/devices/{device_id}/block-script", headers=viewer_headers).status_code, 403)
        self.assertEqual(self.client.put(f"/api/devices/{device_id}/block-script", json={"script": script}, headers=viewer_headers).status_code, 403)
        bad_script = self.client.put(f"/api/devices/{device_id}/block-script", json={"script": "def broken("}, headers=self.headers)
        self.assertEqual(bad_script.status_code, 400)

        def create_disposal_alert(ip: str) -> int:
            with SessionLocal() as db:
                actor = db.get(User, self.user_id)
                alert = Alert(
                    workspace_id=actor.workspace_id, raw_text="script test", source_ip=ip,
                    status="disposal", current_group="disposal", disposal_target="src_ip",
                    disposal_action="block", disposal_ip=ip, assignee_id=actor.id,
                    claimed_at=datetime.utcnow(), created_by_id=actor.id,
                )
                db.add(alert)
                db.commit()
                return alert.id

        success_alert_id = create_disposal_alert("192.0.2.55")
        queued = self.client.post(f"/api/alerts/{success_alert_id}/auto-block", json={"device_id": device_id}, headers=self.headers)
        self.assertEqual(queued.status_code, 202, queued.text[:300])
        task_id = queued.json()["task_id"]
        self.assertEqual(self.client.delete(f"/api/tasks/{task_id}", headers=self.headers).status_code, 409)
        self.assertEqual(self.client.post("/api/tasks/batch-delete", json={"ids": [task_id]}, headers=self.headers).status_code, 409)
        with SessionLocal() as db:
            self.assertEqual(db.get(Alert, success_alert_id).status, "disposal")
        self.assertEqual(claim_auto_block(), task_id)
        with patch("app.services.auto_block_service._runner_call", return_value={"ok": True, "unknown": False, "message": "simulated"}):
            run_auto_block(task_id)
        with SessionLocal() as db:
            alert = db.get(Alert, success_alert_id)
            self.assertEqual(alert.status, "disposed")
            self.assertEqual(alert.block_device_ids, [device_id])
            self.assertEqual(db.get(TaskRecord, task_id).status, "success")

        failed_alert_id = create_disposal_alert("192.0.2.56")
        failed = self.client.post(f"/api/alerts/{failed_alert_id}/auto-block", json={"device_id": device_id}, headers=self.headers)
        self.assertEqual(failed.status_code, 202, failed.text[:300])
        failed_task_id = failed.json()["task_id"]
        self.assertEqual(claim_auto_block(), failed_task_id)
        with patch("app.services.auto_block_service._runner_call", return_value={"ok": False, "unknown": False, "message": "device rejected"}):
            run_auto_block(failed_task_id)
        with SessionLocal() as db:
            self.assertEqual(db.get(Alert, failed_alert_id).status, "disposal")
            self.assertEqual(db.get(TaskRecord, failed_task_id).status, "failed")
        self.assertEqual(self.client.post(f"/api/alerts/{failed_alert_id}/auto-block", json={"device_id": device_id}, headers=self.headers).status_code, 409)
        latest = self.client.get(f"/api/alerts/{failed_alert_id}/auto-block/latest", headers=self.headers)
        self.assertEqual(latest.json()["status"], "failed")

    def test_z_runner_contract(self):
        client = TestClient(runner_app)
        payload = {"script": 'import json, sys\nprint(json.dumps({"ok": json.load(sys.stdin)["ip"] == "192.0.2.10"}))',
                   "ip": "192.0.2.10", "alert_id": 1, "device_id": 2}
        self.assertEqual(client.post("/run", json=payload).status_code, 403)
        headers = {"X-Block-Runner-Token": os.environ["BLOCK_RUNNER_TOKEN"]}
        response = client.post("/run", json=payload, headers=headers)
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertTrue(response.json()["ok"])
        self.assertEqual(client.post("/run", json={**payload, "ip": "not-ip"}, headers=headers).status_code, 400)
        uncertain = client.post("/run", json={**payload, "script": 'import json\nprint(json.dumps({"ok": False, "unknown": True, "message": "pending"}))'}, headers=headers)
        self.assertEqual(uncertain.status_code, 200)
        self.assertTrue(uncertain.json()["unknown"])
        with patch.dict(os.environ, {"BLOCK_DEVICE_TOKENS_JSON": '{"2":"per-device-test"}'}):
            per_device = client.post("/run", json={**payload, "script": 'import json,os\nprint(json.dumps({"ok": os.environ["BLOCK_DEVICE_TOKEN"] == "per-device-test"}))'}, headers=headers)
        self.assertTrue(per_device.json()["ok"])

    def test_plugin_ticket_permissions_and_idempotency(self):
        limited = self.client.post("/api/plugin/tokens", json={"name": "limited", "scopes": ["plugin:devices:read", "plugin:parse"]}, headers=self.headers)
        self.assertEqual(limited.status_code, 200, limited.text[:300])
        limited_headers = {"Authorization": f"Bearer {limited.json()['token']}"}
        me = self.client.get("/api/plugin/me", headers=limited_headers)
        self.assertEqual(me.status_code, 200)
        self.assertFalse(me.json()["capabilities"]["ticket_creation"])
        self.assertEqual(self.client.post("/api/plugin/alerts", json={"text": "test"}, headers=limited_headers).status_code, 403)

        issued = self.client.post("/api/plugin/tokens", json={"name": "ticket", "scopes": ["plugin:devices:read", "plugin:parse", "plugin:alert:create"]}, headers=self.headers)
        self.assertEqual(issued.status_code, 200, issued.text[:300])
        plugin_headers = {"Authorization": f"Bearer {issued.json()['token']}"}
        self.assertTrue(self.client.get("/api/plugin/me", headers=plugin_headers).json()["capabilities"]["ticket_creation"])
        request_id = str(uuid.uuid4())
        body = {"request_id": request_id, "text": "source ip 192.0.2.77 destination ip 198.51.100.77 test event"}
        first = self.client.post("/api/plugin/alerts", json=body, headers=plugin_headers)
        self.assertEqual(first.status_code, 200, first.text[:300])
        self.assertEqual(first.json()["workbench_url"], f"/?page=alerts&alert_hash={first.json()['alert_hash']}")
        repeated = self.client.post("/api/plugin/alerts", json=body, headers=plugin_headers)
        self.assertEqual(repeated.status_code, 200, repeated.text[:300])
        self.assertEqual(first.json()["alert_id"], repeated.json()["alert_id"])
        changed = self.client.post("/api/plugin/alerts", json={**body, "text": "different event"}, headers=plugin_headers)
        self.assertEqual(changed.status_code, 409)
        with SessionLocal() as db:
            self.assertEqual(db.query(Alert).filter(Alert.id == first.json()["alert_id"]).count(), 1)
        self.assertEqual(self.client.post("/api/plugin/alerts", json={"text": ""}, headers=plugin_headers).status_code, 400)
        self.assertEqual(self.client.post("/api/plugin/alerts", json={"text": "x" * (512 * 1024 + 1)}, headers=plugin_headers).status_code, 413)
        self.assertEqual(self.client.post("/api/plugin/alerts", json={"request_id": "not-a-uuid", "text": "test"}, headers=plugin_headers).status_code, 400)
        with SessionLocal() as db:
            row = db.query(PluginAccessToken).filter_by(token_hash=hashlib.sha256(issued.json()["token"].encode()).hexdigest()).one()
            row.revoked_at = datetime.utcnow()
            db.commit()
        self.assertEqual(self.client.get("/api/plugin/me", headers=plugin_headers).status_code, 401)
        self.assertEqual(self.client.post("/api/plugin/alerts", json=body, headers=plugin_headers).status_code, 401)

        with SessionLocal() as db:
            viewer = User(
                workspace_id=db.get(User, self.user_id).workspace_id, username=f"viewer-{uuid.uuid4().hex}",
                display_name="Read only", password_hash="test-only", role="viewer", roles=["viewer"], is_active=True,
            )
            db.add(viewer)
            db.commit()
            viewer_id = viewer.id
        viewer_headers = {"Authorization": f"Bearer {create_access_token(str(viewer_id))}"}
        self.assertFalse(self.client.get("/api/plugin/me", headers=viewer_headers).json()["capabilities"]["ticket_creation"])
        self.assertEqual(self.client.post("/api/plugin/alerts", json=body, headers=viewer_headers).status_code, 403)
        self.assertEqual(self.client.post("/api/plugin/tokens", json={"name": "viewer"}, headers=viewer_headers).status_code, 403)

    def test_background_backup(self):
        response = self.client.post("/api/backup/jobs", headers=self.headers)
        self.assertEqual(response.status_code, 202, response.text[:300])
        job_id = response.json()["id"]
        self.assertEqual(claim_backup_job(), job_id)
        run_backup_job(job_id)
        with SessionLocal() as db:
            job = db.get(BackupJob, job_id)
            self.assertEqual(job.status, "success", job.error)
            self.assertEqual(job.processed_rows, job.total_rows)
        with backup_path(job_id).open(encoding="utf-8") as file:
            payload = json.load(file)
        self.assertEqual(payload["format"], "eff-monitoring.backup.v1")
        self.assertEqual(len(payload["tables"]["alerts"]), 1)
        ticket = self.client.post(f"/api/backup/jobs/{job_id}/ticket", headers=self.headers)
        self.assertEqual(ticket.status_code, 200, ticket.text[:300])
        download = self.client.get(f"/api/backup/jobs/{job_id}/download", params=ticket.json())
        self.assertEqual(download.status_code, 200)

    def test_backup_job_management(self):
        created = self.client.post("/api/backup/jobs", headers=self.headers)
        self.assertEqual(created.status_code, 202, created.text[:300])
        job_id = created.json()["id"]
        listing = self.client.get("/api/backup/jobs", params={"limit": 1, "offset": 0}, headers=self.headers)
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(listing.json()["items"][0]["id"], job_id)
        self.assertEqual(listing.json()["active_job"]["id"], job_id)
        blocked = self.client.delete(f"/api/backup/jobs/{job_id}", headers=self.headers)
        self.assertEqual(blocked.status_code, 409)
        with SessionLocal() as db:
            other_workspace = Workspace(name="v222-other-workspace")
            db.add(other_workspace)
            db.flush()
            other_admin = User(
                workspace_id=other_workspace.id, username="v222-other-admin",
                display_name="Other Admin", password_hash="test-only",
                role="admin", roles=["admin"], is_active=True,
            )
            db.add(other_admin)
            db.commit()
            other_headers = {"Authorization": f"Bearer {create_access_token(str(other_admin.id))}"}
        self.assertEqual(self.client.get(f"/api/backup/jobs/{job_id}", headers=other_headers).status_code, 404)
        self.assertEqual(self.client.delete(f"/api/backup/jobs/{job_id}", headers=other_headers).status_code, 404)
        self.assertEqual(self.client.get("/api/backup/jobs", headers=other_headers).json()["total"], 0)

        self.assertEqual(claim_backup_job(), job_id)
        run_backup_job(job_id)
        path = backup_path(job_id)
        self.assertTrue(path.is_file())
        finished = self.client.get("/api/backup/jobs", params={"status": "success"}, headers=self.headers)
        self.assertEqual(finished.status_code, 200)
        self.assertTrue(any(item["id"] == job_id for item in finished.json()["items"]))
        self.assertIsNone(finished.json()["active_job"])
        deleted = self.client.delete(f"/api/backup/jobs/{job_id}", headers=self.headers)
        self.assertEqual(deleted.status_code, 200, deleted.text[:300])
        self.assertFalse(deleted.json()["file_cleanup_failed"])
        self.assertFalse(path.exists())
        self.assertEqual(self.client.get(f"/api/backup/jobs/{job_id}", headers=self.headers).status_code, 404)
        self.assertEqual(self.client.delete(f"/api/backup/jobs/{job_id}", headers=self.headers).status_code, 404)
        with SessionLocal() as db:
            self.assertIsNotNone(db.query(AuditLog).filter(
                AuditLog.action == "backup.job_delete", AuditLog.target_id == str(job_id),
            ).first())


if __name__ == "__main__":
    unittest.main()
