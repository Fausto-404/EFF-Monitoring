import time
import logging
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from app.models.database import SessionLocal
from app.models.entities import TaskRecord
from app.services.task_service import finish_task, fail_task
from app.services.ai_service import handle_auto_ste_task
from app.services.backup_job_service import claim_backup_job, recover_interrupted_jobs, run_backup_job
from app.services.auto_block_service import claim_auto_block, recover_interrupted_auto_blocks, run_auto_block

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("eff-worker")


def wait_for_schema() -> None:
    while True:
        db: Session = SessionLocal()
        try:
            db.execute(text("SELECT 1 FROM task_records LIMIT 1"))
            db.execute(text("SELECT 1 FROM backup_jobs LIMIT 1"))
            return
        except SQLAlchemyError:
            logger.info("Waiting for application schema to be initialized...")
            time.sleep(3)
        finally:
            db.close()


def main() -> None:
    wait_for_schema()
    recover_interrupted_jobs()
    recover_interrupted_auto_blocks()
    logger.info("EFF worker started. Polling for tasks...")
    
    while True:
        backup_job_id = claim_backup_job()
        if backup_job_id is not None:
            try:
                run_backup_job(backup_job_id)
            except Exception:
                logger.exception("Backup job %s failed", backup_job_id)
            continue
        auto_block_id = claim_auto_block()
        if auto_block_id is not None:
            try:
                run_auto_block(auto_block_id)
            except Exception:
                logger.exception("Auto block task %s failed", auto_block_id)
            continue
        db: Session = SessionLocal()
        try:
            # 1. 查找队列中的任务
            task = db.query(TaskRecord).filter(TaskRecord.status == "queued", TaskRecord.task_type != "block_ip").order_by(TaskRecord.created_at.asc()).first()
            
            if not task:
                db.close()
                time.sleep(5)
                continue
            
            logger.info(f"Processing task {task.id} (type: {task.task_type})...")
            
            # 2. 标记为运行中
            task.status = "running"
            db.commit()
            
            # 3. 执行具体逻辑
            try:
                # 自动提取逻辑已改为人工触发，此处目前作为心跳保留
                logger.info(f"Task {task.id} processed (placeholder).")
                finish_task(db, task, {"msg": "Manual generation required for this task type"})
                
                db.commit()
            except Exception as e:
                db.rollback()
                fail_task(db, task, e)
                db.commit()
                logger.error(f"Task {task.id} failed with error: {str(e)}")
                
        except Exception as e:
            logger.error(f"Worker loop error: {str(e)}")
            time.sleep(10)
        finally:
            db.close()

if __name__ == "__main__":
    main()
