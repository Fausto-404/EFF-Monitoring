import time
import logging
from sqlalchemy.orm import Session
from app.models.database import SessionLocal
from app.models.entities import TaskRecord
from app.services.task_service import finish_task, fail_task
from app.services.ai_service import handle_auto_ste_task

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("eff-worker")

def main() -> None:
    logger.info("EFF worker started. Polling for tasks...")
    
    while True:
        db: Session = SessionLocal()
        try:
            # 1. 查找队列中的任务
            task = db.query(TaskRecord).filter_by(status="queued").order_by(TaskRecord.created_at.asc()).first()
            
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
