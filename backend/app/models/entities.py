from datetime import datetime
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False, index=True
    )


class Workspace(Base, TimestampMixin):
    __tablename__ = "workspaces"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), nullable=False)
    username: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(40), default="admin", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    workspace = relationship("Workspace")


class Project(Base, TimestampMixin):
    __tablename__ = "projects"
    __table_args__ = (UniqueConstraint("workspace_id", "name", name="uq_project_workspace_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)


class Device(Base, TimestampMixin):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), nullable=False)
    vendor: Mapped[str] = mapped_column(String(120), default="", nullable=False)
    product: Mapped[str] = mapped_column(String(120), default="", nullable=False)
    version: Mapped[str] = mapped_column(String(80), default="", nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)


class Asset(Base, TimestampMixin):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("workspace_id", "ip", "domain", name="uq_asset_workspace_ip_domain"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), nullable=False)
    asset_key: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    ip: Mapped[str] = mapped_column(String(120), default="", nullable=False, index=True)
    domain: Mapped[str] = mapped_column(String(255), default="", nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    area: Mapped[str] = mapped_column(String(160), default="", nullable=False, index=True)
    owner: Mapped[str] = mapped_column(String(160), default="", nullable=False, index=True)
    department: Mapped[str] = mapped_column(String(160), default="", nullable=False)
    criticality: Mapped[str] = mapped_column(String(40), default="medium", nullable=False, index=True)
    environment: Mapped[str] = mapped_column(String(80), default="", nullable=False, index=True)
    tags: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    fingerprints: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)


class AssetSegment(Base, TimestampMixin):
    __tablename__ = "asset_segments"
    __table_args__ = (UniqueConstraint("workspace_id", "segment", name="uq_asset_segment_workspace_segment"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), nullable=False)
    segment: Mapped[str] = mapped_column(String(120), nullable=False, index=True) # CIDR or Range
    name: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    area: Mapped[str] = mapped_column(String(160), default="", nullable=False, index=True)
    owner: Mapped[str] = mapped_column(String(160), default="", nullable=False, index=True)
    department: Mapped[str] = mapped_column(String(160), default="", nullable=False)
    criticality: Mapped[str] = mapped_column(String(40), default="medium", nullable=False, index=True)
    environment: Mapped[str] = mapped_column(String(80), default="", nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)


class ParseRule(Base, TimestampMixin):
    __tablename__ = "parse_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), nullable=False)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    field_key: Mapped[str] = mapped_column(String(120), nullable=False)
    field_label: Mapped[str] = mapped_column(String(120), default="", nullable=False)
    match_type: Mapped[str] = mapped_column(String(40), default="regex", nullable=False)
    pattern: Mapped[str] = mapped_column(Text, nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    match_all: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_meta: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    sample_log: Mapped[str] = mapped_column(Text, default="", nullable=False)


class Alert(Base, TimestampMixin):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), nullable=False)
    project_id: Mapped[int | None] = mapped_column(ForeignKey("projects.id"), nullable=True)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id"), nullable=True)
    raw_text: Mapped[str] = mapped_column(Text, nullable=False)
    parsed_fields: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    src_asset_context: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    dst_asset_context: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    alert_hash: Mapped[str] = mapped_column(String(64), default="", nullable=False, index=True)
    ti_result: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    ai_result: Mapped[str] = mapped_column(Text, default="", nullable=False)
    source_ip: Mapped[str] = mapped_column(String(80), default="", nullable=False, index=True)
    destination_ip: Mapped[str] = mapped_column(String(80), default="", nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(240), default="", nullable=False, index=True)
    dedup_hash: Mapped[str] = mapped_column(String(64), default="", nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(40), default="unknown", nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(40), default="analysis", nullable=False, index=True)
    current_group: Mapped[str] = mapped_column(String(40), default="analysis", nullable=False, index=True)
    assignee_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    analysis_owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    disposal_owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    disposal_target: Mapped[str] = mapped_column(String(40), default="", nullable=False)
    disposal_action: Mapped[str] = mapped_column(String(40), default="", nullable=False)
    disposal_ip: Mapped[str] = mapped_column(String(80), default="", nullable=False)
    closure_target: Mapped[str] = mapped_column(String(40), default="", nullable=False)
    closure_action: Mapped[str] = mapped_column(String(60), default="", nullable=False)
    false_positive_reason: Mapped[str] = mapped_column(Text, default="", nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    tags: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    comments: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    last_updated_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)


class Message(Base, TimestampMixin):
    __tablename__ = "messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), nullable=False, index=True)
    recipient_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    alert_id: Mapped[int | None] = mapped_column(ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True, index=True)
    alert_hash: Mapped[str] = mapped_column(String(64), default="", nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    content: Mapped[str] = mapped_column(Text, default="", nullable=False)
    message_type: Mapped[str] = mapped_column(String(60), default="workflow", nullable=False, index=True)
    is_read: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    read_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class Template(Base, TimestampMixin):
    __tablename__ = "templates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), nullable=False)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    type: Mapped[str] = mapped_column(String(60), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    variables: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    scope: Mapped[str] = mapped_column(String(40), default="team", nullable=False)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class ReportRecord(Base, TimestampMixin):
    __tablename__ = "report_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    report_category: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    report_key: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    source_type: Mapped[str] = mapped_column(String(60), default="manual", nullable=False, index=True)
    source_module: Mapped[str] = mapped_column(String(80), default="report_center", nullable=False, index=True)
    source_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    template_id: Mapped[int | None] = mapped_column(ForeignKey("templates.id"), nullable=True, index=True)
    rule_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    project_id: Mapped[int | None] = mapped_column(ForeignKey("projects.id"), nullable=True, index=True)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id"), nullable=True, index=True)
    period_start: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    period_end: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    scope: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    input_payload: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    render_context: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    source_refs: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    summary: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    content: Mapped[str] = mapped_column(Text, default="", nullable=False)
    format: Mapped[str] = mapped_column(String(40), default="markdown", nullable=False)
    # status column retained for DB compatibility only; hidden from all API schemas
    status: Mapped[str] = mapped_column(String(40), server_default="generated", nullable=False)
    tags: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    updated_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)


class Setting(Base, TimestampMixin):
    __tablename__ = "settings"
    __table_args__ = (UniqueConstraint("workspace_id", "user_id", "key", name="uq_setting_workspace_user_key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), nullable=False)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    key: Mapped[str] = mapped_column(String(120), nullable=False)
    value: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class AuditLog(Base, TimestampMixin):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), nullable=False)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    target_type: Mapped[str] = mapped_column(String(80), default="", nullable=False)
    target_id: Mapped[str] = mapped_column(String(80), default="", nullable=False)
    detail: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class TaskRecord(Base, TimestampMixin):
    __tablename__ = "task_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), nullable=False)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    task_type: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(40), default="queued", nullable=False, index=True)
    target_type: Mapped[str] = mapped_column(String(80), default="", nullable=False)
    target_id: Mapped[str] = mapped_column(String(80), default="", nullable=False)
    input: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    output: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    error: Mapped[str] = mapped_column(Text, default="", nullable=False)


class AiPrompt(Base, TimestampMixin):
    __tablename__ = "ai_prompts"
    __table_args__ = (UniqueConstraint("workspace_id", "prompt_key", "name", name="uq_ai_prompt_workspace_key_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    prompt_key: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(80), default="", nullable=False, index=True)
    system_prompt: Mapped[str] = mapped_column(Text, default="", nullable=False)
    user_prompt: Mapped[str] = mapped_column(Text, default="", nullable=False)
    output_schema: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    variables: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    updated_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)


class AiExperience(Base, TimestampMixin):
    __tablename__ = "ai_experiences"
    __table_args__ = (UniqueConstraint("workspace_id", "knowledge_id", name="uq_ai_experience_workspace_knowledge"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), nullable=False, index=True)
    knowledge_id: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    source_alert_id: Mapped[int | None] = mapped_column(ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True, index=True)
    alert_hash: Mapped[str] = mapped_column(String(64), default="", nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    tags: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    index_data: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    ste: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    action: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    quality: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(String(40), default="draft", nullable=False, index=True)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    updated_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)


class AiConversation(Base, TimestampMixin):
    __tablename__ = "ai_conversations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), default="新的对话", nullable=False)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)


class AiMessage(Base, TimestampMixin):
    __tablename__ = "ai_messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), nullable=False, index=True)
    conversation_id: Mapped[int] = mapped_column(ForeignKey("ai_conversations.id", ondelete="CASCADE"), nullable=False, index=True)
    role: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    content: Mapped[str] = mapped_column(Text, default="", nullable=False)
    tool_calls: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
