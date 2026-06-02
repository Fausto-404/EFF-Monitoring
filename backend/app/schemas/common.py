from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class OrmModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(OrmModel):
    id: int
    username: str
    display_name: str
    role: str
    workspace_id: int
    is_active: bool


class UserCreate(BaseModel):
    username: str
    display_name: str
    password: str
    role: str = "analyst"
    is_active: bool = True


class UserUpdate(BaseModel):
    display_name: str | None = None
    password: str | None = None
    role: str | None = None
    is_active: bool | None = None


class ProjectCreate(BaseModel):
    name: str
    description: str = ""


class ProjectUpdate(BaseModel):
    name: str | None = None
    description: str | None = None


class ProjectOut(OrmModel):
    id: int
    name: str
    description: str


class DeviceCreate(BaseModel):
    name: str
    vendor: str = ""
    product: str = ""
    version: str = ""


class DeviceUpdate(BaseModel):
    name: str | None = None
    vendor: str | None = None
    product: str | None = None
    version: str | None = None


class DeviceOut(OrmModel):
    id: int
    name: str
    vendor: str
    product: str
    version: str


class AssetCreate(BaseModel):
    ip: str = ""
    domain: str = ""
    name: str = ""
    area: str = ""
    owner: str = ""
    department: str = ""
    criticality: str = "medium"
    environment: str = ""
    tags: list[str] = []
    fingerprints: dict[str, Any] = {}
    description: str = ""


class AssetUpdate(BaseModel):
    ip: str | None = None
    domain: str | None = None
    name: str | None = None
    area: str | None = None
    owner: str | None = None
    department: str | None = None
    criticality: str | None = None
    environment: str | None = None
    tags: list[str] | None = None
    fingerprints: dict[str, Any] | None = None
    description: str | None = None
    updated_at: datetime | None = None


class AssetOut(OrmModel):
    id: int
    asset_key: str
    ip: str
    domain: str
    name: str
    area: str
    owner: str
    department: str
    criticality: str
    environment: str
    tags: list[Any]
    fingerprints: dict[str, Any]
    description: str
    created_at: datetime
    updated_at: datetime


class AssetSegmentCreate(BaseModel):
    segment: str
    name: str = ""
    area: str = ""
    owner: str = ""
    department: str = ""
    criticality: str = "medium"
    environment: str = ""
    description: str = ""


class AssetSegmentUpdate(BaseModel):
    segment: str | None = None
    name: str | None = None
    area: str | None = None
    owner: str | None = None
    department: str | None = None
    criticality: str | None = None
    environment: str | None = None
    description: str | None = None
    updated_at: datetime | None = None


class AssetSegmentOut(OrmModel):
    id: int
    segment: str
    name: str
    area: str
    owner: str
    department: str
    criticality: str
    environment: str
    description: str
    created_at: datetime
    updated_at: datetime


class AssetLookupRequest(BaseModel):
    ips: list[str] = []
    domains: list[str] = []


class AssetImportResult(BaseModel):
    created: int = 0
    updated: int = 0
    skipped: int = 0
    errors: list[dict[str, Any]] = []


class AuditLogOut(OrmModel):
    id: int
    actor_id: int | None
    actor_username: str = ""
    actor_name: str = ""
    action: str
    target_type: str
    target_id: str
    detail: dict[str, Any]
    created_at: datetime


class TaskRecordOut(OrmModel):
    id: int
    actor_id: int | None
    actor_username: str = ""
    actor_name: str = ""
    task_type: str
    status: str
    target_type: str
    target_id: str
    input: dict[str, Any]
    output: dict[str, Any]
    error: str
    created_at: datetime
    updated_at: datetime


class LoginRequest(BaseModel):
    username: str
    password: str


class ParseRequest(BaseModel):
    text: str
    device_id: int | None = None
    template_id: int | None = None
    message_template_id: int | None = None
    excel_template_id: int | None = None


class ParseResponse(BaseModel):
    parsed_fields: dict[str, Any]
    warnings: list[str] = []
    matched_rules: list[dict[str, Any]] = []
    formatted_chat: str = ""
    formatted_excel: str = ""
    ip_list_alerts: list[dict[str, str]] = []
    asset_context: dict[str, Any] = {}


class AlertCreate(BaseModel):
    raw_text: str
    parsed_fields: dict[str, Any] = {}
    project_id: int | None = None
    device_id: int | None = None
    tags: list[str] = []


class AlertUpdate(BaseModel):
    status: str | None = None
    severity: str | None = None
    assignee_id: int | None = None
    tags: list[str] | None = None
    comments: list[dict[str, Any]] | None = None
    parsed_fields: dict[str, Any] | None = None
    ai_result: str | None = None
    ti_result: dict[str, Any] | None = None
    updated_at: datetime | None = None
    version: int | None = None


class AlertOut(OrmModel):
    id: int
    alert_code: str = ""
    alert_hash: str = ""
    project_id: int | None
    device_id: int | None
    raw_text: str
    parsed_fields: dict[str, Any]
    src_asset_context: dict[str, Any]
    dst_asset_context: dict[str, Any]
    ti_result: dict[str, Any]
    ai_result: str
    source_ip: str
    destination_ip: str
    event_type: str
    severity: str
    status: str
    current_group: str = "analysis"
    assignee_id: int | None
    claimed_at: datetime | None = None
    analysis_owner_id: int | None = None
    disposal_owner_id: int | None = None
    disposal_target: str = ""
    disposal_action: str = ""
    disposal_ip: str = ""
    closure_target: str = ""
    closure_action: str = ""
    false_positive_reason: str = ""
    version: int = 1
    tags: list[Any]
    comments: list[Any]
    created_by_id: int | None
    last_updated_by_id: int | None
    created_at: datetime
    updated_at: datetime


class AlertClaimRequest(BaseModel):
    updated_at: datetime | None = None
    version: int | None = None


class AlertAssignRequest(BaseModel):
    assignee_id: int
    updated_at: datetime | None = None
    version: int | None = None


class AlertTransitionRequest(BaseModel):
    status: str
    disposal_target: str = ""
    disposal_action: str = ""
    closure_target: str = ""
    closure_action: str = ""
    false_positive_reason: str = ""
    updated_at: datetime | None = None
    version: int | None = None


class AlertBatchTransitionRequest(BaseModel):
    ids: list[int]
    status: str
    disposal_target: str = ""
    disposal_action: str = ""
    closure_target: str = ""
    closure_action: str = ""
    false_positive_reason: str = ""


class MessageItem(OrmModel):
    id: int
    recipient_id: int
    recipient_name: str = ""
    actor_id: int | None = None
    actor_name: str = ""
    alert_id: int | None
    alert_hash: str
    title: str
    content: str
    message_type: str
    is_read: bool
    read_at: datetime | None
    created_at: datetime


class MessageOut(OrmModel):
    id: int
    recipient_id: int
    recipient_name: str = ""
    actor_id: int | None = None
    actor_name: str = ""
    alert_id: int | None
    alert_hash: str
    title: str
    content: str
    message_type: str
    is_read: bool
    read_at: datetime | None
    payload: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class RuleCreate(BaseModel):
    device_id: int | None = None
    name: str
    field_key: str
    field_label: str = ""
    match_type: str = "regex"
    pattern: str
    priority: int = 100
    enabled: bool = True
    match_all: bool = False

    sample_log: str = ""


class RuleUpdate(BaseModel):
    device_id: int | None = None
    name: str | None = None
    field_key: str | None = None
    field_label: str | None = None
    match_type: str | None = None
    pattern: str | None = None
    priority: int | None = None
    enabled: bool | None = None
    match_all: bool | None = None
    sample_log: str | None = None


class RuleOut(OrmModel):
    id: int
    device_id: int | None
    name: str
    field_key: str
    field_label: str
    match_type: str
    pattern: str
    priority: int
    enabled: bool
    match_all: bool
    is_meta: bool
    sample_log: str


class RuleTestRequest(BaseModel):
    text: str
    device_id: int | None = None
    rules: list[RuleCreate] | None = None


class RuleGenerateRequest(BaseModel):
    sample_log: str
    device_id: int | None = None
    field_name: str = ""
    expected_output: str = ""
    mode: str = "match"  # match or ai


class RegexTestRequest(BaseModel):
    sample_log: str
    regex: str


class TemplateCreate(BaseModel):
    device_id: int | None = None
    name: str
    type: str
    content: str
    variables: list[str] = []
    scope: str = "team"
    is_default: bool = False


class TemplateUpdate(BaseModel):
    device_id: int | None = None
    name: str | None = None
    type: str | None = None
    content: str | None = None
    variables: list[str] | None = None
    scope: str | None = None
    is_default: bool | None = None


class TemplateOut(OrmModel):
    id: int
    device_id: int | None
    name: str
    type: str
    content: str
    variables: list[Any]
    scope: str
    is_default: bool


class ReportGenerateRequest(BaseModel):
    title: str | None = None
    report_category: str | None = None
    report_key: str | None = None
    source_type: str = "manual"
    source_module: str = "report_center"
    source_id: int | None = None
    template_id: int | None = None
    rule_id: int | None = None
    project_id: int | None = None
    device_id: int | None = None
    period_start: datetime | None = None
    period_end: datetime | None = None
    scope: dict[str, Any] = Field(default_factory=dict)
    render_context: dict[str, Any] = Field(default_factory=dict)
    source_refs: dict[str, Any] = Field(default_factory=dict)
    raw_template: str | None = None
    content: str | None = None
    save: bool = True
    tags: list[str] = Field(default_factory=list)


class ReportCreate(BaseModel):
    title: str
    report_category: str | None = None
    report_key: str | None = None
    source_type: str = "manual"
    source_module: str = "report_center"
    source_id: int | None = None
    template_id: int | None = None
    rule_id: int | None = None
    project_id: int | None = None
    device_id: int | None = None
    period_start: datetime | None = None
    period_end: datetime | None = None
    scope: dict[str, Any] = Field(default_factory=dict)
    input_payload: dict[str, Any] = Field(default_factory=dict)
    render_context: dict[str, Any] = Field(default_factory=dict)
    source_refs: dict[str, Any] = Field(default_factory=dict)
    summary: dict[str, Any] = Field(default_factory=dict)
    content: str = ""
    format: str = "markdown"
    tags: list[str] = Field(default_factory=list)


class ReportUpdate(BaseModel):
    title: str | None = None
    report_category: str | None = None
    report_key: str | None = None
    tags: list[str] | None = None
    content: str | None = None
    summary: dict[str, Any] | None = None
    render_context: dict[str, Any] | None = None
    source_refs: dict[str, Any] | None = None
    scope: dict[str, Any] | None = None


class ReportOut(OrmModel):
    id: int
    title: str
    report_category: str | None
    report_key: str | None
    source_type: str
    source_module: str
    source_id: int | None
    template_id: int | None
    rule_id: int | None
    project_id: int | None
    device_id: int | None
    period_start: datetime | None
    period_end: datetime | None
    scope: dict[str, Any]
    input_payload: dict[str, Any]
    render_context: dict[str, Any]
    source_refs: dict[str, Any]
    summary: dict[str, Any]
    content: str
    format: str
    tags: list[Any]
    created_by_id: int | None
    updated_by_id: int | None
    created_at: datetime
    updated_at: datetime


class ReportGenerateOut(BaseModel):
    content: str
    report: ReportOut | None = None


class ReportFacetsOut(BaseModel):
    categories: list[str] = Field(default_factory=list)
    report_keys: list[str] = Field(default_factory=list)
    source_types: list[str] = Field(default_factory=list)
    source_modules: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class SettingUpdate(BaseModel):
    value: dict[str, Any]
    updated_at: datetime | None = None


class SettingOut(OrmModel):
    key: str
    value: dict[str, Any]


class WebhookTestRequest(BaseModel):
    text: str


class AiPromptCreate(BaseModel):
    name: str
    prompt_key: str
    category: str = ""
    system_prompt: str = ""
    user_prompt: str = ""
    output_schema: dict[str, Any] = {}
    variables: list[str] = []
    enabled: bool = True
    is_default: bool = False


class AiPromptUpdate(BaseModel):
    name: str | None = None
    prompt_key: str | None = None
    category: str | None = None
    system_prompt: str | None = None
    user_prompt: str | None = None
    output_schema: dict[str, Any] | None = None
    variables: list[str] | None = None
    enabled: bool | None = None
    is_default: bool | None = None


class AiPromptOut(OrmModel):
    id: int
    name: str
    prompt_key: str
    category: str
    system_prompt: str
    user_prompt: str
    output_schema: dict[str, Any]
    variables: list[Any]
    enabled: bool
    is_default: bool
    created_by_id: int | None
    updated_by_id: int | None
    created_at: datetime
    updated_at: datetime


class AiExperienceCreate(BaseModel):
    knowledge_id: str = ""
    source_alert_id: int | None = None
    alert_hash: str = ""
    title: str = ""
    tags: list[str] = []
    index_data: dict[str, Any] = {}
    ste: dict[str, Any] = {}
    action: dict[str, Any] = {}
    quality: dict[str, Any] = {}
    status: str = "draft"


class AiExperienceUpdate(BaseModel):
    knowledge_id: str | None = None
    title: str | None = None
    tags: list[str] | None = None
    index_data: dict[str, Any] | None = None
    ste: dict[str, Any] | None = None
    action: dict[str, Any] | None = None
    quality: dict[str, Any] | None = None
    status: str | None = None


class AiExperienceOut(OrmModel):
    id: int
    knowledge_id: str
    source_alert_id: int | None
    alert_hash: str
    title: str
    tags: list[Any]
    index_data: dict[str, Any]
    ste: dict[str, Any]
    action: dict[str, Any]
    quality: dict[str, Any]
    status: str
    created_by_id: int | None
    updated_by_id: int | None
    created_at: datetime
    updated_at: datetime


class AiExperienceExtractRequest(BaseModel):
    alert_id: int
    save: bool = False
    publish: bool = False


class AiConversationCreate(BaseModel):
    title: str = "新的对话"


class AiConversationOut(OrmModel):
    id: int
    title: str
    created_by_id: int | None
    created_at: datetime
    updated_at: datetime


class AiChatRequest(BaseModel):
    content: str


class AiMessageOut(OrmModel):
    id: int
    conversation_id: int
    role: str
    content: str
    tool_calls: list[Any]
    created_by_id: int | None
    created_at: datetime


class TemplateAiGenerateRequest(BaseModel):
    sample_text: str
    device_id: int | None = None
    template_type: str = "message"
    intent: str = "生成消息通报模板"
