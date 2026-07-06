export interface Alert {
  id: number;
  alert_code: string;
  alert_hash: string;
  project_id?: number | null;
  device_id?: number | null;
  raw_text: string;
  parsed_fields: Record<string, unknown>;
  src_asset_context: Record<string, unknown>;
  dst_asset_context: Record<string, unknown>;
  ti_result: Record<string, unknown>;
  ai_result: string;
  source_ip: string;
  destination_ip: string;
  event_type: string;
  severity: string;
  status: string;
  current_group: string;
  assignee_id?: number | null;
  claimed_at?: string | null;
  analysis_owner_id?: number | null;
  disposal_owner_id?: number | null;
  disposal_target: string;
  disposal_action: string;
  disposal_ip: string;
  closure_target: string;
  closure_action: string;
  false_positive_reason: string;
  version: number;
  tags: string[];
  comments: unknown[];
  created_by_id?: number | null;
  last_updated_by_id?: number | null;
  created_at: string;
  updated_at: string;
}

export interface User {
  id: number;
  username: string;
  display_name: string;
  role: string;
  workspace_id: number;
  is_active: boolean;
}
export interface MessageItem {
  id: number;
  recipient_id: number;
  recipient_name: string;
  actor_id?: number | null;
  actor_name: string;
  alert_id?: number | null;
  alert_hash: string;
  title: string;
  content: string;
  message_type: string;
  is_read: boolean;
  read_at?: string | null;
  payload: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface Project {
  id: number;
  name: string;
  description: string;
}

export interface Device {
  id: number;
  name: string;
  vendor: string;
  product: string;
  version: string;
}

export interface Asset {
  id: number;
  asset_key: string;
  ip: string;
  domain: string;
  name: string;
  area: string;
  owner: string;
  department: string;
  criticality: string;
  environment: string;
  tags: string[];
  fingerprints: Record<string, unknown>;
  description: string;
  created_at: string;
  updated_at: string;
}

export interface AuditLog {
  id: number;
  actor_id?: number | null;
  actor_username: string;
  actor_name: string;
  action: string;
  target_type: string;
  target_id: string;
  detail: Record<string, unknown>;
  created_at: string;
}

export interface DashboardSummary {
  total: number;
  today: number;
  pending: number;
  confirmed: number;
  by_status: Record<string, number>;
  latest: Array<Pick<Alert, 'id' | 'alert_hash' | 'source_ip' | 'destination_ip' | 'event_type' | 'status' | 'created_at' | 'version'>>;
}

export interface TaskRecord {
  id: number;
  actor_id?: number | null;
  actor_username: string;
  actor_name: string;
  task_type: string;
  status: string;
  target_type: string;
  target_id: string;
  input: Record<string, unknown>;
  output: Record<string, unknown>;
  error: string;
  created_at: string;
  updated_at: string;
}

export interface ParseRule {
  id: number;
  device_id?: number | null;
  name: string;
  field_key: string;
  field_label: string;
  match_type: string;
  pattern: string;
  priority: number;
  enabled: boolean;
  match_all: boolean;
  is_meta: boolean;
  sample_log: string;
}

export interface Template {
  id: number;
  device_id?: number | null;
  name: string;
  type: string;
  content: string;
  variables: string[];
  scope: string;
  is_default: boolean;
}

export interface ReportRecord {
  id: number;
  title: string;
  report_category?: string | null;
  report_key?: string | null;
  source_type: string;
  source_module: string;
  source_id?: number | null;
  template_id?: number | null;
  rule_id?: number | null;
  project_id?: number | null;
  device_id?: number | null;
  period_start?: string | null;
  period_end?: string | null;
  scope: Record<string, any>;
  input_payload: Record<string, any>;
  render_context: Record<string, any>;
  source_refs: Record<string, any>;
  summary: Record<string, any>;
  content: string;
  format: string;
  tags: string[];
  created_by_id?: number | null;
  updated_by_id?: number | null;
  created_at: string;
  updated_at: string;
}

export interface ReportFacets {
  categories: string[];
  report_keys: string[];
  source_types: string[];
  source_modules: string[];
  tags: string[];
}

export interface ReportGenerateRequest {
  title?: string;
  report_category?: string | null;
  report_key?: string | null;
  source_type?: string;
  source_module?: string;
  source_id?: number | null;
  template_id?: number | null;
  rule_id?: number | null;
  project_id?: number | null;
  device_id?: number | null;
  period_start?: string | null;
  period_end?: string | null;
  scope?: Record<string, any>;
  render_context?: Record<string, any>;
  source_refs?: Record<string, any>;
  raw_template?: string | null;
  content?: string | null;
  save?: boolean;
  tags?: string[];
}

export interface ReportGenerateResult {
  content: string;
  report: ReportRecord | null;
}

export interface AiPrompt {
  id: number;
  name: string;
  prompt_key: string;
  category: string;
  system_prompt: string;
  user_prompt: string;
  output_schema: Record<string, unknown>;
  variables: string[];
  enabled: boolean;
  is_default: boolean;
  created_by_id?: number | null;
  updated_by_id?: number | null;
  created_at: string;
  updated_at: string;
}

export interface AiExperience {
  id: number;
  knowledge_id: string;
  source_alert_id?: number | null;
  alert_hash: string;
  title: string;
  tags: string[];
  index_data: Record<string, unknown>;
  ste: Record<string, unknown>;
  action: Record<string, unknown>;
  quality: Record<string, unknown>;
  status: string;
  created_by_id?: number | null;
  updated_by_id?: number | null;
  created_at: string;
  updated_at: string;
}

export interface AiConversation {
  id: number;
  title: string;
  created_by_id?: number | null;
  created_at: string;
  updated_at: string;
}

export interface AiToolCall {
  tool: string;
  params?: Record<string, any>;
  data?: any;
}

export interface AiMessage {
  id: number;
  conversation_id: number;
  role: string;
  content: string;
  tool_calls: AiToolCall[];
  created_by_id?: number | null;
  created_at: string;
}
