import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { Key, PointerEvent as ReactPointerEvent } from 'react';
import { useMutation, useQuery, useQueryClient, keepPreviousData } from '@tanstack/react-query';
import { ReloadOutlined, SendOutlined } from '@ant-design/icons';
import { Brain } from 'lucide-react';
import { Button, Card, Collapse, DatePicker, Descriptions, Drawer, Form, Input, Modal, Popconfirm, Radio, Select, Space, Switch, Table, Tabs, Tag, Typography, message } from 'antd';
import dayjs from 'dayjs';
import type { Dayjs } from 'dayjs';
import { api } from '../api/client';
import type { Alert, Device, Template, User } from '../api/types';
import HelpTip from '../components/HelpTip';
import CollapsibleBlock from '../components/CollapsibleBlock';

type ColumnWidths = Record<string, number>;

// 列宽调整 Hook：只在独立手柄上启动拖拽，避免点击表头触发调整。
function useColumnWidths(initialWidths: ColumnWidths) {
  const [widths, setWidths] = useState<Record<string, number>>(initialWidths);
  const defaultsRef = useRef(initialWidths);
  const resizingRef = useRef<{ key: string; startX: number; startWidth: number } | null>(null);

  const onPointerMove = useCallback((e: PointerEvent) => {
    if (!resizingRef.current) return;
    const { key, startX, startWidth } = resizingRef.current;
    const newWidth = Math.min(600, Math.max(60, startWidth + e.clientX - startX));
    setWidths(prev => (prev[key] === newWidth ? prev : { ...prev, [key]: newWidth }));
  }, []);

  const stopResize = useCallback(function stopResize() {
    resizingRef.current = null;
    document.body.style.cursor = '';
    document.body.style.userSelect = '';
    document.removeEventListener('pointermove', onPointerMove);
    document.removeEventListener('pointerup', stopResize);
  }, [onPointerMove]);

  const onResize = useCallback((key: string, e: ReactPointerEvent<HTMLSpanElement>) => {
    e.preventDefault();
    e.stopPropagation();
    resizingRef.current = { key, startX: e.clientX, startWidth: widths[key] };
    document.addEventListener('pointermove', onPointerMove);
    document.addEventListener('pointerup', stopResize);
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  }, [onPointerMove, stopResize, widths]);

  useEffect(() => stopResize, [stopResize]);

  const resetWidth = useCallback((key: string) => {
    setWidths(prev => ({ ...prev, [key]: defaultsRef.current[key] }));
  }, []);

  return { widths, onResize, resetWidth };
}

function ResizableHeader({ label, columnKey, onResize, onReset }: {
  label: string;
  columnKey: string;
  onResize: (key: string, event: ReactPointerEvent<HTMLSpanElement>) => void;
  onReset: (key: string) => void;
}) {
  return (
    <span className="alert-column-header">
      <span>{label}</span>
      <span
        className="alert-column-resizer"
        role="separator"
        aria-label={`调整${label}列宽`}
        title="拖拽调整列宽，双击恢复默认宽度"
        onPointerDown={(event) => onResize(columnKey, event)}
        onDoubleClick={(event) => {
          event.preventDefault();
          event.stopPropagation();
          onReset(columnKey);
        }}
      />
    </span>
  );
}

const statusColor: Record<string, string> = {
  analysis: 'processing',
  disposal: 'warning',
  false_positive: 'magenta',
  ignored: 'default',
  disposed: 'success'
};

const statusLabel: Record<string, string> = {
  analysis: '研判中',
  disposal: '处置中',
  false_positive: '误报',
  ignored: '忽略',
  disposed: '已处置'
};

const groupLabel: Record<string, string> = {
  analysis: '研判组',
  disposal: '处置组',
  none: '无（已闭环）'
};

const roleLabel: Record<string, string> = {
  admin: '管理员',
  monitor: '监测组',
  analyst: '研判组',
  disposer: '处置组',
  viewer: '只读人员'
};

const groupRole: Record<string, string> = {
  analysis: 'analyst',
  disposal: 'disposer'
};

function userRoles(user: User | undefined) {
  const roles = Array.isArray(user?.roles) && user.roles.length ? user.roles : (user?.role ? [user.role] : []);
  return Array.from(new Set(roles.filter(Boolean)));
}

function hasRole(user: User | undefined, role?: string) {
  return !!role && userRoles(user).includes(role);
}

function roleNames(user: User) {
  return userRoles(user).map((role) => roleLabel[role] || role).join('、');
}

const targetOptions = [
  { value: 'src_ip', label: '源 IP' },
  { value: 'dst_ip', label: '目的 IP' }
];

const disposalActionOptions = [
  { value: 'repair', label: '修复' },
  { value: 'emergency', label: '应急' },
  { value: 'block', label: '封禁' }
];

const refreshIntervalOptions = [
  { value: 30_000, label: '30秒' },
  { value: 60_000, label: '1分钟' },
  { value: 180_000, label: '3分钟' },
  { value: 300_000, label: '5分钟' }
];

const targetLabel: Record<string, string> = Object.fromEntries(targetOptions.map((item) => [item.value, item.label]));
const disposalActionLabel: Record<string, string> = Object.fromEntries(disposalActionOptions.map((item) => [item.value, item.label]));
const closureActionLabel: Record<string, string> = {
  ignore: '仅忽略',
  ignore_whitelist: '忽略并加白',
  false_positive: '仅误报',
  false_positive_whitelist: '误报并加白'
};

function extractAiField(text: string, label: string) {
  const match = text.match(new RegExp(`${label}\\s*[:：]\\s*([^\\n]+)`));
  return match?.[1]?.trim() || '';
}

function extractAiSection(text: string, title: string) {
  const match = text.match(new RegExp(`(?:^|\\n)\\s*#{0,4}\\s*${title}\\s*[:：]?\\s*\\n([\\s\\S]*?)(?=\\n\\s*#{1,4}\\s*\\S|\\n\\s*(?:结论|摘要|关键证据|证据链分析|处置建议|不确定性)\\s*[:：]|$)`));
  return match?.[1]?.trim() || '';
}

function renderSimpleMarkdown(text: string) {
  const rows = String(text || '').split('\n').filter((line) => line.trim());
  return rows.map((line, index) => {
    const trimmed = line.trim();
    if (/^#{1,4}\s+/.test(trimmed)) {
      return <Typography.Title key={index} level={5} style={{ margin: '12px 0 6px' }}>{trimmed.replace(/^#{1,4}\s+/, '')}</Typography.Title>;
    }
    if (/^[-*]\s+/.test(trimmed)) {
      return <div key={index} className="ai-evidence-line"><span>{trimmed.replace(/^[-*]\s+/, '')}</span></div>;
    }
    return <Typography.Paragraph key={index} style={{ marginBottom: 8 }}>{trimmed}</Typography.Paragraph>;
  });
}

function normalizeAiPlainText(text: string) {
  return String(text || '')
    .replace(/^#{1,6}\s+/gm, '')
    .replace(/\*\*([^*]+)\*\*/g, '$1')
    .replace(/__([^_]+)__/g, '$1')
    .replace(/`([^`]+)`/g, '$1')
    .trim();
}

function AiAnalysisResultCard({ text }: { text?: string }) {
  if (!text) return <Typography.Text type="secondary">暂无 AI 研判结果，点击顶部“AI 研判”生成。</Typography.Text>;
  const labels = normalizeAiPlainText(extractAiField(text, '研判标签') || extractAiSection(text, '研判标签').split('\n')[0] || '待确认');
  const risk = normalizeAiPlainText(extractAiField(text, '风险等级') || '未知');
  const confidence = extractAiField(text, '置信度') || '-';
  const conclusion = normalizeAiPlainText(extractAiField(text, '结论') || extractAiSection(text, '结论') || '未提取到结构化结论');
  const summary = extractAiSection(text, '摘要') || extractAiSection(text, '结论摘要') || conclusion;
  const evidence = extractAiSection(text, '关键证据') || extractAiSection(text, '证据链分析');
  const labelList = labels.split(/[、,，\s]+/).filter(Boolean);
  const riskColor = /critical|high|高|严重/.test(risk) ? 'red' : /medium|中/.test(risk) ? 'orange' : /low|低/.test(risk) ? 'blue' : 'default';

  return (
    <div className="ai-analysis-card">
      <div className="ai-analysis-hero">
        <div>
          <div className="ai-analysis-conclusion-title">研判结论</div>
          <Typography.Paragraph className="ai-analysis-conclusion-text">{conclusion}</Typography.Paragraph>
          <Space wrap>{labelList.map((item) => <Tag color={item.includes('成功') ? 'red' : item.includes('失败') ? 'orange' : 'geekblue'} key={item}>{item}</Tag>)}</Space>
        </div>
        <div className="ai-analysis-side">
          <div className="ai-analysis-score">
            <span>置信度</span>
            <strong>{confidence}</strong>
          </div>
          <div className="ai-analysis-risk">
            <span>风险等级</span>
            <Tag color={riskColor}>{risk}</Tag>
          </div>
        </div>
      </div>
      <div className="ai-analysis-metrics">
        <div><span>引用经验</span><b>{extractAiField(text, '引用经验') || '无'}</b></div>
        <div><span>研判模式</span><b>{extractAiField(text, '研判模式') || '智能研判（平台证据增强）'}</b></div>
        <div><span>输出状态</span><b>已生成</b></div>
      </div>
      <div className="ai-analysis-section">
        <Typography.Title level={5}>结论摘要</Typography.Title>
        <div className="ai-markdown">{renderSimpleMarkdown(summary)}</div>
      </div>
      {evidence && (
        <div className="ai-analysis-section">
          <Typography.Title level={5}>关键证据</Typography.Title>
          <div className="ai-markdown">{renderSimpleMarkdown(evidence)}</div>
        </div>
      )}
      <div className="ai-analysis-section ai-analysis-fulltext">
        <Typography.Title level={5}>完整研判</Typography.Title>
        <div className="ai-markdown">{renderSimpleMarkdown(text)}</div>
      </div>
    </div>
  );
}

const assetCriticalityColor: Record<string, string> = {
  low: 'default',
  medium: 'blue',
  high: 'orange',
  critical: 'red'
};

const safeHttpUrl = (value: unknown) => {
  const url = String(value || '').trim();
  return /^https?:\/\//i.test(url) ? url : '';
};

const sourceTitle = (source: Record<string, unknown> | undefined) => {
  const title = String(source?.title || '').trim();
  return title || '来源页面';
};

function collectLabels(item: any): string[] {
  let raw: any[] = [];
  if (item?.labels?.length) raw = item.labels;
  else if (item?.judgments?.length) raw = item.judgments;
  else if (item?.details?.[0]?.labels?.length) raw = item.details[0].labels;
  else if (item?.details?.[0]?.judgments?.length) raw = item.details[0].judgments;
  return raw.map((label: any) => (typeof label === 'string' ? label : label?.name)).filter(Boolean);
}

function TiSummary({ result }: { result: Record<string, any> }) {
  const sourceLabel = (item: any) => {
    const s = item?.source || item?.sources?.[0];
    if (s === 'threatbook') return '微步TI';
    if (s === 'nsfocus') return '绿盟 NTI 情报';
    if (s === 'qianxin') return '奇安信 TI 情报';
    if (s === 'dbapp') return '安恒 TI 情报';
    return s || '未查询';
  };
  const displayResult = JSON.parse(JSON.stringify(result || {}, (_key, value) => value === 'threatbook' ? '微步TI' : value));
  const blocks = [
    { title: '源IP威胁情报', data: result?.src_ip_ti },
    { title: '目的IP威胁情报', data: result?.dst_ip_ti }
  ];
  return (
    <Space direction="vertical" className="full-width">
      <div className="ti-summary">
        {blocks.map((block) => {
          const labels = collectLabels(block.data);
          const location = block.data?.location_str;
          return (
            <div className="ti-card" key={block.title}>
              <Typography.Title level={5}>{block.title}</Typography.Title>
              <Space direction="vertical" size={2}>
                <Typography.Text type="secondary">{block.data?.ip || '无 IP'}</Typography.Text>
                {location && <Typography.Text type="secondary" style={{ fontSize: 12 }}>{location}</Typography.Text>}
              </Space>
              <div style={{ marginTop: 8 }}><Tag color="geekblue">{sourceLabel(block.data)}</Tag></div>
              <div className="tag-cloud">
                {labels.length ? labels.map((item) => <Tag color={block.data?.is_malicious ? 'red' : 'blue'} key={item}>{item}</Tag>) : <Tag>暂无标签</Tag>}
              </div>

              {block.data?.threat_events?.length > 0 && (
                <div className="threat-events" style={{ marginTop: 12 }}>
                  <Typography.Text strong style={{ fontSize: 13, display: 'block', marginBottom: 4 }}>威胁事件详情</Typography.Text>
                  {block.data.threat_events.map((ev: any, idx: number) => (
                    <div key={idx} style={{ padding: '8px', background: '#f5f5f5', borderRadius: '4px', marginBottom: 8, border: '1px solid #eee' }}>
                      <Space wrap size={[4, 8]} style={{ marginBottom: 4 }}>
                        {ev.alert_name && <Typography.Text strong>{ev.alert_name}</Typography.Text>}
                        {ev.malicious_type && <Tag color="error">{ev.malicious_type}</Tag>}
                        {ev.risk && <Tag color={ev.risk === 'high' || ev.risk === 'critical' ? 'red' : 'orange'}>风险:{ev.risk}</Tag>}
                        {ev.confidence && <Tag>置信度:{ev.confidence}</Tag>}
                      </Space>
                      <div style={{ fontSize: 12, color: '#666' }}>
                        {ev.kill_chain && <span>KillChain: {ev.kill_chain} | </span>}
                        {ev.current_status && <span>状态: {ev.current_status} | </span>}
                        {ev.etime && <span>时间: {ev.etime}</span>}
                      </div>
                      {ev.malicious_family?.length > 0 && (
                        <div style={{ fontSize: 12, marginTop: 4 }}>
                          家族: {ev.malicious_family.join(', ')}
                        </div>
                      )}
                      {ev.ttp && (
                        <Collapse size="small" ghost items={[{
                          key: 'ttp',
                          label: '查看 TTP 详情',
                          children: <pre style={{ fontSize: 11, background: '#fff', padding: 4, maxHeight: 150, overflow: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{ev.ttp}</pre>
                        }]} />
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
      <Collapse size="small" items={[{ key: 'raw', label: '展开完整 JSON', children: <pre>{JSON.stringify(displayResult, null, 2)}</pre> }]} />
    </Space>
  );
}

function AssetCard({ title, asset }: { title: string; asset?: Record<string, any> }) {
  const ip = asset?.ip;
  const { data: ipCheck } = useQuery({
    queryKey: ['ip-check', ip],
    queryFn: async () => (await api.post('/api/ip-lists/check', { ip })).data,
    enabled: !!ip
  });

  if (!asset || !Object.keys(asset).length) {
    return (
      <Card size="small" title={title}>
        <Typography.Text type="secondary">未命中企业资产</Typography.Text>
      </Card>
    );
  }
  const criticalityLabel: Record<string, string> = {
    low: '低',
    medium: '中',
    high: '高',
    critical: '极高'
  };
  const fingerprints = asset.fingerprints || {};
  const ipMatches = ipCheck?.matches || [];
  return (
    <Card size="small" title={title}>
      <Space direction="vertical" size={6} className="full-width">
        <Space wrap>
          <Typography.Text strong>{asset.name || asset.ip || asset.domain}</Typography.Text>
          <Tag color={assetCriticalityColor[asset.criticality] || 'blue'}>{criticalityLabel[asset.criticality] || asset.criticality}</Tag>
        </Space>
        <Typography.Text type="secondary">{asset.ip || '-'} {asset.domain ? `/ ${asset.domain}` : ''}</Typography.Text>
        <Typography.Text>区域：{asset.area || '-'} / 负责人：{asset.owner || '-'}</Typography.Text>
        <Typography.Text>部门：{asset.department || '-'} / 环境：{asset.environment || '-'}</Typography.Text>
        <Space wrap>{(asset.tags || []).map((tag: string) => <Tag key={tag}>{tag}</Tag>)}</Space>
        {ipMatches.length > 0 && (
          <div style={{ marginTop: 4 }}>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>IP 名单：</Typography.Text>
            <Space wrap size={4}>
              {ipMatches.map((item: any, idx: number) => (
                <Tag key={idx} color={item.list === 'blacklist' ? 'red' : 'blue'}>
                  {item.list === 'blacklist' ? '黑名单' : '白名单'}: {item.range}
                </Tag>
              ))}
            </Space>
          </div>
        )}
        <Collapse size="small" ghost items={[{ key: 'fingerprints', label: '指纹详情', children: <pre>{JSON.stringify(fingerprints, null, 2)}</pre> }]} />
      </Space>
    </Card>
  );
}

function isTerminal(alert: Alert) {
  return ['false_positive', 'ignored', 'disposed'].includes(alert.status);
}

function canClaim(user: User | undefined, alert: Alert) {
  if (!user || isTerminal(alert) || alert.assignee_id) return false;
  if (hasRole(user, 'admin')) return ['analysis', 'disposal'].includes(alert.current_group);
  return hasRole(user, groupRole[alert.current_group]);
}

function canRelease(user: User | undefined, alert: Alert) {
  if (!user || isTerminal(alert) || !alert.assignee_id) return false;
  return hasRole(user, 'admin') || alert.assignee_id === user.id;
}

function availableStatuses(user: User | undefined, alert: Alert) {
  if (!user) return [];
  if (hasRole(user, 'admin')) {
    return ['analysis', 'disposal', 'false_positive', 'ignored', 'disposed'].filter(s => s !== alert.status);
  }
  if (isTerminal(alert)) return [];
  // 收集所有角色可用的状态，支持多角色用户
  const statuses: string[] = [];
  if (hasRole(user, 'monitor')) {
    if (alert.current_group === 'analysis' && !alert.assignee_id && alert.created_by_id === user.id) {
      statuses.push('ignored');
    }
  }
  if (hasRole(user, 'analyst')) {
    if (alert.current_group === 'analysis' && alert.assignee_id === user.id) {
      statuses.push('false_positive', 'ignored', 'disposal');
    }
  }
  if (hasRole(user, 'disposer')) {
    if (alert.current_group === 'disposal' && alert.assignee_id === user.id) {
      statuses.push('analysis', 'false_positive', 'ignored', 'disposed');
    }
  }
  return Array.from(new Set(statuses));
}

function commonAvailableStatuses(user: User | undefined, alerts: Alert[]) {
  if (!alerts.length) return [];
  const [first, ...rest] = alerts;
  return availableStatuses(user, first).filter((status) =>
    rest.every((alert) => availableStatuses(user, alert).includes(status))
  );
}

function ownerDisplay(alert: Alert, users: User[]) {
  if (!alert.assignee_id) return '未认领';
  const user = users.find((item) => item.id === alert.assignee_id);
  return `${groupLabel[alert.current_group] || ''}-${user?.display_name || '未知'}`;
}

type TransitionState = { alerts: Alert[]; mode: 'single' | 'batch' } | null;

export default function AlertWorkbench({
  initialAlertHash,
  onClearInitialAlertHash
}: {
  initialAlertHash?: string;
  onClearInitialAlertHash?: () => void;
}) {
  const [selected, setSelected] = useState<Alert | null>(null);
  const [q, setQ] = useState(initialAlertHash || '');
  const [dismissedAutoHash, setDismissedAutoHash] = useState('');
  const [status, setStatus] = useState<string | undefined>();
  const [currentGroup, setCurrentGroup] = useState<string | undefined>();
  const [assigneeId, setAssigneeId] = useState<number | undefined>();
  const [range, setRange] = useState<[Dayjs, Dayjs] | null>(null);
  const [selectedRowKeys, setSelectedRowKeys] = useState<Key[]>([]);
  const [csvTemplateId, setCsvTemplateId] = useState<number | undefined>();
  const [transitionState, setTransitionState] = useState<TransitionState>(null);
  const [assignTarget, setAssignTarget] = useState<Alert | null>(null);
  const [historyExpanded, setHistoryExpanded] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [refreshInterval, setRefreshInterval] = useState(30_000);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [transitionForm] = Form.useForm();
  const [assignForm] = Form.useForm();
  const watchedStatus = Form.useWatch('status', transitionForm);
  const watchedClosureAction = Form.useWatch('closure_action', transitionForm);
  const watchedBlockDeviceIds = Form.useWatch('block_device_ids', transitionForm);
  const queryClient = useQueryClient();

  const copyText = async (text?: string) => {
    if (!text) {
      message.warning('暂无可复制内容');
      return;
    }
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        message.success('已复制');
        return;
      }
      const textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      message.success('已复制');
    } catch {
      message.error('复制失败，请手动选择文本复制');
    }
  };

  const formattedParsedFields = useMemo(() => {
    if (!selected?.parsed_fields) return '';
    return JSON.stringify(selected.parsed_fields, null, 2);
  }, [selected?.parsed_fields]);

  const codeStyle: React.CSSProperties = {
    fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
    fontSize: 12,
    lineHeight: 1.6,
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-all',
    margin: 0,
    padding: 0,
    background: 'transparent',
    border: 'none',
  };

  useEffect(() => {
    if (initialAlertHash) {
      setQ(initialAlertHash);
      setDismissedAutoHash('');
    }
  }, [initialAlertHash]);

  const { data: currentUser } = useQuery({
    queryKey: ['me'],
    queryFn: async () => (await api.get<User>('/api/auth/me')).data
  });
  const isAdmin = hasRole(currentUser, 'admin');
  const isViewer = userRoles(currentUser).length === 1 && hasRole(currentUser, 'viewer');

  const alertStart = range?.[0]?.format('YYYY-MM-DD HH:mm:ss');
  const alertEnd = range?.[1]?.format('YYYY-MM-DD HH:mm:ss');
  const { data: alertPage = { rows: [], total: 0 }, isLoading, isFetching, refetch } = useQuery({
    queryKey: ['alerts', q, status, currentGroup, assigneeId, alertStart, alertEnd, page, pageSize],
    queryFn: async () => {
      const res = await api.get<Alert[]>('/api/alerts', {
      params: {
        q,
        status,
        current_group: currentGroup,
        assignee_id: assigneeId,
        start_date: alertStart,
        end_date: alertEnd,
        limit: pageSize,
        offset: (page - 1) * pageSize
      }
    });
      return { rows: res.data, total: Number(res.headers['x-total-count'] || res.data.length) };
    },
    placeholderData: keepPreviousData,
    refetchInterval: autoRefresh ? refreshInterval : false
  });
  const data = alertPage.rows;
  const { data: history = [] } = useQuery({
    queryKey: ['alerts', selected?.id, 'history'],
    queryFn: async () => (await api.get<any[]>(`/api/alerts/${selected?.id}/history`)).data,
    enabled: !!selected
  });
  const { data: users = [] } = useQuery({
    queryKey: ['users'],
    queryFn: async () => (await api.get<User[]>('/api/users')).data,
    staleTime: 5 * 60 * 1000  // 5分钟缓存
  });
  const { data: devices = [] } = useQuery({
    queryKey: ['devices'],
    queryFn: async () => (await api.get<Device[]>('/api/devices')).data,
    staleTime: 5 * 60 * 1000  // 5分钟缓存
  });
  const { data: templates = [] } = useQuery({
    queryKey: ['templates'],
    queryFn: async () => (await api.get<Template[]>('/api/templates')).data,
    staleTime: 5 * 60 * 1000  // 5分钟缓存
  });
  const { data: settings = [] } = useQuery({
    queryKey: ['settings'],
    queryFn: async () => (await api.get<Array<{ key: string; value: any }>>('/api/settings')).data,
    staleTime: 5 * 60 * 1000  // 5分钟缓存
  });
  const csvTemplates = templates.filter((item) => item.type === 'csv');
  useEffect(() => {
    if (!csvTemplates.length) return;
    if (csvTemplateId && csvTemplates.some((item) => item.id === csvTemplateId)) return;
    const defaultTemplate = csvTemplates.find((item) => item.is_default) || csvTemplates[0];
    setCsvTemplateId(defaultTemplate?.id);
  }, [csvTemplates, csvTemplateId]);

  useEffect(() => {
    if (!initialAlertHash || dismissedAutoHash === initialAlertHash) return;
    const hit = data.find((item) => item.alert_hash === initialAlertHash);
    if (hit) {
      setSelected(hit);
    }
  }, [data, dismissedAutoHash, initialAlertHash]);

  useEffect(() => {
    setPage(1);
  }, [q, status, currentGroup, assigneeId, alertStart, alertEnd]);

  useEffect(() => {
    if (!selected) return;
    const latest = data.find((item) => item.id === selected.id);
    if (latest && latest.updated_at !== selected.updated_at) {
      setSelected(latest);
      // 同步更新 transitionState 中的 alert 对象
      setTransitionState((current) => {
        if (!current) return null;
        const updatedAlerts = current.alerts.map((a) => (a.id === latest.id ? latest : a));
        return { ...current, alerts: updatedAlerts };
      });
      queryClient.invalidateQueries({ queryKey: ['alerts', latest.id, 'history'] });
    }
  }, [data, queryClient, selected]);

  const refreshAlertState = (alert?: Alert) => {
    if (alert) setSelected((current) => (current?.id === alert.id ? alert : current));
    queryClient.invalidateQueries({ queryKey: ['alerts'] });
    queryClient.invalidateQueries({ queryKey: ['dashboard'] });
    queryClient.invalidateQueries({ queryKey: ['messages'] });
    queryClient.invalidateQueries({ queryKey: ['messages-unread'] });
    if (alert) queryClient.invalidateQueries({ queryKey: ['alerts', alert.id, 'history'] });
  };

  const claim = useMutation({
    mutationFn: async (alert: Alert) => (await api.post<Alert>(`/api/alerts/${alert.id}/claim`, { updated_at: alert.updated_at })).data,
    onSuccess: (alert) => {
      refreshAlertState(alert);
      message.success('已认领告警');
      // 认领后自动弹出流转对话框（如果有可用的流转状态）
      // 使用 API 返回的 alert 对象（包含最新的 updated_at）
      const transitions = availableStatuses(currentUser, alert);
      if (transitions.length > 0) {
        setTimeout(() => openTransition([alert], 'single'), 300);
      }
    },
    onError: (error: any) => message.error(error?.response?.data?.detail || '认领失败')
  });

  const release = useMutation({
    mutationFn: async ({ alert, force }: { alert: Alert; force?: boolean }) =>
      (await api.post<Alert>(`/api/alerts/${alert.id}/${force ? 'force-release' : 'release-claim'}`, { updated_at: alert.updated_at })).data,
    onSuccess: (alert) => {
      refreshAlertState(alert);
      message.success('认领已释放');
    },
    onError: (error: any) => message.error(error?.response?.data?.detail || '释放失败')
  });

  const assign = useMutation({
    mutationFn: async (payload: { alert: Alert; assignee_id: number }) =>
      (await api.post<Alert>(`/api/alerts/${payload.alert.id}/assign`, { assignee_id: payload.assignee_id, updated_at: payload.alert.updated_at })).data,
    onSuccess: (alert) => {
      setAssignTarget(null);
      assignForm.resetFields();
      refreshAlertState(alert);
      message.success('已重新指派');
    },
    onError: (error: any) => message.error(error?.response?.data?.detail || '指派失败')
  });

  const transition = useMutation({
    mutationFn: async (values: any) => {
      if (!transitionState) return null;
      if (transitionState.mode === 'batch') {
        return (await api.post('/api/alerts/batch-transition', { ids: transitionState.alerts.map((item) => item.id), ...values })).data;
      }
      const alert = transitionState.alerts[0];
      return (await api.post<Alert>(`/api/alerts/${alert.id}/transition`, { ...values, updated_at: alert.updated_at })).data;
    },
    onSuccess: (result: any) => {
      if (result?.errors?.length) {
        message.warning(`批量流转完成：成功 ${result.updated} 条，失败 ${result.errors.length} 条`);
      } else {
        message.success(transitionState?.mode === 'batch' ? '批量流转完成' : '状态已流转');
      }
      if (result && !result.errors) refreshAlertState(result as Alert);
      else refreshAlertState();
      setTransitionState(null);
      setSelectedRowKeys([]);
      transitionForm.resetFields();
    },
    onError: (error: any) => message.error(error?.response?.data?.detail || '流转失败')
  });

  const ai = useMutation({
    mutationFn: async (id: number) => (await api.post(`/api/alerts/${id}/ai-analysis`)).data,
    onSuccess: (alert) => {
      setSelected(alert);
      refreshAlertState(alert);
      message.success('AI 研判完成');
    }
  });

  const ti = useMutation({
    mutationFn: async (id: number) => (await api.post(`/api/alerts/${id}/ti-query`)).data,
    onSuccess: (alert) => {
      setSelected(alert);
      refreshAlertState(alert);
      message.success('威胁情报查询完成');
    }
  });

  const aiExtract = useMutation({
    mutationFn: async ({ id }: { id: number }) => {
      const res = await api.post('/api/ai/experiences/extract', { alert_id: id, save: true });
      return res.data;
    },
    onSuccess: () => {
      message.success('已自动提取并保存至经验库');
      queryClient.invalidateQueries({ queryKey: ['ai-experiences'] });
    },
    onError: (error: any) => message.error(error?.response?.data?.detail || '提取失败')
  });

  const webhookConfig = settings.find((item) => item.key === 'webhook')?.value || {};
  const webhookProvider = webhookConfig.provider;
  const webhookReady = webhookConfig.enabled !== false && (
    webhookProvider
      ? !!(webhookConfig[webhookProvider]?.url || webhookConfig.url)
      : ['dingtalk', 'wecom', 'feishu'].some((key) => webhookConfig[key]?.enabled && webhookConfig[key]?.url)
  );

  const webhook = useMutation({
    mutationFn: async (id: number) => (await api.post(`/api/alerts/${id}/send-webhook`)).data,
    onSuccess: () => message.success('已发送通报消息'),
    onError: (error: any) => message.error(error?.response?.data?.detail || '发送失败')
  });

  const remove = useMutation({
    mutationFn: async (id: number) => (await api.delete(`/api/alerts/${id}`)).data,
    onSuccess: () => {
      setSelected(null);
      refreshAlertState();
      message.success('告警已删除');
    }
  });

  const batchRemove = useMutation({
    mutationFn: async () => (await api.post('/api/alerts/batch-delete', { ids: selectedRowKeys })).data,
    onSuccess: (result) => {
      setSelectedRowKeys([]);
      refreshAlertState();
      message.success(`批量删除完成：成功 ${result.deleted} 条${result.missing ? `，跳过 ${result.missing} 条（已删除）` : ''}`);
    },
    onError: (error: any) => message.error(error?.response?.data?.detail || '批量删除失败')
  });

  const userName = (id?: number | null) => users.find((item) => item.id === id)?.display_name || '未记录';
  const optionalUserName = (id?: number | null) => users.find((item) => item.id === id)?.display_name || '';
  const deviceName = (id?: number | null) => devices.find((item) => item.id === id)?.name || '未记录';
  const exportParams = {
    q: q || undefined,
    status,
    current_group: currentGroup,
    assignee_id: assigneeId,
    start_date: range?.[0]?.format('YYYY-MM-DD HH:mm:ss'),
    end_date: range?.[1]?.format('YYYY-MM-DD HH:mm:ss'),
    template_id: csvTemplateId
  };
  const exportCsv = async () => {
    const response = await api.get('/api/exports/alerts.csv', { params: exportParams, responseType: 'blob' });
    const url = window.URL.createObjectURL(new Blob([response.data]));
    const link = document.createElement('a');
    link.href = url;
    const suffix = range ? `_${range[0].format('YYYYMMDD')}_${range[1].format('YYYYMMDD')}` : '';
    link.download = `alerts_filtered${suffix}.csv`;
    link.click();
    window.URL.revokeObjectURL(url);
  };

  const openTransition = (alerts: Alert[], mode: 'single' | 'batch') => {
    if (!alerts.length) return;
    const options = mode === 'single' ? availableStatuses(currentUser, alerts[0]) : commonAvailableStatuses(currentUser, alerts);
    if (!options.length) {
      message.warning(mode === 'batch' ? '所选告警没有共同可执行的流转状态' : '当前告警暂无可执行的流转状态');
      return;
    }
    transitionForm.setFieldsValue({
      status: options[0],
      disposal_target: 'src_ip',
      disposal_action: 'repair',
      closure_action: options[0] === 'false_positive' ? 'false_positive' : 'ignore',
      closure_target: 'src_ip',
      false_positive_reason: '',
      block_device_ids: [],
      block_at: dayjs(),
      response_note: '',
      response_owner_id: undefined
    });
    setTransitionState({ alerts, mode });
  };

  const closeTransition = () => {
    setTransitionState(null);
    transitionForm.resetFields();
  };

  const selectedAlerts = data.filter((item) => selectedRowKeys.includes(item.id));
  const batchTransitionOptions = commonAvailableStatuses(currentUser, selectedAlerts);
  const transitionOptions = transitionState
    ? transitionState.mode === 'single'
      ? availableStatuses(currentUser, transitionState.alerts[0])
      : commonAvailableStatuses(currentUser, transitionState.alerts)
    : [];
  const closureOptions = watchedStatus === 'false_positive'
    ? [{ value: 'false_positive', label: '仅误报' }, { value: 'false_positive_whitelist', label: '误报并加白' }]
    : [{ value: 'ignore', label: '仅忽略' }, { value: 'ignore_whitelist', label: '忽略并加白' }];
  const needsFalsePositiveReason = watchedStatus === 'false_positive' && !!transitionState?.alerts.some((item) => item.current_group === 'disposal');
  const transitionDisposalAction = useMemo(() => {
    if (!transitionState?.alerts.length) return '';
    const actions = Array.from(new Set(transitionState.alerts.map((item) => item.disposal_action).filter(Boolean)));
    return actions.length === 1 ? actions[0] : '';
  }, [transitionState]);
  const needsBlockFields = watchedStatus === 'disposed' && transitionDisposalAction === 'block';
  const needsEmergencyFields = watchedStatus === 'disposed' && transitionDisposalAction === 'emergency';
  const blockDevices = devices.filter((item) => item.device_role === 'block');
  const activeResponseUsers = users.filter((item) => hasRole(item, 'disposer') && item.is_active);
  const serializeTransitionValues = (values: any) => ({
    ...values,
    block_at: values.block_at ? values.block_at.format('YYYY-MM-DD HH:mm:ss') : undefined,
  });
  const closeDrawer = () => {
    if (initialAlertHash && selected?.alert_hash === initialAlertHash) {
      setDismissedAutoHash(initialAlertHash);
      onClearInitialAlertHash?.();
    }
    setSelected(null);
    setHistoryExpanded(false);
  };

  // 列宽状态
  const { widths: columnWidths, onResize, resetWidth } = useColumnWidths({
    alert_code: 130,
    created_at: 100,
    source_ip: 110,
    destination_ip: 110,
    event_type: 150,
    current_group: 80,
    status: 100,
    assignee_id: 90,
    actions: 280,
  });

  const columns = useMemo(
    () => [
      {
        title: <ResizableHeader label="告警ID" columnKey="alert_code" onResize={onResize} onReset={resetWidth} />,
        dataIndex: 'alert_code',
        width: columnWidths.alert_code,
        render: (v: string) => <Typography.Text className="table-nowrap">{v}</Typography.Text>
      },
      {
        title: <ResizableHeader label="创建时间" columnKey="created_at" onResize={onResize} onReset={resetWidth} />,
        dataIndex: 'created_at',
        width: columnWidths.created_at,
        render: (v: string) => (
          <div className="table-time">
            <span>{dayjs(v).format('YYYY-MM-DD')}</span>
            <b>{dayjs(v).format('HH:mm:ss')}</b>
          </div>
        )
      },
      {
        title: <ResizableHeader label="源IP" columnKey="source_ip" onResize={onResize} onReset={resetWidth} />,
        dataIndex: 'source_ip',
        width: columnWidths.source_ip,
        render: (v: string) => <Typography.Text className="table-nowrap">{v || '-'}</Typography.Text>
      },
      {
        title: <ResizableHeader label="目的IP" columnKey="destination_ip" onResize={onResize} onReset={resetWidth} />,
        dataIndex: 'destination_ip',
        width: columnWidths.destination_ip,
        render: (v: string) => <Typography.Text className="table-nowrap">{v || '-'}</Typography.Text>
      },
      {
        title: <ResizableHeader label="事件类型" columnKey="event_type" onResize={onResize} onReset={resetWidth} />,
        dataIndex: 'event_type',
        width: columnWidths.event_type,
        render: (v: string) => <Typography.Text className="table-nowrap table-event-type" title={v || ''}>{v || '未识别'}</Typography.Text>
      },
      {
        title: <ResizableHeader label="所属组" columnKey="current_group" onResize={onResize} onReset={resetWidth} />,
        dataIndex: 'current_group',
        width: columnWidths.current_group,
        render: (v: string) => <Typography.Text className="table-nowrap">{groupLabel[v] || v}</Typography.Text>
      },
      {
        title: <ResizableHeader label="状态" columnKey="status" onResize={onResize} onReset={resetWidth} />,
        dataIndex: 'status',
        width: columnWidths.status,
        render: (v: string, row: Alert) => (
          <Space direction="vertical" size={2}>
            <Tag color={statusColor[v]}>{statusLabel[v] || v}</Tag>
            {!isTerminal(row) && <Tag color={row.assignee_id ? 'green' : 'orange'}>{row.assignee_id ? '已认领' : '未认领'}</Tag>}
          </Space>
        )
      },
      {
        title: <ResizableHeader label="负责人" columnKey="assignee_id" onResize={onResize} onReset={resetWidth} />,
        dataIndex: 'assignee_id',
        width: columnWidths.assignee_id,
        render: (_: number | null, row: Alert) => <Typography.Text className="table-nowrap">{ownerDisplay(row, users)}</Typography.Text>
      },
      {
        title: <ResizableHeader label="操作" columnKey="actions" onResize={onResize} onReset={resetWidth} />,
        width: columnWidths.actions,
        render: (_: unknown, row: Alert) => {
          const transitions = availableStatuses(currentUser, row);
          return (
            <div className="table-action-grid">
              {!isViewer && canClaim(currentUser, row) && <Button size="small" type="primary" loading={claim.isPending} onClick={() => claim.mutate(row)}>认领</Button>}
              {!isViewer && canRelease(currentUser, row) && <Button size="small" loading={release.isPending} onClick={() => release.mutate({ alert: row })}>释放</Button>}
              {!isViewer && transitions.length > 0 && <Button size="small" onClick={() => openTransition([row], 'single')}>流转</Button>}
              {isAdmin && !isTerminal(row) && <Button size="small" onClick={() => { setAssignTarget(row); assignForm.resetFields(); }}>指派</Button>}
              <Button size="small" onClick={() => setSelected(row)}>详情</Button>
              {isAdmin && (
                <Popconfirm title="删除该告警？" onConfirm={() => remove.mutate(row.id)}>
                  <Button size="small" danger>删除</Button>
                </Popconfirm>
              )}
            </div>
          );
        }
      }
    ],
    [users, currentUser, isViewer, isAdmin, claim.isPending, release.isPending, remove, columnWidths, onResize, resetWidth]
  );

  const renderHistoryItem = (item: any) => {
    const time = dayjs(item.created_at).format('YYYY-MM-DD HH:mm:ss');
    const actor = item.actor_name || item.actor_username || '系统';
    const changes = item.detail?.changes || {};
    if (changes.status) {
      return <li key={item.id} style={{ marginBottom: 8, fontSize: 13 }}>
        <Typography.Text type="secondary">{time}</Typography.Text>
        <Typography.Text strong style={{ margin: '0 8px' }}>{actor}</Typography.Text>
        将状态从 <Tag>{statusLabel[changes.status.old] || changes.status.old || '未知'}</Tag> 改为了 <Tag color="blue">{statusLabel[changes.status.new] || changes.status.new || '未知'}</Tag>
      </li>;
    }
    if (changes.disposal_target) {
      return <li key={item.id} style={{ marginBottom: 8, fontSize: 13 }}>
        <Typography.Text type="secondary">{time}</Typography.Text>
        <Typography.Text strong style={{ margin: '0 8px' }}>{actor}</Typography.Text>
        将处置对象设为 <Tag>{targetLabel[changes.disposal_target.new] || changes.disposal_target.new}</Tag>
      </li>;
    }
    if (changes.disposal_action) {
      return <li key={item.id} style={{ marginBottom: 8, fontSize: 13 }}>
        <Typography.Text type="secondary">{time}</Typography.Text>
        <Typography.Text strong style={{ margin: '0 8px' }}>{actor}</Typography.Text>
        将处置动作设为 <Tag color="volcano">{disposalActionLabel[changes.disposal_action.new] || changes.disposal_action.new}</Tag>
      </li>;
    }
    if (changes.assignee_id) {
      return <li key={item.id} style={{ marginBottom: 8, fontSize: 13 }}>
        <Typography.Text type="secondary">{time}</Typography.Text>
        <Typography.Text strong style={{ margin: '0 8px' }}>{actor}</Typography.Text>
        将负责人从 <Typography.Text code>{userName(changes.assignee_id.old)}</Typography.Text> 改为了 <Typography.Text code>{userName(changes.assignee_id.new)}</Typography.Text>
      </li>;
    }
    const actionMap: Record<string, string> = {
      'alert.create': '创建了告警',
      'alert.claim': '认领了告警',
      'alert.release_claim': '释放了认领',
      'alert.force_release': '强制解锁了告警',
      'alert.force_assign': '重新指派了告警',
      'alert.transition': '流转了告警状态',
      'alert.webhook_send': '发送了通报消息',
      'alert.delete': '删除了告警',
      'alert.batch_delete': '批量删除了告警',
      'alert.ai_analysis': '触发了 AI 研判',
      'alert.ti_query': '查询了威胁情报'
    };
    return <li key={item.id} style={{ marginBottom: 8, fontSize: 13 }}>
      <Typography.Text type="secondary">{time}</Typography.Text>
      <Typography.Text strong style={{ margin: '0 8px' }}>{actor}</Typography.Text>
      {actionMap[item.action] || `执行了 ${item.action}`}
    </li>;
  };

  const activeAssignUsers = users.filter((item) => hasRole(item, groupRole[assignTarget?.current_group || '']) && item.is_active);

  return (
    <div className="page">
      <div className="page-toolbar">
        <div>
          <Typography.Title level={4}>告警工作台</Typography.Title>
          <Typography.Text type="secondary">协作告警表格用于管理和协作处理安全告警</Typography.Text>
        </div>
        <Space wrap>
          <Input.Search placeholder="搜索告警 Hash / IP / 事件类型" allowClear value={q} onChange={(event) => setQ(event.target.value)} onSearch={setQ} style={{ width: 300 }} />
          <DatePicker.RangePicker showTime format="YYYY-MM-DD HH:mm:ss" value={range} onChange={(value) => setRange(value as [Dayjs, Dayjs] | null)} />
          <Select allowClear placeholder="负责人" style={{ width: 150 }} value={assigneeId} onChange={setAssigneeId} options={users.map((item) => ({ value: item.id, label: item.display_name }))} />
          <Select allowClear placeholder="所属组" style={{ width: 150 }} value={currentGroup} onChange={setCurrentGroup} options={Object.entries(groupLabel).map(([value, label]) => ({ value, label }))} />
          <Select allowClear placeholder="状态" style={{ width: 140 }} value={status} onChange={setStatus} options={Object.entries(statusLabel).map(([value, label]) => ({ value, label }))} />
          <Select allowClear placeholder="CSV 模板" style={{ width: 170 }} value={csvTemplateId} onChange={setCsvTemplateId} options={csvTemplates.map((item) => ({ value: item.id, label: item.name }))} />
          <Button type="primary" onClick={exportCsv}>导出筛选结果 <HelpTip title="导出内容会复用当前工作台筛选条件，包括关键词、时间、负责人、状态和 CSV 模板。" /></Button>
        </Space>
      </div>
      <div className="panel-toolbar">
        <Space wrap>
          <Typography.Text type="secondary">已选择 {selectedRowKeys.length} 条</Typography.Text>
          <Button icon={<ReloadOutlined />} loading={isFetching} onClick={() => refetch()}>手动刷新</Button>
          <Switch checked={autoRefresh} onChange={setAutoRefresh} checkedChildren="自动刷新" unCheckedChildren="自动刷新" />
          <Select
            disabled={!autoRefresh}
            value={refreshInterval}
            onChange={setRefreshInterval}
            style={{ width: 110 }}
            options={refreshIntervalOptions}
          />
          {!isViewer && (
            <Button disabled={!selectedRowKeys.length || !batchTransitionOptions.length} onClick={() => openTransition(selectedAlerts, 'batch')}>
              批量流转
            </Button>
          )}
          {isAdmin && (
            <Popconfirm title={`确定要删除选中的 ${selectedRowKeys.length} 条告警吗？`} onConfirm={() => batchRemove.mutate()} disabled={!selectedRowKeys.length}>
              <Button danger disabled={!selectedRowKeys.length} loading={batchRemove.isPending}>批量删除</Button>
            </Popconfirm>
          )}
        </Space>
      </div>
      <Table
        rowKey="id"
        loading={isLoading}
        dataSource={data}
        columns={columns}
        rowSelection={{ selectedRowKeys, onChange: setSelectedRowKeys }}
        className="alert-workbench-table"
        scroll={{
          x: Math.max(1200, Object.values(columnWidths).reduce((total, width) => total + width, 0) + 32),
          y: 600,
        }}
        virtual
        pagination={{
          current: page,
          pageSize,
          total: alertPage.total,
          pageSizeOptions: ['10', '20', '50', '100', '200', '500', '1000'],
          showSizeChanger: true,
          showTotal: (total) => `共 ${total} 条`,
          onChange: (nextPage, nextPageSize) => {
            setPage(nextPage);
            setPageSize(nextPageSize);
            setSelectedRowKeys([]);
          }
        }}
      />

      <Drawer open={!!selected} onClose={closeDrawer} width={980} title="告警详情" className="alert-detail-drawer">
        {selected && (
          <div className="alert-detail">
            <section className="alert-detail-hero">
              <div className="alert-detail-hero-main">
                <Space wrap size={[8, 8]}>
                  <Tag color={statusColor[selected.status]}>{statusLabel[selected.status] || selected.status}</Tag>
                  <Tag color={selected.severity === 'critical' ? 'red' : selected.severity === 'high' ? 'volcano' : selected.severity === 'medium' ? 'orange' : 'blue'}>
                    {({ critical: '极高', high: '高', medium: '中', low: '低' }[selected.severity as string] || selected.severity || '未知')}
                  </Tag>
                  {selected.is_emergency && <Tag color="red">应急</Tag>}
                  <Tag>{groupLabel[selected.current_group] || selected.current_group}</Tag>
                </Space>
                <Typography.Title level={4} className="alert-detail-title">
                  {selected.event_type || '未识别事件类型'}
                </Typography.Title>
                <Space wrap split={<Typography.Text type="secondary">→</Typography.Text>}>
                  <Typography.Text code>{selected.source_ip || '无源 IP'}</Typography.Text>
                  <Typography.Text code>{selected.destination_ip || '无目的 IP'}</Typography.Text>
                </Space>
                <div className="alert-detail-meta">
                  <Typography.Text type="secondary">告警ID：{selected.alert_code}</Typography.Text>
                  <Typography.Text type="secondary">负责人：{ownerDisplay(selected, users)}</Typography.Text>
                  <Typography.Text type="secondary">更新时间：{dayjs(selected.updated_at).format('YYYY-MM-DD HH:mm:ss')}</Typography.Text>
                </div>
              </div>
            </section>

            <div className="alert-detail-actions">
              <Space wrap>
                {!isViewer && canClaim(currentUser, selected) && <Button type="primary" loading={claim.isPending} onClick={() => claim.mutate(selected)}>认领</Button>}
                {!isViewer && canRelease(currentUser, selected) && <Button loading={release.isPending} onClick={() => release.mutate({ alert: selected })}>释放认领</Button>}
                {isAdmin && !isTerminal(selected) && selected.assignee_id && <Button danger loading={release.isPending} onClick={() => release.mutate({ alert: selected, force: true })}>强制解锁</Button>}
                {!isViewer && availableStatuses(currentUser, selected).length > 0 && <Button onClick={() => openTransition([selected], 'single')}>状态流转</Button>}
                {isAdmin && !isTerminal(selected) && <Button onClick={() => { setAssignTarget(selected); assignForm.resetFields(); }}>重新指派</Button>}
                <Button type="primary" loading={ai.isPending} onClick={() => ai.mutate(selected.id)} disabled={isViewer}>AI 研判</Button>
                <Button icon={<Brain size={15} />} loading={aiExtract.isPending} onClick={() => aiExtract.mutate({ id: selected.id })} disabled={isViewer}>AI 经验提取</Button>
                <Button loading={ti.isPending} onClick={() => ti.mutate(selected.id)} disabled={isViewer}>查询情报</Button>
                <Button icon={<SendOutlined />} onClick={() => webhook.mutate(selected.id)} disabled={isViewer || !webhookReady || webhook.isPending}>发送通报</Button>
              </Space>
            </div>

            <Tabs
              className="alert-detail-tabs"
              defaultActiveKey="overview"
              items={[
                {
                  key: 'overview',
                  label: '概览',
                  children: (
                    <Space direction="vertical" className="full-width" size="middle">
                      {safeHttpUrl(selected.source_context?.url) && (
                        <div className="detail-section source-section">
                          <div>
                            <Tag color="geekblue">浏览器助手工单</Tag>
                            <Typography.Text strong>{sourceTitle(selected.source_context)}</Typography.Text>
                            <Typography.Paragraph copyable ellipsis={{ rows: 1, tooltip: String(selected.source_context?.url || '') }} style={{ margin: '8px 0 0' }}>
                              {String(selected.source_context?.url || '')}
                            </Typography.Paragraph>
                          </div>
                          <Button type="primary" onClick={() => window.open(safeHttpUrl(selected.source_context?.url), '_blank', 'noopener,noreferrer')}>
                            打开来源平台
                          </Button>
                        </div>
                      )}
                      <div className="detail-section">
                        <Typography.Title level={5}>基础信息</Typography.Title>
                        <Descriptions column={2} size="small">
                          <Descriptions.Item label="告警Hash"><Typography.Text copyable code>{selected.alert_hash || '未生成'}</Typography.Text></Descriptions.Item>
                          <Descriptions.Item label="设备">{deviceName(selected.device_id)}</Descriptions.Item>
                          <Descriptions.Item label="创建时间">{dayjs(selected.created_at).format('YYYY-MM-DD HH:mm:ss')}</Descriptions.Item>
                          <Descriptions.Item label="更新时间">{dayjs(selected.updated_at).format('YYYY-MM-DD HH:mm:ss')}</Descriptions.Item>
                          <Descriptions.Item label="监测上报人员">{selected.reported_by_name || userName(selected.created_by_id)}</Descriptions.Item>
                          <Descriptions.Item label="最后更新人">{userName(selected.last_updated_by_id)}</Descriptions.Item>
                        </Descriptions>
                      </div>
                      <div className="detail-section">
                        <Typography.Title level={5}>处置摘要</Typography.Title>
                        <Descriptions column={2} size="small">
                          <Descriptions.Item label="处置对象">{targetLabel[selected.disposal_target] || selected.disposal_target || '-'}</Descriptions.Item>
                          <Descriptions.Item label="处置动作">{disposalActionLabel[selected.disposal_action] || selected.disposal_action || '-'}</Descriptions.Item>
                          <Descriptions.Item label="处置IP">{selected.disposal_ip || '-'}</Descriptions.Item>
                          <Descriptions.Item label="封禁时间">{selected.block_at ? dayjs(selected.block_at).format('YYYY-MM-DD HH:mm:ss') : '-'}</Descriptions.Item>
                          <Descriptions.Item label="封禁位置" span={2}>{selected.block_device_ids?.length ? selected.block_device_ids.map((id) => deviceName(id)).join('、') : '-'}</Descriptions.Item>
                          <Descriptions.Item label="处置描述" span={2}>{selected.response_note || '-'}</Descriptions.Item>
                        </Descriptions>
                      </div>
                    </Space>
                  )
                },
                {
                  key: 'assets',
                  label: '资产与情报',
                  children: (
                    <Space direction="vertical" className="full-width" size="middle">
                      <div className="asset-hit-grid">
                        <AssetCard title="源资产" asset={selected.src_asset_context || (selected.parsed_fields?.src_asset_context as any) || (selected.parsed_fields?.asset_context as any)?.src_asset} />
                        <AssetCard title="目的资产" asset={selected.dst_asset_context || (selected.parsed_fields?.dst_asset_context as any) || (selected.parsed_fields?.asset_context as any)?.dst_asset} />
                      </div>
                      <div className="detail-section">
                        <Typography.Title level={5}>威胁情报</Typography.Title>
                        <TiSummary result={selected.ti_result || {}} />
                      </div>
                    </Space>
                  )
                },
                {
                  key: 'ai',
                  label: 'AI 研判',
                  children: (
                    <div className="detail-section ai-analysis-wrap">
                      <div className="section-title-row">
                        <Typography.Title level={5}>AI 研判结果</Typography.Title>
                        <Button size="small" type="link" onClick={() => copyText(selected.ai_result)}>复制</Button>
                      </div>
                      <AiAnalysisResultCard text={selected.ai_result} />
                    </div>
                  )
                },
                {
                  key: 'evidence',
                  label: '原始证据',
                  children: (
                    <Space direction="vertical" className="full-width" size="middle">
                      <CollapsibleBlock
                        key={`raw-${selected.id}`}
                        title="原始日志"
                        collapsible={!!selected.raw_text}
                        collapsedHeight={260}
                        expandedMaxHeight={620}
                        extra={<Button size="small" type="link" onClick={() => copyText(selected.raw_text)}>复制</Button>}
                      >
                        {selected.raw_text ? <pre style={codeStyle}>{selected.raw_text}</pre> : <Typography.Text type="secondary">暂无</Typography.Text>}
                      </CollapsibleBlock>
                      <CollapsibleBlock
                        key={`parsed-${selected.id}`}
                        title="解析字段 JSON"
                        collapsible={!!formattedParsedFields && formattedParsedFields !== '{}'}
                        collapsedHeight={320}
                        expandedMaxHeight={620}
                        extra={<Button size="small" type="link" onClick={() => copyText(formattedParsedFields)}>复制</Button>}
                      >
                        {formattedParsedFields && formattedParsedFields !== '{}' ? <pre style={codeStyle}>{formattedParsedFields}</pre> : <Typography.Text type="secondary">暂无</Typography.Text>}
                      </CollapsibleBlock>
                    </Space>
                  )
                },
                {
                  key: 'workflow',
                  label: '协作流转',
                  children: (
                    <Space direction="vertical" className="full-width" size="middle">
                      <div className="detail-section">
                        <Typography.Title level={5}>协作状态</Typography.Title>
                        <Descriptions column={2} size="small">
                          <Descriptions.Item label="所属组">{groupLabel[selected.current_group] || selected.current_group}</Descriptions.Item>
                          <Descriptions.Item label="认领状态">{isTerminal(selected) ? '已闭环' : selected.assignee_id ? '已认领' : '未认领'}</Descriptions.Item>
                          <Descriptions.Item label="负责人">{ownerDisplay(selected, users)}</Descriptions.Item>
                          <Descriptions.Item label="研判负责人">{userName(selected.analysis_owner_id)}</Descriptions.Item>
                          <Descriptions.Item label="处置负责人">{userName(selected.disposal_owner_id)}</Descriptions.Item>
                          <Descriptions.Item label="应急人员">{optionalUserName(selected.response_owner_id) || '-'}</Descriptions.Item>
                          <Descriptions.Item label="闭环动作">{closureActionLabel[selected.closure_action] || selected.closure_action || '-'}</Descriptions.Item>
                          <Descriptions.Item label="误报原因" span={2}>{selected.false_positive_reason || '-'}</Descriptions.Item>
                        </Descriptions>
                      </div>
                      <CollapsibleBlock
                        key={`history-${selected.id}`}
                        title={`状态变更记录（共 ${history.length} 条）`}
                        collapsible={history.length > 3}
                        onExpandChange={setHistoryExpanded}
                        collapsedHeight={200}
                        expandedMaxHeight={620}
                      >
                        {history.length > 0 ? (
                          <ul className="history-list" style={{ paddingLeft: 20, margin: 0 }}>
                            {(historyExpanded ? history : history.slice(0, 3)).map(renderHistoryItem)}
                          </ul>
                        ) : (
                          <Typography.Text type="secondary">暂无变更记录</Typography.Text>
                        )}
                      </CollapsibleBlock>
                    </Space>
                  )
                }
              ]}
            />
          </div>
        )}
      </Drawer>

      <Modal
        title={transitionState?.mode === 'batch' ? `批量流转 ${transitionState.alerts.length} 条告警` : '状态流转'}
        open={!!transitionState}
        onCancel={closeTransition}
        onOk={() => transitionForm.submit()}
        confirmLoading={transition.isPending}
        destroyOnClose
      >
        <Form
          form={transitionForm}
          layout="vertical"
          onValuesChange={(changed) => {
            if (changed.status === 'false_positive') transitionForm.setFieldsValue({ closure_action: 'false_positive' });
            if (changed.status === 'ignored') transitionForm.setFieldsValue({ closure_action: 'ignore' });
          }}
          onFinish={(values) => {
            if (values.status === 'disposed' && transitionState?.mode === 'batch' && !transitionDisposalAction) {
              message.error('批量流转到已处置时，所选告警的处置动作必须一致');
              return;
            }
            transition.mutate(serializeTransitionValues(values));
          }}
        >
          <Form.Item name="status" label="目标状态" rules={[{ required: true, message: '请选择目标状态' }]}>
            <Select options={transitionOptions.map((value) => ({ value, label: statusLabel[value] || value }))} />
          </Form.Item>
          {watchedStatus === 'disposal' && (
            <>
              <Form.Item name="disposal_target" label="处置对象" rules={[{ required: true, message: '请选择处置对象' }]}>
                <Radio.Group options={targetOptions} />
              </Form.Item>
              <Form.Item name="disposal_action" label="处置动作" rules={[{ required: true, message: '请选择处置动作' }]}>
                <Radio.Group options={disposalActionOptions} />
              </Form.Item>
            </>
          )}
          {(watchedStatus === 'false_positive' || watchedStatus === 'ignored') && (
            <>
              <Form.Item name="closure_action" label="闭环动作" rules={[{ required: true, message: '请选择闭环动作' }]}>
                <Select options={closureOptions} />
              </Form.Item>
              {(watchedClosureAction === 'ignore_whitelist' || watchedClosureAction === 'false_positive_whitelist') && (
                <Form.Item name="closure_target" label="加白对象" rules={[{ required: true, message: '请选择加白对象' }]}>
                  <Radio.Group options={targetOptions} />
                </Form.Item>
              )}
            </>
          )}
          {needsFalsePositiveReason && (
            <Form.Item name="false_positive_reason" label="误报原因" rules={[{ required: true, message: '处置组闭环为误报时必须填写原因' }]}>
              <Input.TextArea rows={3} />
            </Form.Item>
          )}
          {watchedStatus === 'disposed' && !transitionDisposalAction && transitionState?.mode === 'batch' && (
            <Typography.Text type="warning">批量闭环到已处置时，所选告警的处置动作必须一致。</Typography.Text>
          )}
          {needsBlockFields && (
            <>
              <Form.Item name="block_device_ids" label="封禁设备" rules={[{ required: true, message: '请选择至少一个封禁设备' }]}>
                <Select mode="multiple" options={blockDevices.map((item) => ({ value: item.id, label: item.name }))} />
              </Form.Item>
              <Form.Item name="block_at" label="封禁时间" rules={[{ required: true, message: '请选择封禁时间' }]}>
                <DatePicker showTime className="full-width" />
              </Form.Item>
              {watchedBlockDeviceIds?.length ? (
                <Typography.Text type="secondary">封禁位置将导出为：{watchedBlockDeviceIds.map((id: number) => deviceName(id)).join('、')}</Typography.Text>
              ) : null}
            </>
          )}
          {needsEmergencyFields && (
            <>
              <Form.Item name="response_owner_id" label="应急人员">
                <Select allowClear options={activeResponseUsers.map((item) => ({ value: item.id, label: item.display_name }))} />
              </Form.Item>
              <Form.Item name="response_note" label="处置描述">
                <Input.TextArea rows={3} placeholder="可选填写本次应急处置说明" />
              </Form.Item>
            </>
          )}
        </Form>
      </Modal>

      <Modal
        title="重新指派"
        open={!!assignTarget}
        onCancel={() => setAssignTarget(null)}
        onOk={() => assignForm.submit()}
        confirmLoading={assign.isPending}
        destroyOnClose
      >
        <Form form={assignForm} layout="vertical" onFinish={(values) => assignTarget && assign.mutate({ alert: assignTarget, assignee_id: values.assignee_id })}>
          <Form.Item label="所属组">
            <Typography.Text>{groupLabel[assignTarget?.current_group || ''] || '-'}</Typography.Text>
          </Form.Item>
          <Form.Item name="assignee_id" label="负责人" rules={[{ required: true, message: '请选择负责人' }]}>
            <Select options={activeAssignUsers.map((item) => ({ value: item.id, label: `${item.display_name}（${roleNames(item)}）` }))} />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
}
