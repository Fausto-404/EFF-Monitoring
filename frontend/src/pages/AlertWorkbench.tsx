import { useEffect, useMemo, useState } from 'react';
import type { Key } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { SendOutlined } from '@ant-design/icons';
import { Brain } from 'lucide-react';
import { Button, Card, Collapse, DatePicker, Descriptions, Drawer, Form, Input, Modal, Popconfirm, Radio, Select, Space, Table, Tag, Typography, message } from 'antd';
import dayjs from 'dayjs';
import type { Dayjs } from 'dayjs';
import { api } from '../api/client';
import type { Alert, Project, Template, User } from '../api/types';
import HelpTip from '../components/HelpTip';
import CollapsibleBlock from '../components/CollapsibleBlock';

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

const targetOptions = [
  { value: 'src_ip', label: '源 IP' },
  { value: 'dst_ip', label: '目的 IP' }
];

const disposalActionOptions = [
  { value: 'repair', label: '修复' },
  { value: 'emergency', label: '应急' },
  { value: 'block', label: '封禁' }
];

const targetLabel: Record<string, string> = Object.fromEntries(targetOptions.map((item) => [item.value, item.label]));
const disposalActionLabel: Record<string, string> = Object.fromEntries(disposalActionOptions.map((item) => [item.value, item.label]));
const closureActionLabel: Record<string, string> = {
  ignore: '仅忽略',
  ignore_whitelist: '忽略并加白',
  false_positive: '仅误报',
  false_positive_whitelist: '误报并加白'
};

const assetCriticalityColor: Record<string, string> = {
  low: 'default',
  medium: 'blue',
  high: 'orange',
  critical: 'red'
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
  if (user.role === 'admin') return ['analysis', 'disposal'].includes(alert.current_group);
  return groupRole[alert.current_group] === user.role;
}

function canRelease(user: User | undefined, alert: Alert) {
  if (!user || isTerminal(alert) || !alert.assignee_id) return false;
  return user.role === 'admin' || alert.assignee_id === user.id;
}

function availableStatuses(user: User | undefined, alert: Alert) {
  if (!user) return [];
  if (user.role === 'admin') {
    return ['analysis', 'disposal', 'false_positive', 'ignored', 'disposed'].filter(s => s !== alert.status);
  }
  if (isTerminal(alert)) return [];
  if (user.role === 'monitor') {
    return alert.current_group === 'analysis' && !alert.assignee_id && alert.created_by_id === user.id ? ['ignored'] : [];
  }
  if (user.role === 'analyst') {
    return alert.current_group === 'analysis' && alert.assignee_id === user.id ? ['false_positive', 'ignored', 'disposal'] : [];
  }
  if (user.role === 'disposer') {
    return alert.current_group === 'disposal' && alert.assignee_id === user.id ? ['analysis', 'false_positive', 'ignored', 'disposed'] : [];
  }
  return [];
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
  const [projectId, setProjectId] = useState<number | undefined>();
  const [assigneeId, setAssigneeId] = useState<number | undefined>();
  const [range, setRange] = useState<[Dayjs, Dayjs] | null>(null);
  const [selectedRowKeys, setSelectedRowKeys] = useState<Key[]>([]);
  const [csvTemplateId, setCsvTemplateId] = useState<number | undefined>();
  const [transitionState, setTransitionState] = useState<TransitionState>(null);
  const [assignTarget, setAssignTarget] = useState<Alert | null>(null);
  const [historyExpanded, setHistoryExpanded] = useState(false);
  const [transitionForm] = Form.useForm();
  const [assignForm] = Form.useForm();
  const watchedStatus = Form.useWatch('status', transitionForm);
  const watchedClosureAction = Form.useWatch('closure_action', transitionForm);
  const queryClient = useQueryClient();

  const copyText = async (text?: string) => {
    if (!text) {
      message.warning('暂无可复制内容');
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
      message.success('已复制');
    } catch {
      message.error('复制失败');
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
  const isAdmin = currentUser?.role === 'admin';
  const isViewer = currentUser?.role === 'viewer';

  const { data = [], isLoading } = useQuery({
    queryKey: ['alerts', q, status, currentGroup, projectId, assigneeId, range?.[0]?.format('YYYY-MM-DD HH:mm:ss'), range?.[1]?.format('YYYY-MM-DD HH:mm:ss')],
    queryFn: async () => (await api.get<Alert[]>('/api/alerts', {
      params: {
        q,
        status,
        current_group: currentGroup,
        project_id: projectId,
        assignee_id: assigneeId,
        start_date: range?.[0]?.format('YYYY-MM-DD HH:mm:ss'),
        end_date: range?.[1]?.format('YYYY-MM-DD HH:mm:ss')
      }
    })).data
  });
  const { data: history = [] } = useQuery({
    queryKey: ['alerts', selected?.id, 'history'],
    queryFn: async () => (await api.get<any[]>(`/api/alerts/${selected?.id}/history`)).data,
    enabled: !!selected
  });
  const { data: users = [] } = useQuery({ queryKey: ['users'], queryFn: async () => (await api.get<User[]>('/api/users')).data });
  const { data: projects = [] } = useQuery({ queryKey: ['projects'], queryFn: async () => (await api.get<Project[]>('/api/projects')).data });
  const { data: templates = [] } = useQuery({ queryKey: ['templates'], queryFn: async () => (await api.get<Template[]>('/api/templates')).data });
  const { data: settings = [] } = useQuery({ queryKey: ['settings'], queryFn: async () => (await api.get<Array<{ key: string; value: any }>>('/api/settings')).data });
  const csvTemplates = templates.filter((item) => item.type === 'csv');

  useEffect(() => {
    if (!initialAlertHash || dismissedAutoHash === initialAlertHash) return;
    const hit = data.find((item) => item.alert_hash === initialAlertHash);
    if (hit) {
      setSelected(hit);
    }
  }, [data, dismissedAutoHash, initialAlertHash]);

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
  const webhookReady =
    webhookConfig.enabled !== false &&
    ['dingtalk', 'wecom', 'feishu'].some((key) => webhookConfig[key]?.enabled && webhookConfig[key]?.url);

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
  const exportParams = {
    q: q || undefined,
    status,
    current_group: currentGroup,
    project_id: projectId,
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
      false_positive_reason: ''
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
  const closeDrawer = () => {
    if (initialAlertHash && selected?.alert_hash === initialAlertHash) {
      setDismissedAutoHash(initialAlertHash);
      onClearInitialAlertHash?.();
    }
    setSelected(null);
    setHistoryExpanded(false);
  };

  const columns = useMemo(
    () => [
      { title: '告警ID', dataIndex: 'alert_code', width: 140 },
      { title: '创建时间', dataIndex: 'created_at', width: 180, render: (v: string) => dayjs(v).format('YYYY-MM-DD HH:mm:ss') },
      { title: '源IP', dataIndex: 'source_ip', width: 140 },
      { title: '目的IP', dataIndex: 'destination_ip', width: 140 },
      { title: '事件类型', dataIndex: 'event_type' },
      { title: '所属组', dataIndex: 'current_group', width: 100, render: (v: string) => groupLabel[v] || v },
      {
        title: '状态',
        dataIndex: 'status',
        width: 120,
        render: (v: string, row: Alert) => (
          <Space direction="vertical" size={2}>
            <Tag color={statusColor[v]}>{statusLabel[v] || v}</Tag>
            {!isTerminal(row) && <Tag color={row.assignee_id ? 'green' : 'orange'}>{row.assignee_id ? '已认领' : '未认领'}</Tag>}
          </Space>
        )
      },
      { title: '负责人', dataIndex: 'assignee_id', width: 130, render: (_: number | null, row: Alert) => ownerDisplay(row, users) },
      {
        title: '操作',
        width: 300,
        render: (_: unknown, row: Alert) => {
          const transitions = availableStatuses(currentUser, row);
          return (
            <Space wrap>
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
            </Space>
          );
        }
      }
    ],
    [users, currentUser, isViewer, isAdmin, claim.isPending, release.isPending, remove]
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

  const activeAssignUsers = users.filter((item) => item.role === groupRole[assignTarget?.current_group || ''] && item.is_active);

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
          <Select allowClear placeholder="项目" style={{ width: 150 }} value={projectId} onChange={setProjectId} options={projects.map((item) => ({ value: item.id, label: item.name }))} />
          <Select allowClear placeholder="负责人" style={{ width: 150 }} value={assigneeId} onChange={setAssigneeId} options={users.map((item) => ({ value: item.id, label: item.display_name }))} />
          <Select allowClear placeholder="所属组" style={{ width: 150 }} value={currentGroup} onChange={setCurrentGroup} options={Object.entries(groupLabel).map(([value, label]) => ({ value, label }))} />
          <Select allowClear placeholder="状态" style={{ width: 140 }} value={status} onChange={setStatus} options={Object.entries(statusLabel).map(([value, label]) => ({ value, label }))} />
          <Select allowClear placeholder="CSV 模板" style={{ width: 170 }} value={csvTemplateId} onChange={setCsvTemplateId} options={csvTemplates.map((item) => ({ value: item.id, label: item.name }))} />
          <Button type="primary" onClick={exportCsv}>导出筛选结果 <HelpTip title="导出内容会复用当前工作台筛选条件，包括关键词、时间、项目、负责人、状态和 CSV 模板。" /></Button>
        </Space>
      </div>
      <div className="panel-toolbar">
        <Space wrap>
          <Typography.Text type="secondary">已选择 {selectedRowKeys.length} 条</Typography.Text>
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
        scroll={{ x: 1300 }}
        pagination={{ pageSizeOptions: ['10', '20', '50', '100'], showSizeChanger: true }}
      />

      <Drawer open={!!selected} onClose={closeDrawer} width={760} title="告警详情">
        {selected && (
          <Space direction="vertical" size="large" className="full-width">
            <Descriptions bordered column={2} size="small">
              <Descriptions.Item label="告警ID">{selected.alert_code}</Descriptions.Item>
              <Descriptions.Item label="告警Hash"><Typography.Text copyable code>{selected.alert_hash || '未生成'}</Typography.Text></Descriptions.Item>
              <Descriptions.Item label="创建时间">{dayjs(selected.created_at).format('YYYY-MM-DD HH:mm:ss')}</Descriptions.Item>
              <Descriptions.Item label="更新时间">{dayjs(selected.updated_at).format('YYYY-MM-DD HH:mm:ss')}</Descriptions.Item>
              <Descriptions.Item label="源IP">{selected.source_ip}</Descriptions.Item>
              <Descriptions.Item label="目的IP">{selected.destination_ip}</Descriptions.Item>
              <Descriptions.Item label="事件类型" span={2}>{selected.event_type}</Descriptions.Item>
              <Descriptions.Item label="威胁等级">
                <Tag color={selected.severity === 'critical' ? 'red' : selected.severity === 'high' ? 'volcano' : selected.severity === 'medium' ? 'orange' : 'blue'}>
                  {({ critical: '极高', high: '高', medium: '中', low: '低' }[selected.severity as string] || selected.severity || '未知')}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="状态"><Tag color={statusColor[selected.status]}>{statusLabel[selected.status] || selected.status}</Tag></Descriptions.Item>
              <Descriptions.Item label="所属组">{groupLabel[selected.current_group] || selected.current_group}</Descriptions.Item>
              <Descriptions.Item label="认领状态">{isTerminal(selected) ? '已闭环' : selected.assignee_id ? '已认领' : '未认领'}</Descriptions.Item>
              <Descriptions.Item label="负责人">{ownerDisplay(selected, users)}</Descriptions.Item>
              <Descriptions.Item label="研判负责人">{userName(selected.analysis_owner_id)}</Descriptions.Item>
              <Descriptions.Item label="处置负责人">{userName(selected.disposal_owner_id)}</Descriptions.Item>
              <Descriptions.Item label="创建人">{userName(selected.created_by_id)}</Descriptions.Item>
              <Descriptions.Item label="最后更新人">{userName(selected.last_updated_by_id)}</Descriptions.Item>
              <Descriptions.Item label="项目">{projects.find((item) => item.id === selected.project_id)?.name || '未选择'}</Descriptions.Item>
              <Descriptions.Item label="处置对象">{targetLabel[selected.disposal_target] || selected.disposal_target || '-'}</Descriptions.Item>
              <Descriptions.Item label="处置动作">{disposalActionLabel[selected.disposal_action] || selected.disposal_action || '-'}</Descriptions.Item>
              <Descriptions.Item label="处置IP">{selected.disposal_ip || '-'}</Descriptions.Item>
              <Descriptions.Item label="闭环动作">{closureActionLabel[selected.closure_action] || selected.closure_action || '-'}</Descriptions.Item>
              <Descriptions.Item label="误报原因" span={2}>{selected.false_positive_reason || '-'}</Descriptions.Item>
            </Descriptions>
            <Space wrap>
              {!isViewer && canClaim(currentUser, selected) && <Button type="primary" loading={claim.isPending} onClick={() => claim.mutate(selected)}>认领</Button>}
              {!isViewer && canRelease(currentUser, selected) && <Button loading={release.isPending} onClick={() => release.mutate({ alert: selected })}>释放认领</Button>}
              {isAdmin && !isTerminal(selected) && selected.assignee_id && <Button danger loading={release.isPending} onClick={() => release.mutate({ alert: selected, force: true })}>强制解锁</Button>}
              {!isViewer && availableStatuses(currentUser, selected).length > 0 && <Button onClick={() => openTransition([selected], 'single')}>状态流转</Button>}
              {isAdmin && !isTerminal(selected) && <Button onClick={() => { setAssignTarget(selected); assignForm.resetFields(); }}>重新指派</Button>}
              <Button type="primary" loading={ai.isPending} onClick={() => ai.mutate(selected.id)} disabled={isViewer}>AI 研判</Button>
              <Button 
                icon={<Brain size={15} />} 
                loading={aiExtract.isPending} 
                onClick={() => aiExtract.mutate({ id: selected.id })}
                disabled={isViewer}
              >
                AI 经验提取
              </Button>
              <Button loading={ti.isPending} onClick={() => ti.mutate(selected.id)} disabled={isViewer}>查询情报</Button>
              <Button icon={<SendOutlined />} onClick={() => webhook.mutate(selected.id)} disabled={isViewer || !webhookReady || webhook.isPending}>发送通报</Button>
            </Space>
            <CollapsibleBlock
              key={`history-${selected.id}`}
              title={`状态变更记录（共 ${history.length} 条）`}
              collapsible={history.length > 3}
              onExpandChange={setHistoryExpanded}
              collapsedHeight={160}
              expandedMaxHeight={520}
            >
              {history.length > 0 ? (
                <ul className="history-list" style={{ paddingLeft: 20, margin: 0 }}>
                  {(historyExpanded ? history : history.slice(0, 3)).map(renderHistoryItem)}
                </ul>
              ) : (
                <Typography.Text type="secondary">暂无变更记录</Typography.Text>
              )}
            </CollapsibleBlock>

            <section style={{ marginBottom: 16 }}>
              <Typography.Title level={5} style={{ fontSize: 14 }}>资产上下文</Typography.Title>
              <div className="asset-hit-grid">
                <AssetCard title="源资产" asset={selected.src_asset_context || (selected.parsed_fields?.src_asset_context as any) || (selected.parsed_fields?.asset_context as any)?.src_asset} />
                <AssetCard title="目的资产" asset={selected.dst_asset_context || (selected.parsed_fields?.dst_asset_context as any) || (selected.parsed_fields?.asset_context as any)?.dst_asset} />
              </div>
            </section>

            <section style={{ marginBottom: 16 }}>
              <Typography.Title level={5} style={{ fontSize: 14 }}>威胁情报</Typography.Title>
              <TiSummary result={selected.ti_result || {}} />
            </section>

            <CollapsibleBlock
              key={`ai-${selected.id}`}
              title="AI 研判"
              collapsible={!!selected.ai_result}
              collapsedHeight={240}
              expandedMaxHeight={520}
              extra={<Button size="small" type="link" onClick={() => copyText(selected.ai_result)}>复制</Button>}
            >
              {selected.ai_result ? (
                <pre style={codeStyle}>{selected.ai_result}</pre>
              ) : (
                <Typography.Text type="secondary">暂无</Typography.Text>
              )}
            </CollapsibleBlock>

            <CollapsibleBlock
              key={`raw-${selected.id}`}
              title="原始日志"
              collapsible={!!selected.raw_text}
              collapsedHeight={220}
              expandedMaxHeight={520}
              extra={<Button size="small" type="link" onClick={() => copyText(selected.raw_text)}>复制</Button>}
            >
              {selected.raw_text ? (
                <pre style={codeStyle}>{selected.raw_text}</pre>
              ) : (
                <Typography.Text type="secondary">暂无</Typography.Text>
              )}
            </CollapsibleBlock>

            <CollapsibleBlock
              key={`parsed-${selected.id}`}
              title="解析字段"
              collapsible={!!formattedParsedFields && formattedParsedFields !== '{}'}
              collapsedHeight={260}
              expandedMaxHeight={520}
              extra={<Button size="small" type="link" onClick={() => copyText(formattedParsedFields)}>复制</Button>}
            >
              {formattedParsedFields && formattedParsedFields !== '{}' ? (
                <pre style={codeStyle}>{formattedParsedFields}</pre>
              ) : (
                <Typography.Text type="secondary">暂无</Typography.Text>
              )}
            </CollapsibleBlock>
          </Space>
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
          onFinish={(values) => transition.mutate(values)}
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
            <Select options={activeAssignUsers.map((item) => ({ value: item.id, label: `${item.display_name}（${roleLabel[item.role] || item.role}）` }))} />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
}
