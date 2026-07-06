import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Button, Form, Input, Modal, Pagination, Popconfirm, Select, Space, Table, Tag, Typography, message } from 'antd';
import { RobotOutlined } from '@ant-design/icons';
import { api } from '../api/client';
import type { Device, ParseRule, Template, User } from '../api/types';
import HelpTip from '../components/HelpTip';

const categoryColors: Record<string, string> = {
  '系统基础': 'blue',
  '设备信息': 'cyan',
  '解析分析': 'purple',
  '源资产详情': 'orange',
  '目的资产详情': 'gold',
  '流程协作': 'geekblue',
  '运营效能统计': 'green'
};

const systemBuiltinRules: (Partial<ParseRule> & { category: string })[] = [
  // 系统基础 (11项)
  { id: -1, name: '告警ID', field_key: 'alert_code', match_type: 'system', category: '系统基础', pattern: '系统生成的业务流水号', enabled: true },
  { id: -2, name: '告警Hash', field_key: 'alert_hash', match_type: 'system', category: '系统基础', pattern: '生命周期追踪唯一标识', enabled: true },
  { id: -3, name: '创建人', field_key: 'created_by_name', match_type: 'system', category: '系统基础', pattern: '告警记录创建者', enabled: true },
  { id: -4, name: '最后更新人', field_key: 'last_updated_by_name', match_type: 'system', category: '系统基础', pattern: '最后修改记录的人员', enabled: true },
  { id: -5, name: '负责人', field_key: 'assignee_name', match_type: 'system', category: '系统基础', pattern: '当前指派的处理人员', enabled: true },
  { id: -6, name: '状态', field_key: 'status_label', match_type: 'system', category: '系统基础', pattern: '告警当前业务状态', enabled: true },
  { id: -42, name: '所属组', field_key: 'current_group', match_type: 'system', category: '流程协作', pattern: '告警当前所属处理组', enabled: true },
  { id: -43, name: '研判负责人', field_key: 'analysis_owner', match_type: 'system', category: '流程协作', pattern: '曾认领研判阶段的人员', enabled: true },
  { id: -44, name: '处置负责人', field_key: 'disposal_owner', match_type: 'system', category: '流程协作', pattern: '曾认领处置阶段的人员', enabled: true },
  { id: -45, name: '处置对象', field_key: 'disposal_target', match_type: 'system', category: '流程协作', pattern: '源 IP 或目的 IP', enabled: true },
  { id: -46, name: '处置动作', field_key: 'disposal_action', match_type: 'system', category: '流程协作', pattern: '修复、应急或封禁', enabled: true },
  { id: -47, name: '处置IP', field_key: 'disposal_ip', match_type: 'system', category: '流程协作', pattern: '进入处置阶段的具体 IP', enabled: true },
  { id: -48, name: '闭环动作', field_key: 'closure_action', match_type: 'system', category: '流程协作', pattern: '误报、忽略及加白动作', enabled: true },
  { id: -49, name: '误报原因', field_key: 'false_positive_reason', match_type: 'system', category: '流程协作', pattern: '处置组纠正误报时填写的原因', enabled: true },
  { id: -7, name: '项目名称', field_key: 'project_name', match_type: 'system', category: '系统基础', pattern: '所属运营项目名', enabled: true },
  { id: -12, name: '登录用户名称', field_key: 'current_user', match_type: 'system', category: '系统基础', pattern: '当前操作人员姓名', enabled: true },
  { id: -13, name: '登录用户名', field_key: 'current_username', match_type: 'system', category: '系统基础', pattern: '当前操作人员账号', enabled: true },
  { id: -15, name: '当前时间', field_key: 'current_time', match_type: 'system', category: '系统基础', pattern: '解析执行的具体时间', enabled: true },
  { id: -16, name: '当前日期', field_key: 'current_date', match_type: 'system', category: '系统基础', pattern: '解析执行的当前日期', enabled: true },

  // 设备信息 (4项)
  { id: -8, name: '设备名称', field_key: 'device_name', match_type: 'system', category: '设备信息', pattern: '解析日志的设备名', enabled: true },
  { id: -9, name: '设备厂商', field_key: 'current_device_vendor', match_type: 'system', category: '设备信息', pattern: '安全设备的所属厂商', enabled: true },
  { id: -10, name: '设备产品', field_key: 'current_device_product', match_type: 'system', category: '设备信息', pattern: '安全设备的产品系列', enabled: true },
  { id: -11, name: '设备版本', field_key: 'current_device_version', match_type: 'system', category: '设备信息', pattern: '安全设备的软件版本', enabled: true },

  // 解析分析 (3项)
  { id: -14, name: '原始日志', field_key: 'raw_text', match_type: 'system', category: '解析分析', pattern: '未经处理的原始报文内容', enabled: true },
  { id: -17, name: 'AI 研判结果', field_key: 'ai_result', match_type: 'system', category: '解析分析', pattern: '由大模型生成的分析建议', enabled: true },
  { id: -18, name: '威胁情报结果', field_key: 'ti_result', match_type: 'system', category: '解析分析', pattern: '由情报平台返回的标签信息', enabled: true },

  // 源资产详情 (7项)
  { id: -19, name: '源资产名称', field_key: 'src_asset_name', match_type: 'asset', category: '源资产详情', pattern: '命中的源资产名', enabled: true },
  { id: -20, name: '源资产区域', field_key: 'src_asset_area', match_type: 'asset', category: '源资产详情', pattern: '源资产所属的业务区域', enabled: true },
  { id: -21, name: '源资产负责人', field_key: 'src_asset_owner', match_type: 'asset', category: '源资产详情', pattern: '源资产的归属负责人', enabled: true },
  { id: -22, name: '源资产重要性', field_key: 'src_asset_criticality', match_type: 'asset', category: '源资产详情', pattern: '源资产的重要程度', enabled: true },
  { id: -23, name: '源资产环境', field_key: 'src_asset_environment', match_type: 'asset', category: '源资产详情', pattern: '源资产所在的网络环境', enabled: true },
  { id: -24, name: '源资产指纹', field_key: 'src_asset_fingerprints', match_type: 'asset', category: '源资产详情', pattern: '源资产的详细指纹信息', enabled: true },
  { id: -25, name: '源IP地理位置', field_key: 'src_ip_location', match_type: 'system', category: '源资产详情', pattern: '源IP所属地理位置', enabled: true },

  // 目的资产详情 (7项)
  { id: -26, name: '目的资产名称', field_key: 'dst_asset_name', match_type: 'asset', category: '目的资产详情', pattern: '命中的目的资产名', enabled: true },
  { id: -27, name: '目的资产区域', field_key: 'dst_asset_area', match_type: 'asset', category: '目的资产详情', pattern: '目的资产所属的业务区域', enabled: true },
  { id: -28, name: '目的资产负责人', field_key: 'dst_asset_owner', match_type: 'asset', category: '目的资产详情', pattern: '目的资产的归属负责人', enabled: true },
  { id: -29, name: '目的资产重要性', field_key: 'dst_asset_criticality', match_type: 'asset', category: '目的资产详情', pattern: '目的资产的重要程度', enabled: true },
  { id: -30, name: '目的资产环境', field_key: 'dst_asset_environment', match_type: 'asset', category: '目的资产详情', pattern: '目的资产所在的网络环境', enabled: true },
  { id: -31, name: '目的资产指纹', field_key: 'dst_asset_fingerprints', match_type: 'asset', category: '目的资产详情', pattern: '目的资产的详细指纹信息', enabled: true },
  { id: -32, name: '目的IP地理位置', field_key: 'dst_ip_location', match_type: 'system', category: '目的资产详情', pattern: '目的IP所属地理位置', enabled: true },

  // 运营效能统计 (9项)
  { id: -33, name: '今日告警总数', field_key: '今日告警总数', match_type: 'system', category: '运营效能统计', pattern: '今日产生的记录总量', enabled: true },
  { id: -34, name: '今日待处理数', field_key: '今日待处理数', match_type: 'system', category: '运营效能统计', pattern: '目前未办结的告警数', enabled: true },
  { id: -35, name: '今日已办结数', field_key: '今日已办结数', match_type: 'system', category: '运营效能统计', pattern: '今日已处置完成的告警数', enabled: true },
  { id: -36, name: '今日处置率 (%)', field_key: '今日处置率 (%)', match_type: 'system', category: '运营效能统计', pattern: '今日结案占比百分比', enabled: true },
  { id: -37, name: '今日平均处置耗时', field_key: '今日平均处置耗时', match_type: 'system', category: '运营效能统计', pattern: '今日办结告警的平均结案时长', enabled: true },
  { id: -38, name: '今日资产命中率 (%)', field_key: '今日资产命中率 (%)', match_type: 'system', category: '运营效能统计', pattern: '今日告警成功关联资产的比例', enabled: true },
  { id: -39, name: '今日高危告警占比 (%)', field_key: '今日高危告警占比 (%)', match_type: 'system', category: '运营效能统计', pattern: '今日高危等级告警的占比', enabled: true },
  { id: -40, name: '今日 Top 5 攻击源', field_key: '今日 Top 5 攻击源', match_type: 'system', category: '运营效能统计', pattern: '今日最活跃攻击源 IP 列表', enabled: true },
  { id: -41, name: '今日 Top 5 受攻击资产', field_key: '今日 Top 5 受攻击资产', match_type: 'system', category: '运营效能统计', pattern: '今日受灾最重的资产 IP 列表', enabled: true }
];

const systemBlocks = [
  { key: '告警ID', label: '告警ID' },
  { key: '告警Hash', label: '告警Hash' },
  { key: '创建人', label: '创建人' },
  { key: '最后更新人', label: '最后更新人' },
  { key: '负责人', label: '负责人' },
  { key: '状态', label: '状态' },
  { key: '所属组', label: '所属组' },
  { key: '研判负责人', label: '研判负责人' },
  { key: '处置负责人', label: '处置负责人' },
  { key: '处置对象', label: '处置对象' },
  { key: '处置动作', label: '处置动作' },
  { key: '处置IP', label: '处置IP' },
  { key: '闭环动作', label: '闭环动作' },
  { key: '误报原因', label: '误报原因' },
  { key: '当前时间', label: '当前时间' },
  { key: '当前日期', label: '当前日期' },
  { key: '项目名称', label: '项目名称' },
  { key: '设备名称', label: '设备名称' },
  { key: '设备厂商', label: '设备厂商' },
  { key: '设备产品', label: '设备产品' },
  { key: '设备版本', label: '设备版本' },
  { key: '登录用户名称', label: '登录用户名称' },
  { key: '登录用户名', label: '登录用户名' },
  { key: '原始日志', label: '原始日志' },
  { key: 'AI 研判结果', label: 'AI 研判结果' },
  { key: '威胁情报结果', label: '威胁情报结果' },
  { key: '源资产名称', label: '源资产名称' },
  { key: '源资产区域', label: '源资产区域' },
  { key: '源资产负责人', label: '源资产负责人' },
  { key: '源资产重要性', label: '源资产重要性' },
  { key: '源资产环境', label: '源资产环境' },
  { key: '源资产指纹', label: '源资产指纹' },
  { key: '目的资产名称', label: '目的资产名称' },
  { key: '目的资产区域', label: '目的资产区域' },
  { key: '目的资产负责人', label: '目的资产负责人' },
  { key: '目的资产重要性', label: '目的资产重要性' },
  { key: '目的资产环境', label: '目的资产环境' },
  { key: '目的资产指纹', label: '目的资产指纹' },
  { key: '源IP地理位置', label: '源IP地理位置' },
  { key: '目的IP地理位置', label: '目的IP地理位置' },
  { key: '今日告警总数', label: '今日告警总数' },
  { key: '今日待处理数', label: '今日待处理数' },
  { key: '今日已办结数', label: '今日已办结数' },
  { key: '今日处置率 (%)', label: '今日处置率 (%)' },
  { key: '今日平均处置耗时', label: '今日平均处置耗时' },
  { key: '今日资产命中率 (%)', label: '今日资产命中率 (%)' },
  { key: '今日高危告警占比 (%)', label: '今日高危告警占比 (%)' },
  { key: '今日 Top 5 攻击源', label: '今日 Top 5 攻击源' },
  { key: '今日 Top 5 受攻击资产', label: '今日 Top 5 受攻击资产' }
];


interface BuilderBlock {
  key: string;
  label: string;
}

interface BuilderCandidate extends BuilderBlock {
  kind: 'field' | 'rule' | 'template';
  isSystem?: boolean;
  isMeta?: boolean;
}

export default function TemplateCenter() {
  const [preview, setPreview] = useState<Template | null>(null);
  const [builderOpen, setBuilderOpen] = useState(false);
  const [editingTemplate, setEditingTemplate] = useState<Template | null>(null);
  const [builderName, setBuilderName] = useState('研判中事件模板');
  const [builderType, setBuilderType] = useState<'message' | 'excel' | 'csv'>('message');
  const [builderBlocks, setBuilderBlocks] = useState<BuilderBlock[]>([]);
  const [builderContent, setBuilderContent] = useState('');
  const [candidateQuery, setCandidateQuery] = useState('');
  const [candidateCategory, setCandidateCategory] = useState<string | undefined>();
  const [candidatePage, setCandidatePage] = useState(1);
  const [candidatePageSize, setCandidatePageSize] = useState(10);
  const [templateQuery, setTemplateQuery] = useState('');
  const [templateTypeFilter, setTemplateTypeFilter] = useState<string | undefined>();
  const [templateDeviceFilter, setTemplateDeviceFilter] = useState<number | undefined>();
  const [builderDeviceId, setBuilderDeviceId] = useState<number | undefined>();

  const queryClient = useQueryClient();
  const { data: currentUser } = useQuery({ queryKey: ['me'], queryFn: async () => (await api.get<User>('/api/auth/me')).data });
  const isAdmin = currentUser?.role === 'admin';

  const { data = [], isLoading } = useQuery({
    queryKey: ['templates'],
    queryFn: async () => (await api.get<Template[]>('/api/templates')).data
  });
  const { data: rules = [] } = useQuery({
    queryKey: ['rules'],
    queryFn: async () => (await api.get<ParseRule[]>('/api/rules')).data
  });
  const { data: devices = [] } = useQuery({
    queryKey: ['devices'],
    queryFn: async () => (await api.get<Device[]>('/api/devices')).data
  });

  const create = useMutation({
    mutationFn: async (payload: Partial<Template>) => {
      if (editingTemplate) {
        return (await api.patch(`/api/templates/${editingTemplate.id}`, payload)).data;
      }
      return (await api.post('/api/templates', payload)).data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['templates'] });
      setBuilderOpen(false);
      setBuilderBlocks([]);
      setEditingTemplate(null);
      message.success('模板已保存');
    },
    onError: (error: any) => message.error(error?.response?.data?.detail || '模板保存失败')
  });

  const remove = useMutation({
    mutationFn: async (id: number) => (await api.delete(`/api/templates/${id}`)).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['templates'] });
      message.success('模板已删除');
    }
  });

  const compatibleRules = rules.filter((rule: ParseRule) => !builderDeviceId || !rule.device_id || rule.device_id === builderDeviceId);
  const compatibleTemplates = data.filter((template: Template) => !builderDeviceId || !template.device_id || template.device_id === builderDeviceId);
  
  const builderCandidates: BuilderCandidate[] = [
    ...systemBlocks.map((item) => {
      const builtin = systemBuiltinRules.find(r => r.name === item.label);
      return { ...item, kind: 'field' as const, isSystem: true, category: builtin?.category };
    }),
    ...compatibleRules.map((rule: ParseRule) => ({ 
      key: rule.name, 
      label: rule.name, 
      kind: 'rule' as const,
      isSystem: rule.match_type === 'system' || rule.match_type === 'builtin',
      isMeta: rule.is_meta,
      category: (rule as any).category,
      field_key: rule.field_key 
    })),
    ...compatibleTemplates.map((template: Template) => ({ key: template.name, label: template.name, kind: 'template' as const }))
  ].filter((item, index, arr) => arr.findIndex((other) => other.key === item.key && other.label === item.label) === index);
  
  const filteredCandidates = builderCandidates.filter((item) => {
    const hitQuery = `${item.label} ${item.key}`.toLowerCase().includes(candidateQuery.toLowerCase());
    const itemCat = (item as any).category;
    let hitCategory = true;
    if (candidateCategory === 'custom') {
      hitCategory = !itemCat;
    } else if (candidateCategory) {
      hitCategory = itemCat === candidateCategory;
    }
    return hitQuery && hitCategory;
  });
  const pagedCandidates = filteredCandidates.slice((candidatePage - 1) * candidatePageSize, candidatePage * candidatePageSize);
  const filteredTemplates = data.filter((item: Template) => {
    const hitQuery = `${item.name} ${item.type} ${(item.variables || []).join(' ')}`.toLowerCase().includes(templateQuery.toLowerCase());
    const hitType = !templateTypeFilter || item.type === templateTypeFilter;
    const hitDevice = !templateDeviceFilter || item.device_id === templateDeviceFilter;
    return hitQuery && hitType && hitDevice;
  });

  const openEditor = (template?: Template) => {
    if (template) {
      setEditingTemplate(template);
      setBuilderName(template.name);
      setBuilderType(template.type as any);
      setBuilderDeviceId(template.device_id || undefined);
      setBuilderContent(template.content || '');
      // Restore blocks for structured templates
      const blocks: BuilderBlock[] = (template.variables || []).map(key => {
        const cand = builderCandidates.find(c => c.key === key);
        return { key, label: cand?.label || key };
      });
      setBuilderBlocks(blocks);
    } else {
      setEditingTemplate(null);
      setBuilderName('研判中事件模板');
      setBuilderType('message');
      setBuilderDeviceId(undefined);
      setBuilderBlocks([]);
      setBuilderContent('');
    }
    setBuilderOpen(true);
  };

  const saveBuilderTemplate = () => {
    if (!builderName) {
      message.warning('请填写模板名称');
      return;
    }
    
    let content = '';
    let variables: string[] = [];

    if (builderType === 'message') {
      content = builderContent;
      // Extract variables from {{key}}
      const matches = builderContent.match(/{{(.*?)}}/g);
      variables = matches ? matches.map(m => m.replace(/[{}]/g, '')) : [];
    } else {
      if (builderBlocks.length === 0) {
        message.warning('请拖入字段');
        return;
      }
      variables = builderBlocks.map((item) => item.key);
      content = builderType === 'excel'
        ? builderBlocks.map((item) => `{{${item.key}}}`).join('\t')
        : builderBlocks.map((item) => `${item.label}：{{${item.key}}}`).join('\n');
    }

    create.mutate({
      name: builderName,
      device_id: builderDeviceId ?? null,
      type: builderType,
      scope: 'team',
      is_default: false,
      variables,
      content
    });
  };

  const insertVariable = (key: string) => {
    if (builderType !== 'message') return;
    setBuilderContent(prev => prev + `{{${key}}}`);
  };

  const handleDropOnCanvas = (event: React.DragEvent) => {
    event.preventDefault();
    const data = event.dataTransfer.getData('text/plain');
    if (!data) return;

    if (data.startsWith('reorder:')) {
      const fromIndex = parseInt(data.replace('reorder:', ''), 10);
      const items = [...builderBlocks];
      const [moved] = items.splice(fromIndex, 1);
      items.push(moved);
      setBuilderBlocks(items);
    } else if (data.startsWith('palette:')) {
      const item = JSON.parse(data.replace('palette:', ''));
      setBuilderBlocks((items) => [...items, { key: item.key, label: item.label }]);
    }
  };

  const handleDropOnBlock = (event: React.DragEvent, toIndex: number) => {
    event.preventDefault();
    event.stopPropagation();
    const data = event.dataTransfer.getData('text/plain');
    if (!data) return;

    if (data.startsWith('reorder:')) {
      const fromIndex = parseInt(data.replace('reorder:', ''), 10);
      if (fromIndex === toIndex) return;
      const items = [...builderBlocks];
      const [moved] = items.splice(fromIndex, 1);
      items.splice(toIndex, 0, moved);
      setBuilderBlocks(items);
    } else if (data.startsWith('palette:')) {
      const item = JSON.parse(data.replace('palette:', ''));
      const items = [...builderBlocks];
      items.splice(toIndex, 0, { key: item.key, label: item.label });
      setBuilderBlocks(items);
    }
  };

  return (
    <div className="page">
      <div className="page-toolbar">
        <div>
          <Typography.Title level={4}>模板中心</Typography.Title>
          <Typography.Text type="secondary">通过拖拽规则字段拼接消息模板</Typography.Text>
        </div>
        <Space wrap>
          <Input.Search allowClear placeholder="搜索模板名称 / 变量" value={templateQuery} onChange={(event) => setTemplateQuery(event.target.value)} style={{ width: 240 }} />
          <Select
            allowClear
            placeholder="类型"
            style={{ width: 150 }}
            value={templateTypeFilter}
            onChange={setTemplateTypeFilter}
            options={[
              { value: 'message', label: '消息模板' },
              { value: 'excel', label: 'Excel 模板' },
              { value: 'csv', label: 'CSV 模板' }
            ]}
          />
          <Select
            allowClear
            placeholder="适用设备"
            style={{ width: 170 }}
            value={templateDeviceFilter}
            onChange={setTemplateDeviceFilter}
            options={devices.map((item) => ({ value: item.id, label: item.name }))}
          />
          {isAdmin && (
            <Button type="primary" onClick={() => openEditor()}>新增模板</Button>
          )}
        </Space>
      </div>
      <Table
        rowKey="id"
        loading={isLoading}
        dataSource={filteredTemplates}
        pagination={{ pageSizeOptions: ['10', '20', '50', '100'], showSizeChanger: true }}
        columns={[
          { title: '名称', dataIndex: 'name' },
          { title: '类型', dataIndex: 'type', width: 130, render: (v: string) => ({ excel: 'Excel 模板', csv: 'CSV 模板', message: '消息模板' }[v] || v) },
          { title: '适用设备', dataIndex: 'device_id', width: 150, render: (v: number | null) => v ? devices.find((item) => item.id === v)?.name || v : '全局' },
          { title: '变量', dataIndex: 'variables', render: (v: string[]) => v?.join(', ') },
          {
            title: '操作',
            width: 200,
            render: (_: any, row: Template) => (
              <Space>
                <Button size="small" onClick={() => setPreview(row)}>预览</Button>
                {isAdmin && (
                  <>
                    <Button size="small" onClick={() => openEditor(row)}>编辑</Button>
                    <Popconfirm title="删除该模板？" onConfirm={() => remove.mutate(row.id)}>
                      <Button size="small" danger>删除</Button>
                    </Popconfirm>
                  </>
                )}
              </Space>
            )
          }
        ]}
      />
      <Modal title="模板预览" open={!!preview} onCancel={() => setPreview(null)} footer={null} width={720}>
        {preview && (
          <Space direction="vertical" className="full-width">
            <Typography.Text type="secondary">{preview.name} / {preview.type}</Typography.Text>
            <pre>{preview.content}</pre>
          </Space>
        )}
      </Modal>
      <Modal title={editingTemplate ? '编辑模板' : '新增模板'} open={builderOpen} onCancel={() => setBuilderOpen(false)} onOk={saveBuilderTemplate} width={860}>
        <Form layout="vertical">
          <Form.Item label={<>模板名称<HelpTip title="模板名称会出现在内容解析的模板下拉框中，建议按场景命名，例如“封禁 IP 事件-消息模板”。" /></>}>
            <Input value={builderName} onChange={(e) => setBuilderName(e.target.value)} />
          </Form.Item>
          <Form.Item label={<>模板类型<HelpTip title="消息模板用于复制到群聊；Excel 模板用于生成一行可粘贴到表格的内容；CSV 模板用于告警工作台导出字段。" /></>}>
            <Select
              value={builderType}
              onChange={setBuilderType}
              options={[
                { value: 'message', label: '消息模板' },
                { value: 'excel', label: 'Excel 模板' },
                { value: 'csv', label: 'CSV 模板' }
              ]}
            />
          </Form.Item>
          <Form.Item label={<>适用设备<HelpTip title="不选择设备则所有设备可用；选择设备后，内容解析只有选择该设备时才会看到这个模板。" /></>}>
            <Select
              allowClear
              placeholder="不选择则为全局模板"
              value={builderDeviceId}
              onChange={setBuilderDeviceId}
              options={devices.map((item) => ({ value: item.id, label: item.name }))}
            />
          </Form.Item>
        </Form>
        <div className="template-builder">
          <div className="builder-palette">
            <Typography.Title level={5}>可用变量 <HelpTip title="点选即可插入。内置变量已按维度分组。" /></Typography.Title>
            <div style={{ marginBottom: 12 }}>
              <Select
                allowClear
                placeholder="按维度筛选变量"
                style={{ width: '100%' }}
                value={candidateCategory}
                onChange={(v) => {
                  setCandidateCategory(v);
                  setCandidatePage(1);
                }}
                options={[
                  ...Object.keys(categoryColors).map(cat => ({ value: cat, label: cat })),
                  { value: 'custom', label: '自定义项 (规则/模板)' }
                ]}
              />
            </div>
            <Input.Search
              allowClear
              placeholder="搜索变量"
              value={candidateQuery}
              onChange={(event) => {
                setCandidateQuery(event.target.value);
                setCandidatePage(1);
              }}
              style={{ marginBottom: 12 }}
            />
            <div className="palette-list" style={{ maxHeight: '480px', overflowY: 'auto', marginBottom: 12 }}>
              {Object.keys(categoryColors).map(cat => {
                const items = pagedCandidates.filter(c => (c as any).category === cat);
                if (items.length === 0) return null;

                return (
                  <div key={cat} style={{ marginBottom: 16 }}>
                    <div style={{ fontSize: '12px', color: '#8c8c8c', marginBottom: 8, paddingLeft: 4, fontWeight: 'bold' }}>{cat}</div>
                    {items.map((item) => (
                      <div
                        key={`${item.key}-${item.label}`}
                        className="builder-block"
                        draggable
                        onClick={() => insertVariable(item.key)}
                        onDragStart={(event) => {
                          event.dataTransfer.setData('text/plain', `palette:${JSON.stringify(item)}`);
                        }}
                        style={{ cursor: 'pointer', marginBottom: 4, padding: '4px 8px' }}
                      >
                        <span style={{ fontSize: '13px' }}>{item.label}</span>
                        <Tag color={categoryColors[cat]} style={{ marginRight: 0, fontSize: '10px' }}>{cat}</Tag>
                      </div>
                    ))}
                  </div>
                );
              })}

              {/* 自定义/其他项 */}
              {pagedCandidates.filter(c => !(c as any).category).length > 0 && (
                <div style={{ marginBottom: 16 }}>
                  <div style={{ fontSize: '12px', color: '#8c8c8c', marginBottom: 8, paddingLeft: 4, fontWeight: 'bold' }}>自定义规则 / 模板</div>
                  {pagedCandidates.filter(c => !(c as any).category).map((item) => (
                    <div
                      key={`${item.key}-${item.label}`}
                      className="builder-block"
                      draggable
                      onClick={() => insertVariable(item.key)}
                      onDragStart={(event) => {
                        event.dataTransfer.setData('text/plain', `palette:${JSON.stringify(item)}`);
                      }}
                      style={{ cursor: 'pointer', marginBottom: 4, padding: '4px 8px' }}
                    >
                      <span style={{ fontSize: '13px' }}>{item.label}</span>
                      <Tag>{item.kind === 'template' ? '模板' : '规则'}</Tag>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <Pagination
              size="small"
              current={candidatePage}
              pageSize={candidatePageSize}
              total={filteredCandidates.length}
              onChange={(page, size) => {
                setCandidatePage(page);
                setCandidatePageSize(size || 10);
              }}
              onShowSizeChange={(_page, size) => {
                setCandidatePage(1);
                setCandidatePageSize(size);
              }}
              pageSizeOptions={['10', '20', '50', '100']}
              showSizeChanger
            />
          </div>

          {builderType === 'message' ? (
            <div className="builder-canvas free-text">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <Typography.Title level={5} style={{ margin: 0 }}>
                  消息模版编辑器 <HelpTip title="直接在此输入通报正文。点击左侧变量插入占位符，解析时会通过 {{key}} 自动替换为实际内容。" />
                </Typography.Title>
              </div>
              <Input.TextArea
                value={builderContent}
                onChange={(e) => setBuilderContent(e.target.value)}
                placeholder="例如：\n【安全通报】\n事件类型：{{event_type}}\n攻击来源：{{src_ip}}"
                rows={18}
                style={{ fontFamily: 'monospace', fontSize: '14px' }}
                onDragOver={(e) => e.preventDefault()}
                onDrop={(e) => {
                  e.preventDefault();
                  const data = e.dataTransfer.getData('text/plain');
                  if (data.startsWith('palette:')) {
                    const item = JSON.parse(data.replace('palette:', ''));
                    insertVariable(item.key);
                  }
                }}
              />
              <div style={{ marginTop: 12 }}>
                <Typography.Text type="secondary" style={{ fontSize: '12px' }}>
                  提示：支持自由输入文字、换行和符号。变量占位符必须符合 <code>{`{{key}}`}</code> 格式。
                </Typography.Text>
              </div>
            </div>
          ) : (
            <div
              className="builder-canvas"
              onDragOver={(event) => event.preventDefault()}
              onDrop={handleDropOnCanvas}
            >
              <Typography.Title level={5}>导出字段排序 <HelpTip title="拖入顺序就是输出顺序。Excel 模板输出值并用制表符连接；CSV 模板输出“名称: 值”并用换行连接。支持在此区域内拖动排序。" /></Typography.Title>
              {builderBlocks.length === 0 && <Typography.Text type="secondary">请从左侧拖入字段到此区域</Typography.Text>}
              {builderBlocks.map((item, index) => (
                <div 
                  key={`${item.key}-${index}`} 
                  className="builder-block selected"
                  draggable
                  onDragStart={(event) => {
                    event.dataTransfer.setData('text/plain', `reorder:${index}`);
                  }}
                  onDragOver={(event) => event.preventDefault()}
                  onDrop={(event) => handleDropOnBlock(event, index)}
                >
                  <span>{builderType === 'excel' ? `{{${item.key}}}` : `${item.label}：{{${item.key}}}`}</span>
                  <Button size="small" type="link" onClick={() => setBuilderBlocks((items) => items.filter((_, idx) => idx !== index))}>移除</Button>
                </div>
              ))}
            </div>
          )}
        </div>
      </Modal>
    </div>
  );
}
