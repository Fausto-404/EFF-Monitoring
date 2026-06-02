import { useState, useMemo, useEffect } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Button, Card, Collapse, Empty, Form, Input, List, Modal, Popconfirm, Select, Space, Switch, Table, Tabs, Tag, Typography, message, Tooltip, Divider } from 'antd';
import { InfoCircleOutlined, DeleteOutlined, SendOutlined, PlusOutlined, UserOutlined, RobotOutlined, FullscreenOutlined, FullscreenExitOutlined } from '@ant-design/icons';
import dayjs from 'dayjs';
import { api } from '../api/client';
import type { AiConversation, AiExperience, AiMessage, AiPrompt, User } from '../api/types';

const promptKeyOptions = [
  { value: 'alert_analysis', label: '告警研判' },
  { value: 'ste_extract', label: 'STE 经验提取' },
  { value: 'evidence_extract', label: 'AI 证据提取' },
  { value: 'template_generate', label: '模板生成' },
  { value: 'chat', label: '对话助手' },
  { value: 'regex_generate', label: '正则生成' }
];

const promptVariableHints: Record<string, Array<{ name: string; desc: string }>> = {
  alert_analysis: [
    { name: 'evidence_pack', desc: '当前告警的证据包，包含告警 Hash、解析字段、资产上下文、情报、历史流转等摘要。' },
    { name: 'experience_injection', desc: '按规则 ID、CVE、事件类型、资产标签、攻击结果检索到的 STE 历史经验。' }
  ],
  ste_extract: [
    { name: 'evidence_pack', desc: '已闭环告警的证据包，由平台字段和必要的 AI 证据补充组成。' },
    { name: 'output_schema', desc: '强制输出的 STE JSON 结构，用于约束模型返回可保存的经验。' }
  ],
  evidence_extract: [
    { name: 'known_fields', desc: '平台已经解析出的字段和值。' },
    { name: 'missing_fields', desc: '仍缺失、需要 AI 从原始日志中辅助提取的字段。' },
    { name: 'raw_text_excerpt', desc: '脱敏或截断后的原始日志片段。' }
  ],
  template_generate: [
    { name: 'template_type', desc: '模板类型，例如消息模板或 CSV 模板。' },
    { name: 'intent', desc: '用户希望生成模板的用途说明。' },
    { name: 'variables', desc: '来自规则中心、资产上下文和系统字段的候选变量，只能从这里选择。' },
    { name: 'sample_text', desc: '用户粘贴的样例内容，AI 会把真实值替换成平台变量。' }
  ],
  chat: [
    { name: 'question', desc: '用户在对话中心输入的问题。' },
    { name: 'tool_results', desc: 'Planner 选择的只读查询工具返回结果，已过滤密码、密钥、token、cookie、API Key。' }
  ],
  regex_generate: [
    { name: 'sample_log', desc: '用户提供的样例日志。' },
    { name: 'field_name', desc: '需要提取的字段名称。' },
    { name: 'expected_output', desc: '期望提取结果，用于辅助 AI 生成正则。' }
  ]
};

function PromptVariableGuide() {
  return (
    <Form.Item noStyle shouldUpdate={(prev, next) => prev.prompt_key !== next.prompt_key}>
      {({ getFieldValue }) => {
        const key = getFieldValue('prompt_key') || 'alert_analysis';
        const hints = promptVariableHints[key] || [];
        if (!hints.length) return null;
        return (
          <Card size="small" title="可用变量说明" className="subtle-card" style={{ marginBottom: 16 }}>
            <Space direction="vertical" size={6}>
              {hints.map((item) => (
                <Typography.Text key={item.name}>
                  <Typography.Text code>{`{${item.name}}`}</Typography.Text>
                  <Typography.Text type="secondary"> {item.desc}</Typography.Text>
                </Typography.Text>
              ))}
            </Space>
          </Card>
        );
      }}
    </Form.Item>
  );
}

function parseJson(text: string, fallback: any) {
  try {
    return text ? JSON.parse(text) : fallback;
  } catch {
    return fallback;
  }
}

function jsonText(value: unknown) {
  return JSON.stringify(value || {}, null, 2);
}

function PromptManager() {
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<AiPrompt | null>(null);
  const [form] = Form.useForm();
  const queryClient = useQueryClient();

  const { data: currentUser } = useQuery({ queryKey: ['me'], queryFn: async () => (await api.get<User>('/api/auth/me')).data });
  const isAdmin = currentUser?.role === 'admin';
  const { data = [], isLoading } = useQuery({ queryKey: ['ai-prompts'], queryFn: async () => (await api.get<AiPrompt[]>('/api/ai/prompts')).data });

  const save = useMutation({
    mutationFn: async (values: any) => {
      const payload = {
        ...values,
        output_schema: parseJson(values.output_schema_text, {}),
        variables: values.variables_text ? values.variables_text.split(/[,，\n]/).map((item: string) => item.trim()).filter(Boolean) : []
      };
      delete payload.output_schema_text;
      delete payload.variables_text;
      if (editing) return (await api.patch(`/api/ai/prompts/${editing.id}`, payload)).data;
      return (await api.post('/api/ai/prompts', payload)).data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ai-prompts'] });
      setOpen(false);
      setEditing(null);
      form.resetFields();
      message.success('提示词已保存');
    },
    onError: (error: any) => message.error(error?.response?.data?.detail || '提示词保存失败')
  });

  const remove = useMutation({
    mutationFn: async (id: number) => (await api.delete(`/api/ai/prompts/${id}`)).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ai-prompts'] });
      message.success('提示词已删除');
    }
  });

  const openEditor = (row?: AiPrompt) => {
    setEditing(row || null);
    form.setFieldsValue(row ? {
      ...row,
      output_schema_text: jsonText(row.output_schema),
      variables_text: (row.variables || []).join('\n')
    } : {
      prompt_key: 'alert_analysis',
      category: '告警研判',
      enabled: true,
      is_default: false,
      output_schema_text: '{}',
      variables_text: ''
    });
    setOpen(true);
  };

  return (
    <Space direction="vertical" className="full-width">
      <div className="panel-toolbar">
        <Typography.Text type="secondary">管理 AI 研判、经验提取、模板生成、对话助手等提示词</Typography.Text>
        {isAdmin && <Button type="primary" icon={<PlusOutlined />} onClick={() => openEditor()}>新增提示词</Button>}
      </div>
      <Table
        rowKey="id"
        loading={isLoading}
        dataSource={data}
        pagination={{ pageSizeOptions: ['10', '20', '50', '100'], showSizeChanger: true }}
        columns={[
          { title: '名称', dataIndex: 'name' },
          { title: '类型', dataIndex: 'prompt_key', width: 150, render: (v: string) => promptKeyOptions.find((item) => item.value === v)?.label || v },
          { title: '分类', dataIndex: 'category', width: 120 },
          {
            title: (
              <Space size={4}>
                变量
                <Tooltip title="提示词中可以引用的动态变量，AI 在运行时会自动将其替换为真实的上下文数据。"><InfoCircleOutlined style={{ fontSize: 12, cursor: 'help' }} /></Tooltip>
              </Space>
            ),
            dataIndex: 'variables',
            width: 260,
            render: (items: string[], row) => {
              const names = (items?.length ? items : (promptVariableHints[row.prompt_key] || []).map((item) => item.name)).slice(0, 4);
              return <Space wrap>{names.map((item) => <Tag key={item}>{item}</Tag>)}</Space>;
            }
          },
          { title: '状态', dataIndex: 'enabled', width: 100, render: (v: boolean, row) => <Space>{v ? <Tag color="green">启用</Tag> : <Tag>停用</Tag>}{row.is_default && <Tag color="blue">默认</Tag>}</Space> },
          { title: '更新时间', dataIndex: 'updated_at', width: 170, render: (v: string) => dayjs(v).format('YYYY-MM-DD HH:mm') },
          {
            title: '操作',
            width: 160,
            render: (_: unknown, row: AiPrompt) => isAdmin ? (
              <Space>
                <Button size="small" onClick={() => openEditor(row)}>编辑</Button>
                <Popconfirm title="删除该提示词？" onConfirm={() => remove.mutate(row.id)}>
                  <Button size="small" danger icon={<DeleteOutlined />} />
                </Popconfirm>
              </Space>
            ) : <Typography.Text type="secondary">只读</Typography.Text>
          }
        ]}
      />
      <Modal title={editing ? '编辑提示词' : '新增提示词'} open={open} onCancel={() => setOpen(false)} onOk={() => form.submit()} width={820} confirmLoading={save.isPending} destroyOnClose>
        <Form form={form} layout="vertical" onFinish={(values) => save.mutate(values)}>
          <Form.Item name="name" label="名称" rules={[{ required: true, message: '请填写名称' }]}><Input /></Form.Item>
          <Form.Item name="prompt_key" label="提示词类型" rules={[{ required: true }]}><Select options={promptKeyOptions} /></Form.Item>
          <PromptVariableGuide />
          <Form.Item name="category" label="分类"><Input /></Form.Item>
          <Form.Item name="system_prompt" label="系统提示词"><Input.TextArea rows={5} /></Form.Item>
          <Form.Item name="user_prompt" label="用户提示词"><Input.TextArea rows={7} /></Form.Item>
          <Form.Item name="variables_text" label="变量列表"><Input.TextArea rows={3} placeholder="每行一个变量，或用逗号分隔" /></Form.Item>
          <Form.Item name="output_schema_text" label="输出 JSON Schema"><Input.TextArea rows={5} style={{ fontFamily: 'monospace' }} /></Form.Item>
          <Space>
            <Form.Item name="enabled" valuePropName="checked" label="启用"><Switch /></Form.Item>
            <Form.Item name="is_default" valuePropName="checked" label="设为默认"><Switch /></Form.Item>
          </Space>
        </Form>
      </Modal>
    </Space>
  );
}

const experienceStatusLabel: Record<string, string> = {
  draft: '草稿',
  pending_generation: '待生成',
  pending_publish: '待发布',
  published: '已发布',
  archived: '已归档'
};

const statusColors: Record<string, string> = {
  draft: 'default',
  pending_generation: 'default',
  pending_publish: 'orange',
  published: 'green',
  archived: 'gray'
};

function ExperienceLibrary() {
  const [q, setQ] = useState('');
  const [status, setStatus] = useState<string | undefined>();
  const [selectedRowKeys, setSelectedRowKeys] = useState<number[]>([]);
  const [preview, setPreview] = useState<AiExperience | null>(null);
  const [editing, setEditing] = useState<AiExperience | null>(null);
  const [form] = Form.useForm();
  const queryClient = useQueryClient();

  const { data = [], isLoading } = useQuery({
    queryKey: ['ai-experiences', q, status],
    queryFn: async () => (await api.get<AiExperience[]>('/api/ai/experiences', { params: { q, status } })).data
  });
  const { data: currentUser } = useQuery({ queryKey: ['me'], queryFn: async () => (await api.get<User>('/api/auth/me')).data });
  const isAdmin = currentUser?.role === 'admin';
  const canWrite = currentUser?.role !== 'viewer' && currentUser?.role !== 'monitor';

  const generate = useMutation({
    mutationFn: async (id: number) => (await api.post(`/api/ai/experiences/${id}/generate`)).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ai-experiences'] });
      message.success('经验内容已生成并进入待发布状态');
    }
  });

  const batchGenerate = useMutation({
    mutationFn: async () => (await api.post('/api/ai/experiences/batch-generate', { ids: selectedRowKeys })).data,
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ['ai-experiences'] });
      setSelectedRowKeys([]);
      if (res.errors?.length) {
        message.warning(`批量生成完成：成功 ${res.updated} 条，失败 ${res.errors.length} 条`);
      } else {
        message.success(`批量生成成功：${res.updated} 条`);
      }
    }
  });

  const batchPublish = useMutation({
    mutationFn: async () => (await api.post('/api/ai/experiences/batch-publish', { ids: selectedRowKeys })).data,
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ['ai-experiences'] });
      setSelectedRowKeys([]);
      message.success(`批量发布成功：${res.updated} 条`);
    }
  });

  const batchDelete = useMutation({
    mutationFn: async () => (await api.post('/api/ai/experiences/batch-delete', { ids: selectedRowKeys })).data,
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ['ai-experiences'] });
      setSelectedRowKeys([]);
      message.success(`批量删除成功：${res.deleted} 条`);
    }
  });

  const save = useMutation({
    mutationFn: async (values: any) => {
      if (!editing) return null;
      return (await api.patch(`/api/ai/experiences/${editing.id}`, {
        title: values.title,
        tags: values.tags || [],
        status: values.status,
        index_data: parseJson(values.index_text, {}),
        ste: parseJson(values.ste_text, {}),
        action: parseJson(values.action_text, {}),
        quality: parseJson(values.quality_text, {})
      })).data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ai-experiences'] });
      setEditing(null);
      message.success('经验已保存');
    }
  });

  const remove = useMutation({
    mutationFn: async (id: number) => (await api.delete(`/api/ai/experiences/${id}`)).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ai-experiences'] });
      message.success('经验已删除');
    }
  });

  const publish = useMutation({
    mutationFn: async (id: number) => (await api.post(`/api/ai/experiences/${id}/publish`)).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ai-experiences'] });
      message.success('经验已发布');
    }
  });

  const openEdit = (row: AiExperience) => {
    setEditing(row);
    form.setFieldsValue({
      title: row.title,
      tags: row.tags,
      status: row.status,
      index_text: jsonText(row.index_data),
      ste_text: jsonText(row.ste),
      action_text: jsonText(row.action),
      quality_text: jsonText(row.quality)
    });
  };

  return (
    <Space direction="vertical" className="full-width">
      <div className="panel-toolbar">
        <Space wrap>
          <Input.Search allowClear placeholder="搜索经验编号 / 告警 Hash / 标题" value={q} onChange={(e) => setQ(e.target.value)} onSearch={setQ} style={{ width: 260 }} />
          <Select allowClear placeholder="状态" style={{ width: 140 }} value={status} onChange={setStatus} options={Object.entries(experienceStatusLabel).map(([value, label]) => ({ value, label }))} />
        </Space>
        {selectedRowKeys.length > 0 && (
          <Space>
            <Typography.Text type="secondary">已选择 {selectedRowKeys.length} 项：</Typography.Text>
            <Button size="small" onClick={() => batchGenerate.mutate()} loading={batchGenerate.isPending}>批量生成</Button>
            <Button size="small" type="primary" onClick={() => batchPublish.mutate()} loading={batchPublish.isPending}>批量发布</Button>
            {isAdmin && (
              <Popconfirm title="确定要删除选中的经验吗？" onConfirm={() => batchDelete.mutate()}>
                <Button size="small" danger loading={batchDelete.isPending}>批量删除</Button>
              </Popconfirm>
            )}
          </Space>
        )}
      </div>
      <Table
        rowKey="id"
        loading={isLoading}
        dataSource={data}
        rowSelection={{ 
          selectedRowKeys, 
          onChange: (keys) => setSelectedRowKeys(keys as number[]) 
        }}
        pagination={{ pageSizeOptions: ['10', '20', '50', '100'], showSizeChanger: true }}
        columns={[
          { title: '经验编号', dataIndex: 'knowledge_id', width: 150 },
          { title: '标题', dataIndex: 'title' },
          { title: '告警Hash', dataIndex: 'alert_hash', width: 150, render: (v: string) => v ? <Typography.Text code>{v}</Typography.Text> : '-' },
          { title: '标签', dataIndex: 'tags', width: 180, render: (items: string[]) => <Space wrap>{(items || []).slice(0, 3).map((item) => <Tag key={item}>{item}</Tag>)}</Space> },
          { title: '状态', dataIndex: 'status', width: 100, render: (v: string) => <Tag color={statusColors[v]}>{experienceStatusLabel[v] || v}</Tag> },
          { title: '更新时间', dataIndex: 'updated_at', width: 150, render: (v: string) => dayjs(v).format('YYYY-MM-DD HH:mm') },
          {
            title: '操作',
            width: 200,
            render: (_: unknown, row: AiExperience) => (
              <Space>
                <Button size="small" onClick={() => setPreview(row)}>详情</Button>
                {canWrite && row.status === 'pending_generation' && <Button size="small" type="link" onClick={() => generate.mutate(row.id)} loading={generate.isPending}>生成</Button>}
                {canWrite && row.status !== 'pending_generation' && <Button size="small" onClick={() => openEdit(row)}>编辑</Button>}
                {canWrite && row.status === 'pending_publish' && <Button size="small" type="primary" onClick={() => publish.mutate(row.id)}>发布</Button>}
                {isAdmin && (
                  <Popconfirm title="删除该经验？" onConfirm={() => remove.mutate(row.id)}>
                    <Button size="small" danger icon={<DeleteOutlined />} />
                  </Popconfirm>
                )}
              </Space>
            )
          }
        ]}
      />
      <Modal title="经验详情" open={!!preview} onCancel={() => setPreview(null)} footer={null} width={860}>
        {preview && (
          <Collapse
            defaultActiveKey={['ste']}
            items={[
              { key: 'meta', label: '基础信息', children: <pre>{JSON.stringify({ knowledge_id: preview.knowledge_id, title: preview.title, tags: preview.tags, status: preview.status }, null, 2)}</pre> },
              { key: 'index', label: '检索索引', children: <pre>{jsonText(preview.index_data)}</pre> },
              { key: 'ste', label: 'STE 经验', children: <pre>{jsonText(preview.ste)}</pre> },
              { key: 'action', label: '动作建议', children: <pre>{jsonText(preview.action)}</pre> },
              { key: 'quality', label: '质量信息', children: <pre>{jsonText(preview.quality)}</pre> }
            ]}
          />
        )}
      </Modal>
      <Modal title="编辑经验" open={!!editing} onCancel={() => setEditing(null)} onOk={() => form.submit()} width={880} confirmLoading={save.isPending} destroyOnClose>
        <Form form={form} layout="vertical" onFinish={(values) => save.mutate(values)}>
          <Form.Item name="title" label="标题"><Input /></Form.Item>
          <Form.Item name="tags" label="标签"><Select mode="tags" /></Form.Item>
          <Form.Item name="status" label="状态"><Select options={Object.entries(experienceStatusLabel).map(([value, label]) => ({ value, label }))} /></Form.Item>
          <Form.Item name="index_text" label="检索索引 JSON"><Input.TextArea rows={5} style={{ fontFamily: 'monospace' }} /></Form.Item>
          <Form.Item name="ste_text" label="STE JSON"><Input.TextArea rows={8} style={{ fontFamily: 'monospace' }} /></Form.Item>
          <Form.Item name="action_text" label="动作建议 JSON"><Input.TextArea rows={4} style={{ fontFamily: 'monospace' }} /></Form.Item>
          <Form.Item name="quality_text" label="质量信息 JSON"><Input.TextArea rows={4} style={{ fontFamily: 'monospace' }} /></Form.Item>
        </Form>
      </Modal>
    </Space>
  );
}

function AgentProgress() {
  return (
    <Typography.Text>AI 正在理解问题并规划查询工具...</Typography.Text>
  );
}

function normalizeAgentTrace(toolCalls?: any[]) {
  const rows = Array.isArray(toolCalls) ? toolCalls : [];
  if (!rows.length) return [];
  // 如果是 agent_trace 格式（字符串列表）
  const traceItem = rows.find(item => item.tool === 'agent_trace');
  if (traceItem && Array.isArray(traceItem.data)) {
    return [{
      round: 1,
      title: 'Agent 执行链路',
      steps: traceItem.data
    }];
  }
  return [];
}

function countAgentSteps(toolCalls?: any[]) {
  const traceItem = (toolCalls || []).find(item => item.tool === 'agent_trace');
  return Array.isArray(traceItem?.data) ? traceItem.data.length : 0;
}

function AgentTrace({ toolCalls }: { toolCalls?: any[] }) {
  const traces = normalizeAgentTrace(toolCalls);
  if (!traces.length) {
    return <Typography.Text type="secondary">暂无详细执行记录</Typography.Text>;
  }
  return (
    <Space direction="vertical" size={8} className="full-width">
      {traces[0].steps.map((step: string, idx: number) => (
        <div key={idx} style={{ marginBottom: 4, borderLeft: '2px solid #1890ff', paddingLeft: 8, fontSize: 12 }}>
          {step}
        </div>
      ))}
    </Space>
  );
}

function RawDataModal({ visible, data, onClose }: { visible: boolean, data: any, onClose: () => void }) {
  const evidences = Array.isArray(data) ? data.find((item: any) => item.tool === 'agent_evidences')?.data : null;
  const displayData = evidences || data;
  return (
    <Modal title="原始查询证据包 (Evidence Pack)" open={visible} onCancel={onClose} footer={null} width={1000} bodyStyle={{ maxHeight: 700, overflow: 'auto' }}>
      {displayData ? (
        <pre style={{ background: '#001529', color: '#fff', padding: 16, borderRadius: 4, fontSize: 12 }}>
          {JSON.stringify(displayData, null, 2)}
        </pre>
      ) : (
        <Typography.Text type="secondary">未获取到有效的证据数据包</Typography.Text>
      )}
    </Modal>
  );
}

function ChatCenter() {
  const [conversationId, setConversationId] = useState<number | undefined>();
  const [text, setText] = useState('');
  const [optimisticMessages, setOptimisticMessages] = useState<AiMessage[]>([]);
  const [inspectData, setInspectData] = useState<any>(null);
  const [showConversations, setShowConversations] = useState(true);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const queryClient = useQueryClient();

  useEffect(() => {
    if (isFullscreen) {
      const originalOverflow = document.body.style.overflow;
      document.body.style.overflow = 'hidden';
      
      const handleEsc = (e: KeyboardEvent) => {
        if (e.key === 'Escape') setIsFullscreen(false);
      };
      window.addEventListener('keydown', handleEsc);
      
      return () => {
        document.body.style.overflow = originalOverflow;
        window.removeEventListener('keydown', handleEsc);
      };
    }
  }, [isFullscreen]);

  const toggleFullscreen = () => setIsFullscreen(v => !v);

  const { data: conversations = [] } = useQuery({ queryKey: ['ai-conversations'], queryFn: async () => (await api.get<AiConversation[]>('/api/ai/conversations')).data });
  const activeId = conversationId || conversations[0]?.id;
  
  const { data: serverMessages = [], isLoading } = useQuery({
    queryKey: ['ai-conversation-messages', activeId],
    queryFn: async () => activeId ? (await api.get<AiMessage[]>(`/api/ai/conversations/${activeId}/messages`)).data : [],
    enabled: !!activeId
  });

  const displayMessages = useMemo(() => {
    if (optimisticMessages.length > 0) return [...serverMessages, ...optimisticMessages];
    return serverMessages;
  }, [serverMessages, optimisticMessages]);

  const createConversation = useMutation({
    mutationFn: async () => (await api.post<AiConversation>('/api/ai/conversations', { title: '新的对话' })).data,
    onSuccess: (row) => {
      queryClient.invalidateQueries({ queryKey: ['ai-conversations'] });
      setConversationId(row.id);
      setOptimisticMessages([]);
    }
  });

  const removeConversation = useMutation({
    mutationFn: async (id: number) => (await api.delete(`/api/ai/conversations/${id}`)).data,
    onSuccess: (_, id) => {
      queryClient.invalidateQueries({ queryKey: ['ai-conversations'] });
      if (activeId === id) {
        setConversationId(undefined);
        setOptimisticMessages([]);
      }
      message.success('对话已删除');
    }
  });

  const send = useMutation({
    mutationFn: async (content: string) => {
      let cid = activeId;
      if (!cid) {
        const row = (await api.post<AiConversation>('/api/ai/conversations', { title: content.slice(0, 40) || '新的对话' })).data;
        cid = row.id;
        setConversationId(cid);
        queryClient.invalidateQueries({ queryKey: ['ai-conversations'] });
      }

      const baseUrl = import.meta.env.VITE_API_BASE_URL || '';
      const response = await fetch(`${baseUrl}/api/ai/conversations/${cid}/messages`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('eff_token')}`
        },
        body: JSON.stringify({ content })
      });

      if (!response.ok) throw new Error('发送失败');
      
      const reader = response.body?.getReader();
      const decoder = new TextDecoder();
      let currentTrace: string[] = [];
      let currentEvidences: any[] = [];
      let currentAnswer = '';
      
      queryClient.setQueryData(['ai-conversation-messages', cid], (old: any) => [
        ...(old || []),
        { id: Date.now(), role: 'user', content, created_at: new Date().toISOString() }
      ]);

      if (reader) {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          
          const chunk = decoder.decode(value);
          const lines = chunk.split('\n');
          
          for (const line of lines) {
            if (line.startsWith('data: ')) {
              try {
                const payload = JSON.parse(line.slice(6));
                if (payload.event === 'trace') {
                  currentTrace.push(payload.data);
                  // 保持 Thinking 状态，但记录 Trace 数据
                  setOptimisticMessages([{
                    id: Date.now() + 1,
                    role: 'assistant',
                    content: currentAnswer || 'AI 正在思考中...',
                    tool_calls: [
                      { tool: 'agent_trace', data: [...currentTrace] },
                      { tool: 'agent_evidences', data: currentEvidences }
                    ],
                    created_at: new Date().toISOString(),
                    isThinking: !currentAnswer
                  } as any]);
                } else if (payload.event === 'evidences') {
                  currentEvidences = payload.data;
                  setOptimisticMessages([{
                    id: Date.now() + 1,
                    role: 'assistant',
                    content: currentAnswer || 'AI 正在思考中...',
                    tool_calls: [
                      { tool: 'agent_trace', data: [...currentTrace] },
                      { tool: 'agent_evidences', data: currentEvidences }
                    ],
                    created_at: new Date().toISOString(),
                    isThinking: !currentAnswer
                  } as any]);
                } else if (payload.event === 'token') {
                  const token = payload.data;
                  if (typeof token !== 'string' || !token || token === 'null' || token === 'undefined') {
                    continue;
                  }
                  currentAnswer += token;
                  setOptimisticMessages([{
                    id: Date.now() + 1,
                    role: 'assistant',
                    content: currentAnswer,
                    tool_calls: [
                      { tool: 'agent_trace', data: [...currentTrace] },
                      { tool: 'agent_evidences', data: currentEvidences }
                    ],
                    created_at: new Date().toISOString(),
                    isThinking: false
                  } as any]);
                } else if (payload.event === 'token_reset') {
                  currentAnswer = '';
                } else if (payload.event === 'final_answer') {
                  const answer = payload.data;
                  if (typeof answer === 'string' && answer.length > 0 && answer !== 'null' && answer !== 'undefined') {
                    currentAnswer = answer;
                  }
                  setOptimisticMessages([{
                    id: Date.now() + 2,
                    role: 'assistant',
                    content: currentAnswer,
                    tool_calls: [
                      { tool: 'agent_trace', data: [...currentTrace] },
                      { tool: 'agent_evidences', data: currentEvidences }
                    ],
                    created_at: new Date().toISOString(),
                    isThinking: false
                  } as any]);
                } else if (payload.event === 'completion') {
                  setOptimisticMessages([]);
                  queryClient.invalidateQueries({ queryKey: ['ai-conversation-messages', cid] });
                }
              } catch (e) {
                console.error('Parse error', e);
              }
            }
          }
        }
      }
    },
    onMutate: () => {
      setOptimisticMessages([{
        id: Date.now() + 1,
        role: 'assistant',
        content: '',
        tool_calls: [],
        created_at: new Date().toISOString(),
        isThinking: true
      } as any]);
    },
    onError: (error: any) => {
      setOptimisticMessages([]);
      message.error(error?.message || '发送失败');
    }
  });

  const handleSend = () => {
    if (!text.trim() || send.isPending) return;
    const content = text;
    setText('');
    send.mutate(content);
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: (!isFullscreen && showConversations) ? '280px 1fr' : '1fr', gap: 16 }}>
      {showConversations && !isFullscreen && (
        <Card
          size="small"
          title="对话列表"
          extra={
            <Space>
              <Button size="small" icon={<PlusOutlined />} onClick={() => createConversation.mutate()}>新建</Button>
              <Button size="small" onClick={() => setShowConversations(false)}>收起</Button>
            </Space>
          }
          bodyStyle={{ padding: 0 }}
        >
          <div style={{ maxHeight: 600, overflow: 'auto' }}>
            <List
              dataSource={conversations}
              locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无对话" /> }}
              renderItem={(item) => (
                <List.Item 
                  style={{ cursor: 'pointer', padding: '12px 16px', background: item.id === activeId ? '#e6f7ff' : 'transparent', transition: 'all 0.3s' }} 
                  onClick={() => { setConversationId(item.id); setOptimisticMessages([]); }}
                  className="conversation-item"
                  actions={[
                    <Popconfirm title="删除此对话？" onConfirm={(e) => { e?.stopPropagation(); removeConversation.mutate(item.id); }}>
                      <DeleteOutlined style={{ color: '#ff4d4f' }} onClick={(e) => e.stopPropagation()} />
                    </Popconfirm>
                  ]}
                >
                  <Typography.Text ellipsis style={{ width: 180 }} strong={item.id === activeId}>{item.title}</Typography.Text>
                </List.Item>
              )}
            />
          </div>
        </Card>
      )}
      <div className={isFullscreen ? 'ai-chat-panel ai-chat-panel-fullscreen' : 'ai-chat-panel'}>
        <Card
          size="small"
          title={activeId ? "AI 对话助手" : "开始新的对话"}
          extra={
            <Space>
              {!showConversations && !isFullscreen && (
                <Button size="small" onClick={() => setShowConversations(true)}>展开对话列表</Button>
              )}
              <Button size="small" icon={<PlusOutlined />} onClick={() => createConversation.mutate()}>新建</Button>
              <Button 
                size="small" 
                icon={isFullscreen ? <FullscreenExitOutlined /> : <FullscreenOutlined />} 
                onClick={toggleFullscreen}
              >
                {isFullscreen ? '退出全屏' : '全屏'}
              </Button>
            </Space>
          }
          className="full-height-card"
        >
          <div className="ai-chat-layout">
            <div className="ai-chat-messages">
              {isLoading && !optimisticMessages.length ? (
                <div style={{ textAlign: 'center', marginTop: 100 }}><Typography.Text type="secondary">正在加载历史记录...</Typography.Text></div>
              ) : displayMessages.length ? displayMessages.map((item) => (
                <div key={item.id} style={{ marginBottom: 20, display: 'flex', flexDirection: 'column', alignItems: item.role === 'user' ? 'flex-end' : 'flex-start' }}>
                  <Space style={{ marginBottom: 4 }}>
                    {item.role === 'user' ? (
                      <><Typography.Text type="secondary" style={{ fontSize: 12 }}>{dayjs(item.created_at).format('HH:mm:ss')}</Typography.Text><Tag icon={<UserOutlined />} color="blue">我</Tag></>
                    ) : (
                      <><Tag icon={<RobotOutlined />} color="green">AI</Tag><Typography.Text type="secondary" style={{ fontSize: 12 }}>{dayjs(item.created_at).format('HH:mm:ss')}</Typography.Text></>
                    )}
                  </Space>
                  <div style={{ 
                    maxWidth: '85%', 
                    padding: '10px 14px', 
                    borderRadius: 8, 
                    background: item.role === 'user' ? '#1890ff' : '#fff', 
                    color: item.role === 'user' ? '#fff' : '#000',
                    boxShadow: '0 2px 8px rgba(0,0,0,0.05)',
                    whiteSpace: 'pre-wrap',
                    position: 'relative'
                  }}>
                    {(item as any).isThinking ? <AgentProgress /> : item.content}
                    {(item as any).isThinking && <div className="dot-flashing" style={{ marginTop: 8 }} />}
                  </div>
                  {!!item.tool_calls?.length && (
                    <div style={{ marginTop: 8, width: '100%', maxWidth: '85%' }}>
                      <Collapse 
                        size="small" 
                        ghost 
                        items={[
                          { 
                            key: 'trace', 
                            label: <Typography.Text type="secondary" style={{ fontSize: 12 }}>查看 AI 执行链路 ({countAgentSteps(item.tool_calls as any[])} 步)</Typography.Text>, 
                            children: (
                              <div style={{ fontSize: 12 }}>
                                <AgentTrace toolCalls={item.tool_calls as any[]} />
                                <Divider style={{ margin: '8px 0' }} />
                                <Typography.Link style={{ fontSize: 11 }} onClick={() => setInspectData(item.tool_calls)}>查看原始工具调用数据</Typography.Link>
                              </div>
                            )
                          }
                        ]} 
                      />
                    </div>
                  )}
                </div>
              )) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="快来问我！这个平台的事我都知道" style={{ marginTop: 100 }} />}
            </div>
            
            <RawDataModal visible={!!inspectData} data={inspectData} onClose={() => setInspectData(null)} />
            
            <div className="ai-chat-inputbar">
              <Input.TextArea 
                rows={3} 
                value={text} 
                onChange={(e) => setText(e.target.value)} 
                onPressEnter={(e) => { if (!e.shiftKey) { e.preventDefault(); handleSend(); } }}
                placeholder="例如：192.168.66.23 的负责人是谁？最近有哪些高危告警？" 
                style={{ flex: 1 }}
              />
              <Button 
                type="primary" 
                icon={<SendOutlined />} 
                loading={send.isPending} 
                disabled={!text.trim()} 
                onClick={handleSend}
                style={{ height: 'auto' }}
              >
                发送
              </Button>
            </div>
          </div>
        </Card>
      </div>
      <style>{`
        .dot-flashing {
          position: relative;
          width: 6px;
          height: 6px;
          border-radius: 5px;
          background-color: #52c41a;
          color: #52c41a;
          animation: dot-flashing 1s infinite linear alternate;
          animation-delay: .5s;
          margin-left: 15px;
        }
        .dot-flashing::before, .dot-flashing::after {
          content: '';
          display: inline-block;
          position: absolute;
          top: 0;
        }
        .dot-flashing::before {
          left: -12px;
          width: 6px;
          height: 6px;
          border-radius: 5px;
          background-color: #52c41a;
          color: #52c41a;
          animation: dot-flashing 1s infinite linear alternate;
          animation-delay: 0s;
        }
        .dot-flashing::after {
          left: 12px;
          width: 6px;
          height: 6px;
          border-radius: 5px;
          background-color: #52c41a;
          color: #52c41a;
          animation: dot-flashing 1s infinite linear alternate;
          animation-delay: 1s;
        }
        @keyframes dot-flashing {
          0% { background-color: #52c41a; }
          50%, 100% { background-color: #f0f0f0; }
        }
      `}</style>
    </div>
  );
}

export default function AiCenter() {
  return (
    <div className="page">
      <div className="page-toolbar">
        <div>
          <Typography.Title level={4}>AI 中心</Typography.Title>
          <Typography.Text type="secondary">管理提示词、沉淀 STE 经验，并通过 AI 查询平台数据</Typography.Text>
        </div>
      </div>
      <Tabs
        defaultActiveKey="chat"
        items={[
          { key: 'chat', label: '对话中心', children: <ChatCenter /> },
          { key: 'experiences', label: '经验库', children: <ExperienceLibrary /> },
          { key: 'prompts', label: '提示词管理', children: <PromptManager /> }
        ]}
      />
    </div>
  );
}
