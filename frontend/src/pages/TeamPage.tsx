import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Button, Card, Form, Input, Modal, Popconfirm, Select, Space, Switch, Table, Tabs, Typography, message } from 'antd';
import dayjs from 'dayjs';
import { api } from '../api/client';
import type { AuditLog, Project, TaskRecord, User } from '../api/types';
import HelpTip from '../components/HelpTip';
import DevicesPanel from '../components/DevicesPanel';

const roleLabels: Record<string, string> = {
  admin: '管理员',
  monitor: '监测组',
  analyst: '研判组',
  disposer: '处置组',
  viewer: '只读人员'
};

const roleOptions = [
  { value: 'admin', label: '管理员' },
  { value: 'monitor', label: '监测组' },
  { value: 'analyst', label: '研判组' },
  { value: 'disposer', label: '处置组' },
  { value: 'viewer', label: '只读人员' }
];

export default function TeamPage() {
  return (
    <div className="page">
      <Typography.Title level={4}>系统管理</Typography.Title>
      <Typography.Text type="secondary">管理团队成员、项目、设备资产，并查看关键操作审计</Typography.Text>
      <Tabs
        className="top-tabs"
        items={[
          { key: 'users', label: '成员', children: <UsersPanel /> },
          { key: 'projects', label: '项目', children: <ProjectsPanel /> },
          { key: 'devices', label: '设备', children: <DevicesPanel /> },
          { key: 'time', label: '时间同步', children: <SystemTimePanel /> },
          { key: 'tasks', label: '任务记录', children: <TasksPanel /> },
          { key: 'audit', label: '审计日志', children: <AuditPanel /> }
        ]}
      />
    </div>
  );
}

type SystemTimeInfo = {
  value: {
    timezone: string;
    ntp_enabled: boolean;
    ntp_servers: string[];
  };
  available_timezones: string[];
  app_time: string;
  utc_time: string;
  server_local_time: string;
  server_epoch_ms?: number;
};

function SystemTimePanel() {
  const [form] = Form.useForm();
  const [clockNow, setClockNow] = useState(() => Date.now());
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ['system-time'],
    queryFn: async () => (await api.get<SystemTimeInfo>('/api/settings/system-time')).data
  });
  useEffect(() => {
    if (!data) return;
    form.setFieldsValue({
      timezone: data.value.timezone,
      ntp_enabled: data.value.ntp_enabled,
      ntp_servers: (data.value.ntp_servers || []).join('\n')
    });
  }, [data, form]);
  useEffect(() => {
    const timer = window.setInterval(() => setClockNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  const elapsedMs = Math.max(0, clockNow - (data?.server_epoch_ms || clockNow));
  const displayTimes = useMemo(() => {
    const tick = (value?: string) => value ? dayjs(value).add(elapsedMs, 'millisecond').format('YYYY-MM-DD HH:mm:ss') : '-';
    return {
      app: tick(data?.app_time),
      utc: tick(data?.utc_time),
      server: tick(data?.server_local_time)
    };
  }, [data?.app_time, data?.server_local_time, data?.utc_time, elapsedMs]);

  const save = useMutation({
    mutationFn: async (values: { timezone: string; ntp_enabled: boolean; ntp_servers: string }) => {
      const payload = {
        timezone: values.timezone,
        ntp_enabled: values.ntp_enabled,
        ntp_servers: String(values.ntp_servers || '').split(/\r?\n/).map((item) => item.trim()).filter(Boolean)
      };
      return (await api.patch('/api/settings/system_time', { value: payload }, { params: { scope: 'global' } })).data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['system-time'] });
      queryClient.invalidateQueries({ queryKey: ['settings'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      message.success('系统时间配置已保存');
    },
    onError: (err: any) => message.error(err?.response?.data?.detail || '保存失败')
  });

  return (
    <Space direction="vertical" size="middle" className="full-width">
      <Card size="small" title="当前时间">
        <Space wrap size="large">
          <Typography.Text>应用时间：<Typography.Text strong>{displayTimes.app}</Typography.Text></Typography.Text>
          <Typography.Text>UTC：{displayTimes.utc}</Typography.Text>
          <Typography.Text>服务器本地：{displayTimes.server}</Typography.Text>
        </Space>
      </Card>
      <Card size="small" title="NTP / 时区管理" loading={isLoading}>
        <Form
          form={form}
          layout="vertical"
          initialValues={{ timezone: 'UTC', ntp_enabled: true, ntp_servers: 'pool.ntp.org\ntime.apple.com' }}
          onFinish={(values) => save.mutate(values)}
        >
          <Form.Item name="timezone" label="应用时区" rules={[{ required: true, message: '请选择应用时区' }]}>
            <Select
              showSearch
              options={(data?.available_timezones || ['UTC', 'Asia/Shanghai']).map((item) => ({ value: item, label: item }))}
              placeholder="例如 Asia/Shanghai"
            />
          </Form.Item>
          <Form.Item name="ntp_enabled" label="启用 NTP 同步配置" valuePropName="checked">
            <Switch />
          </Form.Item>
          <Form.Item name="ntp_servers" label="NTP 服务器">
            <Input.TextArea rows={4} placeholder="每行一个，例如 pool.ntp.org" />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={save.isPending}>保存时间配置</Button>
        </Form>
      </Card>
    </Space>
  );
}

function UsersPanel() {
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<User | null>(null);
  const [form] = Form.useForm();
  const queryClient = useQueryClient();
  const { data = [], isLoading } = useQuery({ queryKey: ['users'], queryFn: async () => (await api.get<User[]>('/api/users')).data });
  const create = useMutation({
    mutationFn: async (payload: Record<string, unknown>) => {
      if (editing) {
        return (await api.patch(`/api/users/${editing.id}`, payload)).data;
      }
      return (await api.post('/api/users', payload)).data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      setOpen(false);
      setEditing(null);
      form.resetFields();
      message.success('成员已保存');
    },
    onError: (err: any) => {
      const detail = err?.response?.data?.detail;
      message.error(detail || '保存失败，请重试');
    }
  });
  const remove = useMutation({
    mutationFn: async (id: number) => (await api.delete(`/api/users/${id}`)).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      message.success('成员已删除');
    }
  });

  return (
    <>
      <div className="panel-toolbar"><Button type="primary" onClick={() => { setEditing(null); form.resetFields(); setOpen(true); }}>新增成员</Button></div>
      <Table
        rowKey="id"
        loading={isLoading}
        dataSource={data}
        pagination={{ pageSizeOptions: ['10', '20', '50', '100'], showSizeChanger: true }}
        columns={[
          { title: '用户名', dataIndex: 'username', width: 180 },
          { title: '姓名', dataIndex: 'display_name' },
          { title: '角色', dataIndex: 'role', width: 140, render: (v: string) => roleLabels[v] || v },
          { title: '状态', dataIndex: 'is_active', width: 100, render: (v: boolean) => (v ? '启用' : '禁用') },
          {
            title: '操作',
            width: 160,
            render: (_: unknown, row: User) => (
              <Space>
                <Button size="small" onClick={() => { setEditing(row); form.setFieldsValue(row); setOpen(true); }}>编辑</Button>
                <Popconfirm title="删除该成员？" onConfirm={() => remove.mutate(row.id)}>
                  <Button size="small" danger>删除</Button>
                </Popconfirm>
              </Space>
            )
          }
        ]}
      />
      <Modal title={editing ? '编辑成员' : '新增成员'} open={open} onCancel={() => { setOpen(false); setEditing(null); }} onOk={() => form.submit()}>
        <Form form={form} layout="vertical" initialValues={{ role: 'analyst', is_active: true }} onFinish={(values) => create.mutate(values)}>
          {!editing && <Form.Item name="username" label="用户名" rules={[{ required: true }]}><Input /></Form.Item>}
          <Form.Item name="display_name" label="姓名" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="password" label={editing ? '新密码' : '初始密码'} rules={editing ? [] : [{ required: true }]}><Input.Password /></Form.Item>
          <Form.Item name="role" label="角色"><Select options={roleOptions} /></Form.Item>
          <Form.Item name="is_active" label="启用" valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal>
    </>
  );
}

function ProjectsPanel() {
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<Project | null>(null);
  const [form] = Form.useForm();
  const queryClient = useQueryClient();
  const { data = [], isLoading } = useQuery({ queryKey: ['projects'], queryFn: async () => (await api.get<Project[]>('/api/projects')).data });
  const create = useMutation({
    mutationFn: async (payload: Record<string, unknown>) => {
      if (editing) {
        return (await api.patch(`/api/projects/${editing.id}`, payload)).data;
      }
      return (await api.post('/api/projects', payload)).data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['projects'] });
      setOpen(false);
      setEditing(null);
      form.resetFields();
      message.success('项目已保存');
    },
    onError: (err: any) => {
      const detail = err?.response?.data?.detail;
      message.error(detail || '保存失败，请重试');
    }
  });
  const remove = useMutation({
    mutationFn: async (id: number) => (await api.delete(`/api/projects/${id}`)).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['projects'] });
      message.success('项目已删除');
    }
  });

  return (
    <>
      <div className="panel-toolbar"><Button type="primary" onClick={() => { setEditing(null); form.resetFields(); setOpen(true); }}>新增项目</Button></div>
      <Table rowKey="id" loading={isLoading} dataSource={data} pagination={{ pageSizeOptions: ['10', '20', '50', '100'], showSizeChanger: true }} columns={[
        { title: '项目名称', dataIndex: 'name', width: 220 },
        { title: '说明', dataIndex: 'description' },
        {
          title: '操作',
          width: 160,
          render: (_: unknown, row: Project) => (
            <Space>
              <Button size="small" onClick={() => { setEditing(row); form.setFieldsValue(row); setOpen(true); }}>编辑</Button>
              <Popconfirm title="删除该项目？" onConfirm={() => remove.mutate(row.id)}>
                <Button size="small" danger>删除</Button>
              </Popconfirm>
            </Space>
          )
        }
      ]} />
      <Modal title={editing ? '编辑项目' : '新增项目'} open={open} onCancel={() => { setOpen(false); setEditing(null); }} onOk={() => form.submit()}>
        <Form form={form} layout="vertical" onFinish={(values) => create.mutate(values)}>
          <Form.Item name="name" label="项目名称" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="description" label="说明"><Input.TextArea rows={4} /></Form.Item>
        </Form>
      </Modal>
    </>
  );
}

function AuditPanel() {
  const [action, setAction] = useState('');
  const [actorId, setActorId] = useState<number | undefined>();
  const { data: users = [] } = useQuery({ queryKey: ['users'], queryFn: async () => (await api.get<User[]>('/api/users')).data });
  const params = { action: action || undefined, actor_id: actorId };
  const { data = [], isLoading } = useQuery({ queryKey: ['audit-logs', action, actorId], queryFn: async () => (await api.get<AuditLog[]>('/api/audit-logs', { params })).data });
  const exportCsv = async () => {
    const response = await api.get('/api/exports/audit-logs.csv', { params, responseType: 'blob' });
    downloadBlob(response.data, 'audit_logs.csv');
  };
  return (
    <>
      <div className="panel-toolbar">
        <Space wrap>
          <Typography.Text type="secondary">审计日志 <HelpTip title="记录用户对成员、项目、设备、告警、Webhook 等关键对象的操作，可按操作账号和动作筛选并导出。" /></Typography.Text>
          <Input.Search allowClear placeholder="筛选动作" value={action} onChange={(event) => setAction(event.target.value)} style={{ width: 220 }} />
          <Select allowClear placeholder="操作账号" value={actorId} onChange={setActorId} style={{ width: 180 }} options={users.map((item) => ({ value: item.id, label: `${item.display_name} (${item.username})` }))} />
          <Button onClick={exportCsv}>导出 CSV</Button>
        </Space>
      </div>
      <Table
        rowKey="id"
        loading={isLoading}
        dataSource={data}
        pagination={{ pageSizeOptions: ['10', '20', '50', '100'], showSizeChanger: true }}
        columns={[
          { title: '时间', dataIndex: 'created_at', width: 180, render: (v: string) => dayjs(v).format('YYYY-MM-DD HH:mm:ss') },
          { title: '操作账号', dataIndex: 'actor_username', width: 140 },
          { title: '操作人', dataIndex: 'actor_name', width: 140 },
          { title: '动作', dataIndex: 'action', width: 170 },
          { title: '对象', dataIndex: 'target_type', width: 100 },
          { title: '对象ID', dataIndex: 'target_id', width: 100 },
          { title: '详情', dataIndex: 'detail', render: (v: Record<string, unknown>) => <pre className="inline-pre">{JSON.stringify(v)}</pre> }
        ]}
      />
    </>
  );
}

function TasksPanel() {
  const [taskType, setTaskType] = useState('');
  const [status, setStatus] = useState<string | undefined>();
  const [actorId, setActorId] = useState<number | undefined>();
  const { data: users = [] } = useQuery({ queryKey: ['users'], queryFn: async () => (await api.get<User[]>('/api/users')).data });
  const params = { task_type: taskType || undefined, status, actor_id: actorId };
  const { data = [], isLoading } = useQuery({ queryKey: ['tasks', taskType, status, actorId], queryFn: async () => (await api.get<TaskRecord[]>('/api/tasks', { params })).data });
  const exportCsv = async () => {
    const response = await api.get('/api/exports/tasks.csv', { params, responseType: 'blob' });
    downloadBlob(response.data, 'tasks.csv');
  };
  return (
    <>
      <div className="panel-toolbar">
        <Space wrap>
          <Typography.Text type="secondary">任务记录 <HelpTip title="记录 AI 分析、威胁情报查询、Webhook 发送等异步或外部调用任务，可用于排错和追责。" /></Typography.Text>
          <Input.Search allowClear placeholder="筛选任务类型" value={taskType} onChange={(event) => setTaskType(event.target.value)} style={{ width: 220 }} />
          <Select allowClear placeholder="状态" value={status} onChange={setStatus} style={{ width: 140 }} options={[{ value: 'queued', label: '队列中' }, { value: 'running', label: '运行中' }, { value: 'success', label: '成功' }, { value: 'failed', label: '失败' }]} />
          <Select allowClear placeholder="操作账号" value={actorId} onChange={setActorId} style={{ width: 180 }} options={users.map((item) => ({ value: item.id, label: `${item.display_name} (${item.username})` }))} />
          <Button onClick={exportCsv}>导出 CSV</Button>
        </Space>
      </div>
      <Table
        rowKey="id"
        loading={isLoading}
        dataSource={data}
        pagination={{ pageSizeOptions: ['10', '20', '50', '100'], showSizeChanger: true }}
        columns={[
          { title: '时间', dataIndex: 'created_at', width: 180, render: (v: string) => dayjs(v).format('YYYY-MM-DD HH:mm:ss') },
          { title: '操作账号', dataIndex: 'actor_username', width: 140 },
          { title: '操作人', dataIndex: 'actor_name', width: 140 },
          { title: '类型', dataIndex: 'task_type', width: 180 },
          { title: '状态', dataIndex: 'status', width: 100, render: (v: string) => ({ queued: '队列中', running: '运行中', success: '成功', failed: '失败' }[v] || v) },
          { title: '对象', dataIndex: 'target_type', width: 100 },
          { title: '对象ID', dataIndex: 'target_id', width: 100 },
          { title: '结果', dataIndex: 'output', render: (v: Record<string, unknown>) => <pre className="inline-pre">{JSON.stringify(v)}</pre> },
          { title: '错误', dataIndex: 'error', width: 180 }
        ]}
      />
    </>
  );
}

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}
