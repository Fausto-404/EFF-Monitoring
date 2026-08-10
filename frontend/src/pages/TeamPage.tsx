import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Alert, Button, Card, Form, Input, Modal, Popconfirm, Radio, Select, Space, Switch, Table, Tabs, Typography, Upload, message } from 'antd';
import dayjs from 'dayjs';
import { api } from '../api/client';
import type { AuditLog, TaskRecord, User } from '../api/types';
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

const userRoles = (user: Pick<User, 'role' | 'roles'> | null | undefined) => {
  const roles = Array.isArray(user?.roles) && user.roles.length ? user.roles : (user?.role ? [user.role] : []);
  return Array.from(new Set(roles.filter(Boolean)));
};

const normalizeSelectedRoles = (roles: string[]) => {
  if (roles.includes('admin')) return ['admin'];
  if (roles.includes('viewer') && roles.length > 1) return roles.filter((item) => item !== 'viewer');
  return roles.length ? roles : ['analyst'];
};

export default function TeamPage() {
  return (
    <div className="page">
      <Typography.Title level={4}>系统管理</Typography.Title>
      <Typography.Text type="secondary">管理团队成员、设备资产，并查看关键操作审计</Typography.Text>
      <Tabs
        className="top-tabs"
        items={[
          { key: 'users', label: '成员', children: <UsersPanel /> },
          { key: 'devices', label: '设备', children: <DevicesPanel /> },
          { key: 'time', label: '时间同步', children: <SystemTimePanel /> },
          { key: 'backup', label: '备份与还原', children: <BackupRestorePanel /> },
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
      const roles = normalizeSelectedRoles((payload.roles as string[]) || []);
      payload = { ...payload, roles, role: roles[0] || 'analyst' };
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
          {
            title: '角色',
            dataIndex: 'roles',
            width: 240,
            render: (_: string[], row: User) => (
              <Space wrap size={[4, 4]}>
                {userRoles(row).map((role) => <Typography.Text code key={role}>{roleLabels[role] || role}</Typography.Text>)}
              </Space>
            )
          },
          { title: '状态', dataIndex: 'is_active', width: 100, render: (v: boolean) => (v ? '启用' : '禁用') },
          {
            title: '操作',
            width: 160,
            render: (_: unknown, row: User) => (
              <Space>
                <Button size="small" onClick={() => { setEditing(row); form.setFieldsValue({ ...row, roles: userRoles(row) }); setOpen(true); }}>编辑</Button>
                <Popconfirm title="删除该成员？" onConfirm={() => remove.mutate(row.id)}>
                  <Button size="small" danger>删除</Button>
                </Popconfirm>
              </Space>
            )
          }
        ]}
      />
      <Modal title={editing ? '编辑成员' : '新增成员'} open={open} onCancel={() => { setOpen(false); setEditing(null); }} onOk={() => form.submit()}>
        <Form form={form} layout="vertical" initialValues={{ roles: ['analyst'], is_active: true }} onFinish={(values) => create.mutate(values)}>
          {!editing && <Form.Item name="username" label="用户名" rules={[{ required: true }]}><Input /></Form.Item>}
          <Form.Item name="display_name" label="姓名" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="password" label={editing ? '新密码' : '初始密码'} rules={editing ? [] : [{ required: true }]}><Input.Password /></Form.Item>
          <Form.Item name="roles" label="角色" rules={[{ required: true, message: '请选择至少一个角色' }]}>
            <Select
              mode="multiple"
              options={roleOptions}
              onChange={(roles) => form.setFieldsValue({ roles: normalizeSelectedRoles(roles) })}
              placeholder="可多选，例如：研判组 + 处置组"
            />
          </Form.Item>
          <Form.Item name="is_active" label="启用" valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal>
    </>
  );
}

type BackupInspectResult = {
  format: string;
  app?: string;
  exported_at?: string;
  workspace?: Record<string, any>;
  tables: Array<{
    table: string;
    count: number;
    accepted_fields: number;
    skipped_fields: string[];
    new_fields: string[];
  }>;
};

function BackupRestorePanel() {
  const [file, setFile] = useState<File | null>(null);
  const [mode, setMode] = useState<'merge' | 'replace'>('merge');
  const queryClient = useQueryClient();

  const exportBackup = async () => {
    const response = await api.get('/api/backup/export', { responseType: 'blob' });
    const disposition = String(response.headers['content-disposition'] || '');
    const match = disposition.match(/filename="?([^";]+)"?/i);
    downloadBlob(response.data, match?.[1] || `eff-monitoring-backup-${dayjs().format('YYYYMMDD-HHmmss')}.json`);
  };

  const inspect = useMutation({
    mutationFn: async (nextFile: File) => {
      const form = new FormData();
      form.append('file', nextFile);
      return (await api.post<BackupInspectResult>('/api/backup/inspect', form)).data;
    },
    onError: (err: any) => message.error(err?.response?.data?.detail || '备份文件解析失败')
  });

  const restore = useMutation({
    mutationFn: async () => {
      if (!file) throw new Error('请先选择备份文件');
      const form = new FormData();
      form.append('file', file);
      form.append('mode', mode);
      return (await api.post('/api/backup/restore', form)).data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries();
      message.success('还原完成，已刷新本地数据缓存');
    },
    onError: (err: any) => message.error(err?.response?.data?.detail || err?.message || '还原失败')
  });

  const totalRows = inspect.data?.tables.reduce((sum, item) => sum + item.count, 0) || 0;
  const incompatibleTables = inspect.data?.tables.filter((item) => item.skipped_fields.length || item.new_fields.length) || [];

  return (
    <Space direction="vertical" size="middle" className="full-width">
      <Card size="small" title="导出备份">
        <Space direction="vertical" size="small">
          <Typography.Text type="secondary">建议在升级平台、迁移 Docker 数据卷、修改核心配置前先导出备份。</Typography.Text>
          <Button type="primary" onClick={exportBackup}>下载当前工作区备份</Button>
        </Space>
      </Card>
      <Card size="small" title="还原备份">
        <Space direction="vertical" size="middle" className="full-width">
          <Upload.Dragger
            accept=".json,application/json"
            maxCount={1}
            beforeUpload={(nextFile) => {
              setFile(nextFile as File);
              inspect.mutate(nextFile as File);
              return false;
            }}
            onRemove={() => {
              setFile(null);
              inspect.reset();
            }}
          >
            <p className="ant-upload-text">点击或拖拽备份 JSON 到这里</p>
            <p className="ant-upload-hint">上传后会先做兼容性预检，不会立即写入数据库。</p>
          </Upload.Dragger>
          {inspect.data && (
            <Space direction="vertical" size="small" className="full-width">
              <Typography.Text>
                备份来源：<Typography.Text strong>{inspect.data.app || 'EFF-Monitoring'}</Typography.Text>
                <Typography.Text type="secondary"> / {inspect.data.exported_at ? dayjs(inspect.data.exported_at).format('YYYY-MM-DD HH:mm:ss') : '未知时间'}</Typography.Text>
              </Typography.Text>
              <Typography.Text type="secondary">共 {totalRows} 条记录，涉及 {inspect.data.tables.filter((item) => item.count > 0).length} 张表。</Typography.Text>
              {!!incompatibleTables.length && (
                <Alert
                  type="warning"
                  showIcon
                  message="检测到版本字段差异"
                  description={`有 ${incompatibleTables.length} 张表存在字段差异。还原时会跳过当前版本不存在的字段，新增字段按当前版本默认值处理。`}
                />
              )}
              <Table
                size="small"
                rowKey="table"
                dataSource={inspect.data.tables.filter((item) => item.count > 0 || item.skipped_fields.length || item.new_fields.length)}
                pagination={false}
                columns={[
                  { title: '数据表', dataIndex: 'table', width: 220 },
                  { title: '记录数', dataIndex: 'count', width: 90 },
                  { title: '可接收字段', dataIndex: 'accepted_fields', width: 110 },
                  { title: '跳过字段', dataIndex: 'skipped_fields', render: (items: string[]) => items.length ? <Typography.Text type="secondary">{items.join(', ')}</Typography.Text> : '-' },
                  { title: '当前新增字段', dataIndex: 'new_fields', render: (items: string[]) => items.length ? <Typography.Text type="secondary">{items.join(', ')}</Typography.Text> : '-' }
                ]}
              />
            </Space>
          )}
          <Radio.Group value={mode} onChange={(event) => setMode(event.target.value)}>
            <Radio.Button value="merge">合并/更新</Radio.Button>
            <Radio.Button value="replace">替换当前工作区数据</Radio.Button>
          </Radio.Group>
          <Popconfirm
            title="确认执行还原？"
            description="还原会写入数据库，建议先下载当前备份。"
            onConfirm={() => restore.mutate()}
            okText="确认还原"
            cancelText="取消"
            disabled={!file || !inspect.data}
          >
            <Button danger type="primary" loading={restore.isPending} disabled={!file || !inspect.data}>开始还原</Button>
          </Popconfirm>
        </Space>
      </Card>
    </Space>
  );
}

function AuditPanel() {
  const [action, setAction] = useState('');
  const [actorId, setActorId] = useState<number | undefined>();
  const [selectedIds, setSelectedIds] = useState<number[]>([]);
  const { data: users = [] } = useQuery({ queryKey: ['users'], queryFn: async () => (await api.get<User[]>('/api/users')).data });
  const params = { action: action || undefined, actor_id: actorId };
  const { data = [], isLoading } = useQuery({ queryKey: ['audit-logs', action, actorId], queryFn: async () => (await api.get<AuditLog[]>('/api/audit-logs', { params })).data });
  const queryClient = useQueryClient();
  const deleteOne = useMutation({
    mutationFn: async (id: number) => (await api.delete(`/api/audit-logs/${id}`)).data,
    onSuccess: () => {
      setSelectedIds([]);
      queryClient.invalidateQueries({ queryKey: ['audit-logs'] });
      message.success('审计日志已删除');
    },
    onError: (err: any) => message.error(err?.response?.data?.detail || '删除失败')
  });
  const deleteBatch = useMutation({
    mutationFn: async (ids: number[]) => (await api.post('/api/audit-logs/batch-delete', { ids })).data,
    onSuccess: (result) => {
      setSelectedIds([]);
      queryClient.invalidateQueries({ queryKey: ['audit-logs'] });
      message.success(`已删除 ${result?.deleted ?? 0} 条审计日志`);
    },
    onError: (err: any) => message.error(err?.response?.data?.detail || '批量删除失败')
  });
  const exportCsv = async () => {
    const response = await api.get('/api/exports/audit-logs.csv', { params, responseType: 'blob' });
    downloadBlob(response.data, 'audit_logs.csv');
  };
  return (
    <>
      <div className="panel-toolbar">
        <Space wrap>
          <Typography.Text type="secondary">审计日志 <HelpTip title="记录用户对成员、设备、告警、Webhook 等关键对象的操作，可按操作账号和动作筛选并导出。" /></Typography.Text>
          <Input.Search allowClear placeholder="筛选动作" value={action} onChange={(event) => setAction(event.target.value)} style={{ width: 220 }} />
          <Select allowClear placeholder="操作账号" value={actorId} onChange={setActorId} style={{ width: 180 }} options={users.map((item) => ({ value: item.id, label: `${item.display_name} (${item.username})` }))} />
          <Button onClick={exportCsv}>导出 CSV</Button>
          <Typography.Text type="secondary">已选择 {selectedIds.length} 条</Typography.Text>
          <Popconfirm title="删除选中的审计日志？" onConfirm={() => deleteBatch.mutate(selectedIds)} disabled={!selectedIds.length}>
            <Button danger disabled={!selectedIds.length} loading={deleteBatch.isPending}>批量删除</Button>
          </Popconfirm>
        </Space>
      </div>
      <Table
        rowKey="id"
        loading={isLoading}
        dataSource={data}
        rowSelection={{
          selectedRowKeys: selectedIds,
          onChange: (keys) => setSelectedIds(keys.map((item) => Number(item)))
        }}
        pagination={{ pageSizeOptions: ['10', '20', '50', '100'], showSizeChanger: true }}
        columns={[
          { title: '时间', dataIndex: 'created_at', width: 180, render: (v: string) => dayjs(v).format('YYYY-MM-DD HH:mm:ss') },
          { title: '操作账号', dataIndex: 'actor_username', width: 140 },
          { title: '操作人', dataIndex: 'actor_name', width: 140 },
          { title: '动作', dataIndex: 'action', width: 170 },
          { title: '对象', dataIndex: 'target_type', width: 100 },
          { title: '对象ID', dataIndex: 'target_id', width: 100 },
          { title: '详情', dataIndex: 'detail', render: (v: Record<string, unknown>) => <pre className="inline-pre">{JSON.stringify(v)}</pre> },
          {
            title: '操作',
            width: 90,
            fixed: 'right',
            render: (_: unknown, row: AuditLog) => (
              <Popconfirm title="删除该审计日志？" onConfirm={() => deleteOne.mutate(row.id)}>
                <Button size="small" danger loading={deleteOne.isPending}>删除</Button>
              </Popconfirm>
            )
          }
        ]}
      />
    </>
  );
}

function TasksPanel() {
  const [taskType, setTaskType] = useState('');
  const [status, setStatus] = useState<string | undefined>();
  const [actorId, setActorId] = useState<number | undefined>();
  const [selectedIds, setSelectedIds] = useState<number[]>([]);
  const { data: users = [] } = useQuery({ queryKey: ['users'], queryFn: async () => (await api.get<User[]>('/api/users')).data });
  const params = { task_type: taskType || undefined, status, actor_id: actorId };
  const { data = [], isLoading } = useQuery({ queryKey: ['tasks', taskType, status, actorId], queryFn: async () => (await api.get<TaskRecord[]>('/api/tasks', { params })).data });
  const queryClient = useQueryClient();
  const deleteOne = useMutation({
    mutationFn: async (id: number) => (await api.delete(`/api/tasks/${id}`)).data,
    onSuccess: () => {
      setSelectedIds([]);
      queryClient.invalidateQueries({ queryKey: ['tasks'] });
      message.success('任务记录已删除');
    },
    onError: (err: any) => message.error(err?.response?.data?.detail || '删除失败')
  });
  const deleteBatch = useMutation({
    mutationFn: async (ids: number[]) => (await api.post('/api/tasks/batch-delete', { ids })).data,
    onSuccess: (result) => {
      setSelectedIds([]);
      queryClient.invalidateQueries({ queryKey: ['tasks'] });
      message.success(`已删除 ${result?.deleted ?? 0} 条任务记录`);
    },
    onError: (err: any) => message.error(err?.response?.data?.detail || '批量删除失败')
  });
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
          <Typography.Text type="secondary">已选择 {selectedIds.length} 条</Typography.Text>
          <Popconfirm title="删除选中的任务记录？" onConfirm={() => deleteBatch.mutate(selectedIds)} disabled={!selectedIds.length}>
            <Button danger disabled={!selectedIds.length} loading={deleteBatch.isPending}>批量删除</Button>
          </Popconfirm>
        </Space>
      </div>
      <Table
        rowKey="id"
        loading={isLoading}
        dataSource={data}
        rowSelection={{
          selectedRowKeys: selectedIds,
          onChange: (keys) => setSelectedIds(keys.map((item) => Number(item)))
        }}
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
          { title: '错误', dataIndex: 'error', width: 180 },
          {
            title: '操作',
            width: 90,
            fixed: 'right',
            render: (_: unknown, row: TaskRecord) => (
              <Popconfirm title="删除该任务记录？" onConfirm={() => deleteOne.mutate(row.id)}>
                <Button size="small" danger loading={deleteOne.isPending}>删除</Button>
              </Popconfirm>
            )
          }
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
