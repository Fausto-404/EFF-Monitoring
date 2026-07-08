import { useEffect, useMemo, useState } from 'react';
import type { Key } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { DeleteOutlined, PlusOutlined, UploadOutlined, DownloadOutlined } from '@ant-design/icons';
import { Alert as AntAlert, Button, Card, Col, Descriptions, Drawer, Form, Input, Modal, Popconfirm, Row, Select, Space, Table, Tag, Tabs, Typography, Upload, message } from 'antd';
import type { UploadFile } from 'antd';
import dayjs from 'dayjs';
import { api } from '../api/client';
import type { Asset, User } from '../api/types';
import HelpTip from '../components/HelpTip';

interface AssetSegment {
  id: number;
  segment: string;
  name: string;
  area: string;
  owner: string;
  department: string;
  criticality: string;
  environment: string;
  description: string;
  updated_at: string;
}

const criticalityOptions = [
  { value: 'low', label: '低' },
  { value: 'medium', label: '中' },
  { value: 'high', label: '高' },
  { value: 'critical', label: '关键' }
];

const criticalityColor: Record<string, string> = {
  low: 'default',
  medium: 'blue',
  high: 'orange',
  critical: 'red'
};

const criticalityLabel: Record<string, string> = {
  low: '低',
  medium: '中',
  high: '高',
  critical: '关键'
};

const environmentLabel: Record<string, string> = {
  production: '生产',
  test: '测试',
  office: '办公',
  dmz: '隔离区'
};

const strategyOptions = [
  { value: 'skip', label: '重复时跳过' },
  { value: 'overwrite', label: '重复时覆盖' },
  { value: 'append', label: '始终新增' }
];

function AssetsPanel({ isAdmin }: { isAdmin: boolean }) {
  const [q, setQ] = useState('');
  const [area, setArea] = useState<string | undefined>();
  const [owner, setOwner] = useState<string | undefined>();
  const [criticality, setCriticality] = useState<string | undefined>();
  const [environment, setEnvironment] = useState<string | undefined>();
  const [selected, setSelected] = useState<Asset | null>(null);
  const [editing, setEditing] = useState<Asset | null>(null);
  const [editorOpen, setEditorOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [fileList, setFileList] = useState<UploadFile[]>([]);
  const [strategy, setStrategy] = useState('skip');
  const [importResult, setImportResult] = useState<any>(null);
  const [selectedRowKeys, setSelectedRowKeys] = useState<Key[]>([]);
  const [form] = Form.useForm();
  const queryClient = useQueryClient();

  const { data = [], isLoading } = useQuery({
    queryKey: ['assets', q, area, owner, criticality, environment],
    queryFn: async () => (await api.get<Asset[]>('/api/assets', {
      params: { q: q || undefined, area, owner, criticality, environment }
    })).data
  });

  const { data: listCheck } = useQuery({
    queryKey: ['asset-ip-list-check', selected?.ip],
    queryFn: async () => (await api.post('/api/ip-lists/check', { ip: selected?.ip })).data,
    enabled: !!selected?.ip
  });

  const areas = useMemo(() => Array.from(new Set(data.map((item) => item.area).filter(Boolean))).map((item) => ({ value: item, label: item })), [data]);
  const owners = useMemo(() => Array.from(new Set(data.map((item) => item.owner).filter(Boolean))).map((item) => ({ value: item, label: item })), [data]);
  const environments = useMemo(() => Array.from(new Set(data.map((item) => item.environment).filter(Boolean))).map((item) => ({ value: item, label: environmentLabel[item] || item })), [data]);

  const save = useMutation({
    mutationFn: async (payload: Partial<Asset>) => {
      if (editing) return (await api.patch(`/api/assets/${editing.id}`, { ...payload, updated_at: editing.updated_at })).data;
      return (await api.post('/api/assets', payload)).data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['assets'] });
      setEditorOpen(false);
      setEditing(null);
      form.resetFields();
      message.success('资产已保存');
    },
    onError: (err: any) => {
      if (err.response?.status === 409) {
        message.error(err.response.data.detail || '保存失败：资产冲突或已被他人修改');
      } else {
        message.error('保存失败');
      }
    }
  });

  const remove = useMutation({
    mutationFn: async (id: number) => (await api.delete(`/api/assets/${id}`)).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['assets'] });
      setSelected(null);
      message.success('资产已删除');
    }
  });

  const batchRemove = useMutation({
    mutationFn: async () => (await api.post('/api/assets/batch-delete', { ids: selectedRowKeys })).data,
    onSuccess: (res) => {
      setSelectedRowKeys([]);
      queryClient.invalidateQueries({ queryKey: ['assets'] });
      message.success(`已批量删除 ${res.deleted || 0} 条资产记录`);
    }
  });

  const importAssets = useMutation({
    mutationFn: async () => {
      const file = fileList[0]?.originFileObj;
      if (!file) throw new Error('请选择 Excel 文件');
      const formData = new FormData();
      formData.append('file', file);
      return (await api.post('/api/assets/import', formData, { params: { strategy }, headers: { 'Content-Type': 'multipart/form-data' } })).data;
    },
    onSuccess: (data) => {
      setImportResult(data);
      queryClient.invalidateQueries({ queryKey: ['assets'] });
      message.success('导入完成');
    }
  });

  const openEditor = (asset?: Asset) => {
    setEditing(asset || null);
    form.setFieldsValue(asset ? {
      ...asset,
      fingerprints: Object.entries(asset.fingerprints || {}).map(([key, value]) => ({ key, value: String(value ?? '') }))
    } : { criticality: 'medium', tags: [], fingerprints: [] });
    setEditorOpen(true);
  };

  const submitEditor = (values: any) => {
    const fingerprints = Object.fromEntries((values.fingerprints || []).filter((item: any) => item?.key).map((item: any) => [item.key, item.value || '']));
    save.mutate({ ...values, fingerprints });
  };

  const download = async (url: string, filename: string, params?: Record<string, unknown>) => {
    const response = await api.get(url, { params, responseType: 'blob' });
    const objectUrl = URL.createObjectURL(response.data);
    const link = document.createElement('a');
    link.href = objectUrl;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(objectUrl);
  };

  return (
    <>
      <div className="panel-toolbar">
        <Space wrap>
          <Input.Search placeholder="搜索 IP / 域名 / 名称" allowClear onSearch={setQ} style={{ width: 240 }} />
          <Select allowClear placeholder="区域" style={{ width: 110 }} value={area} onChange={setArea} options={areas} />
          <Select allowClear placeholder="负责人" style={{ width: 110 }} value={owner} onChange={setOwner} options={owners} />
          <Select allowClear placeholder="重要性" style={{ width: 90 }} value={criticality} onChange={setCriticality} options={criticalityOptions} />
          <Select allowClear placeholder="环境" style={{ width: 90 }} value={environment} onChange={setEnvironment} options={environments} />
          {isAdmin && <Button type="primary" onClick={() => openEditor()}>新增资产</Button>}
          {isAdmin && <Button icon={<UploadOutlined />} onClick={() => { setImportOpen(true); setImportResult(null); }}>导入 Excel</Button>}
          <Button onClick={() => download('/api/assets/template.xlsx', 'asset_template.xlsx')}>导出模板</Button>
          <Button onClick={() => download('/api/assets/export.xlsx', 'assets.xlsx', { q: q || undefined, area, owner, criticality, environment })}>导出资产</Button>
          {isAdmin && selectedRowKeys.length > 0 && (
            <Popconfirm title={`确定批量删除选中的 ${selectedRowKeys.length} 条资产？`} onConfirm={() => batchRemove.mutate()}>
              <Button danger loading={batchRemove.isPending}>批量删除</Button>
            </Popconfirm>
          )}
        </Space>
      </div>

      <Table
        size="small"
        rowKey="id"
        loading={isLoading}
        dataSource={data}
        rowSelection={isAdmin ? { selectedRowKeys, onChange: setSelectedRowKeys } : undefined}
        pagination={{ pageSizeOptions: ['10', '20', '50', '100'], showSizeChanger: true }}
        columns={[
          { title: 'IP', dataIndex: 'ip', width: 130 },
          { title: '域名', dataIndex: 'domain', width: 160 },
          { title: '资产名称', dataIndex: 'name' },
          { title: '所属区域', dataIndex: 'area', width: 120 },
          { title: '负责人', dataIndex: 'owner', width: 110 },
          { title: '重要性', dataIndex: 'criticality', width: 90, render: (v: string) => <Tag color={criticalityColor[v]}>{criticalityLabel[v] || '中'}</Tag> },
          { title: '更新时间', dataIndex: 'updated_at', width: 180, render: (v: string) => dayjs(v).format('YYYY-MM-DD HH:mm:ss') },
          {
            title: '操作',
            width: 160,
            render: (_: unknown, row: Asset) => (
              <Space>
                <Button size="small" onClick={() => setSelected(row)}>详情</Button>
                {isAdmin && <Button size="small" onClick={() => openEditor(row)}>编辑</Button>}
                {isAdmin && (
                  <Popconfirm title="删除该资产？" onConfirm={() => remove.mutate(row.id)}>
                    <Button size="small" danger>删除</Button>
                  </Popconfirm>
                )}
              </Space>
            )
          }
        ]}
      />

      <Drawer open={!!selected} onClose={() => setSelected(null)} width={640} title="资产详情">
        {selected && (
          <Space direction="vertical" size="large" className="full-width">
            <Descriptions bordered column={2} size="small">
              <Descriptions.Item label="IP">{selected.ip || '-'}</Descriptions.Item>
              <Descriptions.Item label="域名">{selected.domain || '-'}</Descriptions.Item>
              <Descriptions.Item label="资产名称" span={2}>{selected.name || '-'}</Descriptions.Item>
              <Descriptions.Item label="所属区域">{selected.area || '-'}</Descriptions.Item>
              <Descriptions.Item label="负责人">{selected.owner || '-'}</Descriptions.Item>
              <Descriptions.Item label="部门">{selected.department || '-'}</Descriptions.Item>
              <Descriptions.Item label="重要性"><Tag color={criticalityColor[selected.criticality]}>{criticalityLabel[selected.criticality] || selected.criticality}</Tag></Descriptions.Item>
              <Descriptions.Item label="环境">{environmentLabel[selected.environment] || selected.environment || '-'}</Descriptions.Item>
              <Descriptions.Item label="更新时间" span={2}>{dayjs(selected.updated_at).format('YYYY-MM-DD HH:mm:ss')}</Descriptions.Item>
              </Descriptions>

            <section>
              <Typography.Title level={5}>标签</Typography.Title>
              <Space wrap>{selected.tags?.length ? selected.tags.map((tag) => <Tag key={tag}>{tag}</Tag>) : <Typography.Text type="secondary">暂无标签</Typography.Text>}</Space>
            </section>
            <section>
              <Typography.Title level={5}>指纹详情</Typography.Title>
              <pre>{JSON.stringify(selected.fingerprints || {}, null, 2)}</pre>
            </section>
            {selected.ip && (
              <AntAlert
                type={listCheck?.matched ? 'warning' : 'success'}
                showIcon
                message={listCheck?.matched ? '该资产 IP 命中名单' : '该资产 IP 未命中白/黑名单'}
                description={<Space wrap>{(listCheck?.matches || []).map((item: any) => <Tag color={item.list === 'blacklist' ? 'red' : 'blue'} key={`${item.list}-${item.range}`}>{item.label}: {item.range}</Tag>)}</Space>}
              />
            )}
          </Space>
        )}
      </Drawer>

      <Modal title={editing ? '编辑资产' : '新增资产'} open={editorOpen} onCancel={() => setEditorOpen(false)} onOk={() => form.submit()} width={760}>
        <Form form={form} layout="vertical" onFinish={submitEditor}>
          <div className="asset-form-grid">
            <Form.Item name="ip" label={<>IP <HelpTip title="IP 和域名至少填写一个，用于内容解析和告警上下文匹配。" /></>} rules={[{ required: true, message: '请填写 IP' }]}><Input /></Form.Item>
            <Form.Item name="domain" label="域名" rules={[{ required: true, message: '请填写域名' }]}><Input /></Form.Item>
            <Form.Item name="name" label={<>资产名称 <HelpTip title="业务可读名称，如“财务系统主库”、“外部门户网站”。" /></>} rules={[{ required: true, message: '请填写资产名称' }]}><Input /></Form.Item>
            <Form.Item name="area" label={<>资产所属区域 <HelpTip title="用于逻辑隔离和资产梳理，如“生产区”、“DMZ区”。" /></>}><Input /></Form.Item>
            <Form.Item name="owner" label="负责人"><Input /></Form.Item>
            <Form.Item name="department" label="部门"><Input /></Form.Item>
            <Form.Item name="criticality" label="重要性"><Select options={criticalityOptions} /></Form.Item>
            <Form.Item name="environment" label="环境"><Input placeholder="例如：生产、测试、办公、隔离区" /></Form.Item>
          </div>
          <Form.Item name="tags" label="标签"><Select mode="tags" tokenSeparators={[',', '，']} /></Form.Item>
          <Form.List name="fingerprints">
            {(fields, { add, remove }) => (
              <section>
                <Typography.Title level={5}>自定义指纹 <HelpTip title="可以添加任意业务相关的指纹信息，如“操作系统: CentOS 7”、“中间件: WebLogic”。" /></Typography.Title>
                {fields.map((field) => (
                  <Space key={field.key} align="baseline" className="full-width form-row">
                    <Form.Item {...field} name={[field.name, 'key']}><Input placeholder="字段名" /></Form.Item>
                    <Form.Item {...field} name={[field.name, 'value']}><Input placeholder="字段值" /></Form.Item>
                    <Button icon={<DeleteOutlined />} onClick={() => remove(field.name)} />
                  </Space>
                ))}
                <Button icon={<PlusOutlined />} onClick={() => add()}>添加指纹字段</Button>
              </section>
            )}
          </Form.List>
        </Form>
      </Modal>

      <Modal title="导入 Excel" open={importOpen} onCancel={() => setImportOpen(false)} footer={null} width={620}>
        <Space direction="vertical" className="full-width">
          <Select value={strategy} onChange={setStrategy} options={strategyOptions} style={{ width: 180 }} />
          <Upload accept=".xlsx" maxCount={1} fileList={fileList} beforeUpload={() => false} onChange={({ fileList }) => setFileList(fileList)}>
            <Button icon={<UploadOutlined />}>选择 .xlsx 文件</Button>
          </Upload>
          <Button type="primary" loading={importAssets.isPending} disabled={!fileList.length} onClick={() => importAssets.mutate()}>开始导入</Button>
          {importResult && (
            <AntAlert
              type="success"
              showIcon
              message={`新增 ${importResult.created || 0} 条，更新 ${importResult.updated || 0} 条，跳过 ${importResult.skipped || 0} 条`}
              description={<pre>{JSON.stringify(importResult.errors || [], null, 2)}</pre>}
            />
          )}
        </Space>
      </Modal>
    </>
  );
}

function SegmentsPanel({ isAdmin }: { isAdmin: boolean }) {
  const [q, setQ] = useState('');
  const [editing, setEditing] = useState<AssetSegment | null>(null);
  const [open, setOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [fileList, setFileList] = useState<UploadFile[]>([]);
  const [strategy, setStrategy] = useState('skip');
  const [importResult, setImportResult] = useState<any>(null);
  const [selectedRowKeys, setSelectedRowKeys] = useState<Key[]>([]);
  const [form] = Form.useForm();
  const queryClient = useQueryClient();

  const { data = [], isLoading } = useQuery({
    queryKey: ['asset-segments', q],
    queryFn: async () => (await api.get<AssetSegment[]>('/api/assets/segments', { params: { q: q || undefined } })).data
  });
  const save = useMutation({
    mutationFn: async (payload: Partial<AssetSegment>) => {
      if (editing) return (await api.patch(`/api/assets/segments/${editing.id}`, { ...payload, updated_at: editing.updated_at })).data;
      return (await api.post('/api/assets/segments', payload)).data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['asset-segments'] });
      setOpen(false);
      setEditing(null);
      form.resetFields();
      message.success('网段配置已保存');
    },
    onError: (err: any) => {
      if (err.response?.status === 409) {
        message.error(err.response.data.detail || '保存失败：网段冲突或已被他人修改');
      } else {
        message.error('保存失败');
      }
    }
  });

  const remove = useMutation({
    mutationFn: async (id: number) => (await api.delete(`/api/assets/segments/${id}`)).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['asset-segments'] });
      message.success('网段已删除');
    }
  });

  const batchRemove = useMutation({
    mutationFn: async () => (await api.post('/api/assets/segments/batch-delete', { ids: selectedRowKeys })).data,
    onSuccess: (res) => {
      setSelectedRowKeys([]);
      queryClient.invalidateQueries({ queryKey: ['asset-segments'] });
      message.success(`已批量删除 ${res.deleted || 0} 条网段记录`);
    }
  });

  const importSegments = useMutation({
    mutationFn: async () => {
      const file = fileList[0]?.originFileObj;
      if (!file) throw new Error('请选择 Excel 文件');
      const formData = new FormData();
      formData.append('file', file);
      return (await api.post('/api/assets/segments/import', formData, { params: { strategy }, headers: { 'Content-Type': 'multipart/form-data' } })).data;
    },
    onSuccess: (data) => {
      setImportResult(data);
      queryClient.invalidateQueries({ queryKey: ['asset-segments'] });
      message.success('导入完成');
    }
  });

  const download = async (url: string, filename: string, params?: Record<string, unknown>) => {
    const response = await api.get(url, { params, responseType: 'blob' });
    const objectUrl = URL.createObjectURL(response.data);
    const link = document.createElement('a');
    link.href = objectUrl;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(objectUrl);
  };

  return (
    <>
      <div className="panel-toolbar">
        <Space wrap>
          <Input.Search placeholder="搜索网段 / 名称 / 区域" allowClear onSearch={setQ} style={{ width: 240 }} />
          {isAdmin && <Button type="primary" onClick={() => { setEditing(null); form.resetFields(); setOpen(true); }}>新增网段</Button>}
          {isAdmin && <Button icon={<UploadOutlined />} onClick={() => { setImportOpen(true); setImportResult(null); }}>导入 Excel</Button>}
          <Button onClick={() => download('/api/assets/segments/template.xlsx', 'segment_template.xlsx')}>导出模板</Button>
          <Button onClick={() => download('/api/assets/segments/export.xlsx', 'segments.xlsx', { q: q || undefined })}>导出资产</Button>
          {isAdmin && selectedRowKeys.length > 0 && (
            <Popconfirm title={`确定批量删除选中的 ${selectedRowKeys.length} 个网段？`} onConfirm={() => batchRemove.mutate()}>
              <Button danger loading={batchRemove.isPending}>批量删除</Button>
            </Popconfirm>
          )}
        </Space>
      </div>
      <Table
        size="small"
        rowKey="id"
        loading={isLoading}
        dataSource={data}
        rowSelection={isAdmin ? { selectedRowKeys, onChange: setSelectedRowKeys } : undefined}
        pagination={{ pageSizeOptions: ['10', '20', '50', '100'], showSizeChanger: true }}
        columns={[
          { title: '网段范围', dataIndex: 'segment', width: 180, render: (v) => <Typography.Text code>{v}</Typography.Text> },
          { title: '网段名称', dataIndex: 'name' },
          { title: '所属区域', dataIndex: 'area', width: 140 },
          { title: '负责人', dataIndex: 'owner', width: 120 },
          { title: '重要性', dataIndex: 'criticality', width: 100, render: (v: string) => <Tag color={criticalityColor[v]}>{criticalityLabel[v] || '中'}</Tag> },
          { title: '环境', dataIndex: 'environment', width: 120, render: (v: string) => environmentLabel[v] || v || '-' },
          {
            title: '操作',
            width: 140,
            render: (_: unknown, row: AssetSegment) => isAdmin ? (
              <Space>
                <Button size="small" onClick={() => { setEditing(row); form.setFieldsValue(row); setOpen(true); }}>编辑</Button>
                <Popconfirm title="确定删除该网段定义？" onConfirm={() => remove.mutate(row.id)}>
                  <Button size="small" danger>删除</Button>
                </Popconfirm>
              </Space>
            ) : <Typography.Text type="secondary">只读</Typography.Text>
          }
        ]}
      />
      <Modal title={editing ? '编辑网段' : '新增网段'} open={open} onCancel={() => setOpen(false)} onOk={() => form.submit()} width={680}>
        <Form form={form} layout="vertical" initialValues={{ criticality: 'medium' }} onFinish={(v) => save.mutate(v)}>
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item name="segment" label={<>网段范围 <HelpTip title="支持 CIDR (如 192.168.1.0/24) 或 范围 (如 10.0.0.1-10.0.0.50)。" /></>} rules={[{ required: true, message: '请填写网段范围' }]}><Input placeholder="192.168.1.0/24" /></Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="name" label={<>网段名称 <HelpTip title="该网段的业务含义，如“财务核心服务器段”。" /></>} rules={[{ required: true, message: '请填写网段名称' }]}><Input placeholder="XX 业务网段" /></Form.Item>
            </Col>
          </Row>
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item name="area" label={<>所属区域 <HelpTip title="用于网段的逻辑分类。" /></>}><Input placeholder="例如：办公区、生产区" /></Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="owner" label="负责人"><Input /></Form.Item>
            </Col>
          </Row>
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item name="criticality" label="默认重要性"><Select options={criticalityOptions} /></Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="environment" label="部署环境"><Input placeholder="例如：生产、开发" /></Form.Item>
            </Col>
          </Row>
          <Form.Item name="description" label="备注说明"><Input.TextArea rows={3} /></Form.Item>
        </Form>
      </Modal>

      <Modal title="导入网段 Excel" open={importOpen} onCancel={() => setImportOpen(false)} footer={null} width={620}>
        <Space direction="vertical" className="full-width">
          <Select value={strategy} onChange={setStrategy} options={strategyOptions} style={{ width: 180 }} />
          <Upload accept=".xlsx" maxCount={1} fileList={fileList} beforeUpload={() => false} onChange={({ fileList }) => setFileList(fileList)}>
            <Button icon={<UploadOutlined />}>选择 .xlsx 文件</Button>
          </Upload>
          <Button type="primary" loading={importSegments.isPending} disabled={!fileList.length} onClick={() => importSegments.mutate()}>开始导入</Button>
          {importResult && (
            <AntAlert
              type="success"
              showIcon
              message={`新增 ${importResult.created || 0} 条，更新 ${importResult.updated || 0} 条，跳过 ${importResult.skipped || 0} 条`}
              description={<pre>{JSON.stringify(importResult.errors || [], null, 2)}</pre>}
            />
          )}
        </Space>
      </Modal>
    </>
  );
}

export default function AssetCenter() {
  const { data: currentUser } = useQuery({
    queryKey: ['me'],
    queryFn: async () => (await api.get<User>('/api/auth/me')).data
  });
  const isAdmin = currentUser?.role === 'admin';

  return (
    <div className="page">
      <div className="page-toolbar">
        <div>
          <Typography.Title level={4}>资产中心</Typography.Title>
          <Typography.Text type="secondary">维护企业资产与网段库，为研判提供全方位业务上下文</Typography.Text>
        </div>
      </div>

      <Tabs
        type="card"
        items={[
          {
            key: 'individual',
            label: '个体资产',
            children: <Card className="plain-panel"><AssetsPanel isAdmin={isAdmin} /></Card>
          },
          {
            key: 'segments',
            label: '网段资产库',
            children: <Card className="plain-panel"><SegmentsPanel isAdmin={isAdmin} /></Card>
          }
        ]}
      />
    </div>
  );
}
