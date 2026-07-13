import { useMemo, useState } from 'react';
import type { Key } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { DeleteOutlined, DownloadOutlined, PlusOutlined, UploadOutlined } from '@ant-design/icons';
import { Alert, Button, Form, Input, Modal, Popconfirm, Select, Space, Table, Tag, Typography, message } from 'antd';
import dayjs from 'dayjs';
import { api } from '../api/client';
import HelpTip from '../components/HelpTip';

type ListType = 'whitelist' | 'blacklist';
type ValueType = 'single' | 'cidr' | 'range';

interface IpListItem {
  id: string;
  list_type: ListType;
  value: string;
  value_type: ValueType;
  description?: string;
  source?: string;
  created_at?: string;
  updated_at?: string;
}

interface Lists {
  whitelist: string[];
  blacklist: string[];
  items?: IpListItem[];
  updated_at?: string;
  deleted?: number;
  import_result?: {
    added: number;
    skipped: number;
    invalid: Array<{ value: string; error: string }>;
  };
}

const listTypeOptions = [
  { value: 'whitelist', label: '白名单' },
  { value: 'blacklist', label: '黑名单' }
];

const listTypeLabel: Record<ListType, string> = {
  whitelist: '白名单',
  blacklist: '黑名单'
};

const valueTypeLabel: Record<ValueType, string> = {
  single: '单 IP',
  cidr: 'CIDR',
  range: '范围'
};

const sourceLabel: Record<string, string> = {
  manual: '手工',
  alert_flow: '告警流转',
  import: '导入',
  legacy: '历史数据'
};

export default function IpListPage() {
  const [q, setQ] = useState('');
  const [listType, setListType] = useState<ListType | undefined>();
  const [valueType, setValueType] = useState<ValueType | undefined>();
  const [selectedRowKeys, setSelectedRowKeys] = useState<Key[]>([]);
  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<IpListItem | null>(null);
  const [importOpen, setImportOpen] = useState(false);
  const [importResult, setImportResult] = useState<Lists['import_result'] | null>(null);
  const [searchIp, setSearchIp] = useState('');
  const [searchResult, setSearchResult] = useState<{ ip: string; matched: boolean; matches: Array<{ label: string; range: string; list: string }> } | null>(null);
  const [form] = Form.useForm();
  const [importForm] = Form.useForm();
  const queryClient = useQueryClient();

  const { data: currentUser } = useQuery({
    queryKey: ['me'],
    queryFn: async () => (await api.get<any>('/api/auth/me')).data
  });
  const isViewer = currentUser?.role === 'viewer';

  const { data, isLoading } = useQuery({
    queryKey: ['ip-lists'],
    queryFn: async () => (await api.get<Lists>('/api/ip-lists')).data
  });

  const items = useMemo(() => data?.items || [], [data]);
  const filteredItems = useMemo(() => {
    const keyword = q.trim().toLowerCase();
    return items.filter((item) => {
      if (listType && item.list_type !== listType) return false;
      if (valueType && item.value_type !== valueType) return false;
      if (!keyword) return true;
      return [item.value, item.description, item.source].some((value) => String(value || '').toLowerCase().includes(keyword));
    });
  }, [items, listType, q, valueType]);

  const counts = useMemo(() => ({
    whitelist: items.filter((item) => item.list_type === 'whitelist').length,
    blacklist: items.filter((item) => item.list_type === 'blacklist').length
  }), [items]);

  const setListData = (updatedData: Lists) => {
    queryClient.setQueryData(['ip-lists'], updatedData);
  };

  const openEditor = (item?: IpListItem) => {
    setEditing(item || null);
    form.setFieldsValue(item || { list_type: 'whitelist', value: '', description: '' });
    setEditorOpen(true);
  };

  const saveItem = useMutation({
    mutationFn: async (values: Partial<IpListItem>) => {
      if (editing) {
        return (await api.patch<Lists>(`/api/ip-lists/items/${editing.id}`, values)).data;
      }
      return (await api.post<Lists>('/api/ip-lists/items', values)).data;
    },
    onSuccess: (updatedData: Lists) => {
      setListData(updatedData);
      setEditorOpen(false);
      setEditing(null);
      form.resetFields();
      message.success('名单项已保存');
    },
    onError: (error: any) => message.error(error?.response?.data?.detail || '保存失败')
  });

  const remove = useMutation({
    mutationFn: async (id: string) => (await api.delete<Lists>(`/api/ip-lists/items/${id}`)).data,
    onSuccess: (updatedData: Lists) => {
      setListData(updatedData);
      message.success('名单项已删除');
    },
    onError: (error: any) => message.error(error?.response?.data?.detail || '删除失败')
  });

  const batchRemove = useMutation({
    mutationFn: async () => (await api.post<Lists>('/api/ip-lists/batch-delete', { ids: selectedRowKeys })).data,
    onSuccess: (updatedData: Lists) => {
      setSelectedRowKeys([]);
      setListData(updatedData);
      message.success(`已删除 ${updatedData.deleted || selectedRowKeys.length} 个名单项`);
    },
    onError: (error: any) => message.error(error?.response?.data?.detail || '批量删除失败')
  });

  const check = useMutation({
    mutationFn: async () => (await api.post('/api/ip-lists/check', { ip: searchIp })).data,
    onSuccess: (result) => setSearchResult(result),
    onError: (error: any) => message.error(error?.response?.data?.detail || '检测失败')
  });

  const importItems = useMutation({
    mutationFn: async (values: any) => (await api.post<Lists>('/api/ip-lists/import', {
      list_type: values.list_type,
      text: values.text,
      description: values.description || ''
    })).data,
    onSuccess: (updatedData: Lists) => {
      setListData(updatedData);
      setImportResult(updatedData.import_result || null);
      message.success('导入完成');
    },
    onError: (error: any) => message.error(error?.response?.data?.detail || '导入失败')
  });

  const exportTxt = async (type: 'whitelist' | 'blacklist' | 'all') => {
    const response = await api.get('/api/ip-lists/export.txt', { params: { type }, responseType: 'blob' });
    const blob = new Blob([response.data], { type: 'text/plain;charset=utf-8' });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = type === 'all' ? 'ip-lists.txt' : `${type}.txt`;
    link.click();
    window.URL.revokeObjectURL(url);
  };

  return (
    <div className="page">
      <div className="page-toolbar">
        <div>
          <Typography.Title level={4}>IP 名单</Typography.Title>
          <Typography.Text type="secondary">按条目维护白名单和黑名单，支持单 IP、CIDR 和范围规则</Typography.Text>
        </div>
        <Space wrap>
          <Button icon={<DownloadOutlined />} onClick={() => exportTxt('whitelist')}>导出白名单</Button>
          <Button icon={<DownloadOutlined />} onClick={() => exportTxt('blacklist')}>导出黑名单</Button>
          <Button icon={<DownloadOutlined />} onClick={() => exportTxt('all')}>导出全部</Button>
          {!isViewer && <Button icon={<UploadOutlined />} onClick={() => { setImportOpen(true); setImportResult(null); importForm.setFieldsValue({ list_type: 'blacklist' }); }}>批量导入</Button>}
          {!isViewer && <Button type="primary" icon={<PlusOutlined />} onClick={() => openEditor()}>新增名单项</Button>}
        </Space>
      </div>

      <section className="plain-panel">
        <Typography.Title level={5}>IP 范围检测 <HelpTip title="输入单个 IP 后，系统会检查它是否落在白名单或黑名单的单 IP、CIDR、范围或简写范围中。" /></Typography.Title>
        <Space direction="vertical" className="full-width">
          <Space wrap>
            <Input value={searchIp} onChange={(event) => setSearchIp(event.target.value)} placeholder="输入 IP，检测是否命中白/黑名单范围" style={{ width: 360 }} />
            <Button type="primary" loading={check.isPending} disabled={!searchIp} onClick={() => check.mutate()}>检测 IP</Button>
          </Space>
          {searchResult && (
            <Alert
              type={searchResult.matched ? 'warning' : 'success'}
              showIcon
              message={searchResult.matched ? `${searchResult.ip} 命中名单` : `${searchResult.ip} 未命中名单`}
              description={<Space wrap>{searchResult.matches.map((item) => <Tag color={item.list === 'blacklist' ? 'red' : 'blue'} key={`${item.list}-${item.range}`}>{item.label}: {item.range}</Tag>)}</Space>}
            />
          )}
        </Space>
      </section>

      <div className="panel-toolbar">
        <Space wrap>
          <Input.Search allowClear placeholder="搜索 IP / 备注 / 来源" onSearch={setQ} onChange={(event) => setQ(event.target.value)} style={{ width: 240 }} />
          <Select allowClear placeholder="名单类型" value={listType} onChange={setListType} style={{ width: 130 }} options={listTypeOptions} />
          <Select allowClear placeholder="值类型" value={valueType} onChange={setValueType} style={{ width: 120 }} options={Object.entries(valueTypeLabel).map(([value, label]) => ({ value, label }))} />
          <Tag color="blue">白名单 {counts.whitelist}</Tag>
          <Tag color="red">黑名单 {counts.blacklist}</Tag>
          <Typography.Text type="secondary">已选择 {selectedRowKeys.length} 项</Typography.Text>
          {!isViewer && selectedRowKeys.length > 0 && (
            <Popconfirm title={`确定删除选中的 ${selectedRowKeys.length} 个名单项？`} onConfirm={() => batchRemove.mutate()}>
              <Button danger icon={<DeleteOutlined />} loading={batchRemove.isPending}>批量删除</Button>
            </Popconfirm>
          )}
        </Space>
      </div>

      <Table
        rowKey="id"
        size="small"
        loading={isLoading}
        dataSource={filteredItems}
        rowSelection={isViewer ? undefined : { selectedRowKeys, onChange: setSelectedRowKeys }}
        pagination={{ pageSizeOptions: ['10', '20', '50', '100'], showSizeChanger: true }}
        columns={[
          { title: '名单', dataIndex: 'list_type', width: 100, render: (value: ListType) => <Tag color={value === 'blacklist' ? 'red' : 'blue'}>{listTypeLabel[value]}</Tag> },
          { title: 'IP / CIDR / 范围', dataIndex: 'value', width: 220, render: (value: string) => <Typography.Text code>{value}</Typography.Text> },
          { title: '类型', dataIndex: 'value_type', width: 100, render: (value: ValueType) => valueTypeLabel[value] || value },
          { title: '来源', dataIndex: 'source', width: 110, render: (value: string) => sourceLabel[value] || value || '-' },
          { title: '备注', dataIndex: 'description' },
          { title: '更新时间', dataIndex: 'updated_at', width: 180, render: (value: string) => value ? dayjs(value).format('YYYY-MM-DD HH:mm:ss') : '-' },
          {
            title: '操作',
            width: 150,
            render: (_: unknown, row: IpListItem) => (
              <Space>
                {!isViewer && <Button size="small" onClick={() => openEditor(row)}>编辑</Button>}
                {!isViewer && (
                  <Popconfirm title="删除该名单项？" onConfirm={() => remove.mutate(row.id)}>
                    <Button size="small" danger>删除</Button>
                  </Popconfirm>
                )}
              </Space>
            )
          }
        ]}
      />

      <Modal title={editing ? '编辑名单项' : '新增名单项'} open={editorOpen} onCancel={() => setEditorOpen(false)} onOk={() => form.submit()} confirmLoading={saveItem.isPending} destroyOnClose>
        <Form form={form} layout="vertical" onFinish={(values) => saveItem.mutate(values)}>
          <Form.Item name="list_type" label="名单类型" rules={[{ required: true, message: '请选择名单类型' }]}>
            <Select options={listTypeOptions} />
          </Form.Item>
          <Form.Item name="value" label="IP / CIDR / 范围" rules={[{ required: true, message: '请输入名单值' }]}>
            <Input placeholder="192.168.1.10、10.0.0.0/24、192.168.1.10-50" />
          </Form.Item>
          <Form.Item name="description" label="备注">
            <Input.TextArea rows={3} />
          </Form.Item>
        </Form>
      </Modal>

      <Modal title="批量导入 IP 名单" open={importOpen} onCancel={() => setImportOpen(false)} onOk={() => importForm.submit()} confirmLoading={importItems.isPending} width={760}>
        <Space direction="vertical" className="full-width" size="middle">
          <Alert type="info" showIcon message="导入说明" description="每行导入为一个名单规则。CIDR 和范围会保留为规则条目。" />
          <Form form={importForm} layout="vertical" initialValues={{ list_type: 'blacklist' }} onFinish={(values) => importItems.mutate(values)}>
            <Form.Item name="list_type" label="导入到" rules={[{ required: true }]}>
              <Select options={listTypeOptions} />
            </Form.Item>
            <Form.Item name="text" label="IP / CIDR / 范围" rules={[{ required: true, message: '请输入要导入的内容' }]}>
              <Input.TextArea rows={8} placeholder="每行一个，支持 192.168.1.10、10.0.0.0/24、192.168.1.10-50" />
            </Form.Item>
            <Form.Item name="description" label="备注">
              <Input placeholder="批量导入备注，可选" />
            </Form.Item>
          </Form>
          {importResult && (
            <Alert
              type={importResult.invalid.length ? 'warning' : 'success'}
              showIcon
              message={`导入结果：新增 ${importResult.added}，跳过 ${importResult.skipped}`}
              description={importResult.invalid.length ? importResult.invalid.map((item) => `${item.value}: ${item.error}`).join('；') : '全部导入成功'}
            />
          )}
        </Space>
      </Modal>
    </div>
  );
}
