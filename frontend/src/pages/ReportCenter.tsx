import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Button, Collapse, DatePicker, Descriptions, Drawer, Form, Input, Modal, Popconfirm, Select, Space, Table, Tag, Typography, message } from 'antd';
import { Download, RefreshCw } from 'lucide-react';
import dayjs from 'dayjs';
import { api, reportApi } from '../api/client';
import type { ReportRecord } from '../api/types';

const { RangePicker } = DatePicker;

function parseTags(value: string | undefined): string[] {
  return (value || '')
    .split(/[,，\s]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function tagsToText(tags?: string[]) {
  return (tags || []).join(', ');
}

function JsonBlock({ value }: { value: unknown }) {
  return <pre>{JSON.stringify(value || {}, null, 2)}</pre>;
}

export default function ReportCenter() {
  const [filters, setFilters] = useState<Record<string, any>>({});
  const [selected, setSelected] = useState<ReportRecord | null>(null);
  const [editing, setEditing] = useState<ReportRecord | null>(null);
  const [editorOpen, setEditorOpen] = useState(false);
  const [form] = Form.useForm();
  const queryClient = useQueryClient();

  const queryParams = useMemo(() => ({
    q: filters.q || undefined,
    report_category: filters.report_category,
    source_type: filters.source_type,
    source_module: filters.source_module,
    tag: filters.tag,
    start_date: filters.range?.[0]?.toISOString(),
    end_date: filters.range?.[1]?.toISOString()
  }), [filters]);

  const { data = [], isLoading, refetch } = useQuery({
    queryKey: ['reports', queryParams],
    queryFn: () => reportApi.listReports(queryParams)
  });

  const { data: facets } = useQuery({
    queryKey: ['report-facets'],
    queryFn: reportApi.getReportFacets
  });

  const save = useMutation({
    mutationFn: async (values: any) => {
      const payload = {
        title: values.title,
        report_category: values.report_category || null,
        tags: parseTags(values.tags),
        content: values.content || ''
      };
      if (editing) return reportApi.updateReport(editing.id, payload);
      return reportApi.createReport({
        ...payload,
        source_type: 'manual',
        source_module: 'report_center',
        format: 'markdown'
      });
    },
    onSuccess: (row) => {
      queryClient.invalidateQueries({ queryKey: ['reports'] });
      queryClient.invalidateQueries({ queryKey: ['report-facets'] });
      setEditorOpen(false);
      setEditing(null);
      setSelected(row);
      form.resetFields();
      message.success('报告已保存');
    },
    onError: (error: any) => message.error(error?.response?.data?.detail || '保存失败')
  });

  const duplicate = useMutation({
    mutationFn: (id: number) => reportApi.duplicateReport(id),
    onSuccess: (row) => {
      queryClient.invalidateQueries({ queryKey: ['reports'] });
      queryClient.invalidateQueries({ queryKey: ['report-facets'] });
      setSelected(row);
      message.success('报告已复制');
    }
  });

  const remove = useMutation({
    mutationFn: (id: number) => reportApi.deleteReport(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['reports'] });
      queryClient.invalidateQueries({ queryKey: ['report-facets'] });
      setSelected(null);
      message.success('报告已删除');
    },
    onError: (error: any) => message.error(error?.response?.data?.detail || '删除失败')
  });

  const openEditor = (row?: ReportRecord) => {
    setEditing(row || null);
    form.setFieldsValue(row ? {
      title: row.title,
      report_category: row.report_category,
      tags: tagsToText(row.tags),
      content: row.content
    } : {
      title: '',
      report_category: '',
      tags: '',
      content: ''
    });
    setEditorOpen(true);
  };

  const exportReport = async (row: ReportRecord, format: 'md') => {
    const response = await api.get(reportApi.getReportExportUrl(row.id, format), { responseType: 'blob' });
    const url = URL.createObjectURL(response.data);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${row.title || 'report'}.${format}`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="page">
      <div className="page-toolbar">
        <div>
          <Typography.Title level={4}>报告中心</Typography.Title>
          <Typography.Text type="secondary">统一管理由模板、规则和其他模块生成的报告。</Typography.Text>
        </div>
        <Space wrap>
          <Button type="primary" onClick={() => openEditor()}>新建报告</Button>
          <Button icon={<RefreshCw size={16} />} onClick={() => refetch()}>刷新</Button>
        </Space>
      </div>

      <div className="panel-toolbar" style={{ justifyContent: 'flex-start' }}>
        <Space wrap>
          <Input.Search allowClear placeholder="关键词" style={{ width: 220 }} onSearch={(q) => setFilters((prev) => ({ ...prev, q }))} />
          <Select allowClear placeholder="报告分类" style={{ width: 160 }} value={filters.report_category} onChange={(value) => setFilters((prev) => ({ ...prev, report_category: value }))} options={(facets?.categories || []).map((item) => ({ value: item, label: item }))} />
          <Select allowClear placeholder="来源类型" style={{ width: 140 }} value={filters.source_type} onChange={(value) => setFilters((prev) => ({ ...prev, source_type: value }))} options={(facets?.source_types || []).map((item) => ({ value: item, label: item }))} />
          <Select allowClear placeholder="来源模块" style={{ width: 150 }} value={filters.source_module} onChange={(value) => setFilters((prev) => ({ ...prev, source_module: value }))} options={(facets?.source_modules || []).map((item) => ({ value: item, label: item }))} />
          <Select allowClear placeholder="标签" style={{ width: 130 }} value={filters.tag} onChange={(value) => setFilters((prev) => ({ ...prev, tag: value }))} options={(facets?.tags || []).map((item) => ({ value: item, label: item }))} />
          <RangePicker showTime value={filters.range} onChange={(range) => setFilters((prev) => ({ ...prev, range }))} />
        </Space>
      </div>

      <Table
        rowKey="id"
        loading={isLoading}
        dataSource={data}
        pagination={{ pageSizeOptions: ['10', '20', '50', '100'], showSizeChanger: true }}
        columns={[
          { title: '标题', dataIndex: 'title', render: (value: string, row: ReportRecord) => <Button type="link" onClick={() => setSelected(row)}>{value}</Button> },
          { title: '分类', dataIndex: 'report_category', width: 150, render: (value?: string) => value || '-' },
          { title: '来源', width: 180, render: (_: unknown, row: ReportRecord) => `${row.source_type || '-'} / ${row.source_module || '-'}` },
          { title: '标签', dataIndex: 'tags', width: 180, render: (tags: string[]) => (tags || []).map((tag) => <Tag key={tag}>{tag}</Tag>) },
          { title: '更新时间', dataIndex: 'updated_at', width: 170, render: (value: string) => dayjs(value).format('YYYY-MM-DD HH:mm:ss') },
          {
            title: '操作',
            width: 320,
            render: (_: unknown, row: ReportRecord) => (
              <Space wrap>
                <Button size="small" onClick={() => setSelected(row)}>查看</Button>
                <Button size="small" onClick={() => openEditor(row)}>编辑</Button>
                <Button size="small" onClick={() => duplicate.mutate(row.id)}>复制</Button>
                <Button size="small" icon={<Download size={14} />} onClick={() => exportReport(row, 'md')}>导出 MD</Button>
                <Popconfirm title="彻底删除该报告？" onConfirm={() => remove.mutate(row.id)}>
                  <Button size="small" danger>删除</Button>
                </Popconfirm>
              </Space>
            )
          }
        ]}
      />

      <Drawer title="报告详情" open={!!selected} onClose={() => setSelected(null)} width={760}>
        {selected && (
          <Space direction="vertical" className="full-width" size={16}>
            <Descriptions column={2} size="small" bordered>
              <Descriptions.Item label="标题" span={2}>{selected.title}</Descriptions.Item>
              <Descriptions.Item label="分类">{selected.report_category || '-'}</Descriptions.Item>
              <Descriptions.Item label="来源类型">{selected.source_type}</Descriptions.Item>
              <Descriptions.Item label="来源模块">{selected.source_module}</Descriptions.Item>
              <Descriptions.Item label="标签" span={2}>{(selected.tags || []).map((tag) => <Tag key={tag}>{tag}</Tag>)}</Descriptions.Item>
              <Descriptions.Item label="创建时间">{dayjs(selected.created_at).format('YYYY-MM-DD HH:mm:ss')}</Descriptions.Item>
              <Descriptions.Item label="更新时间">{dayjs(selected.updated_at).format('YYYY-MM-DD HH:mm:ss')}</Descriptions.Item>
            </Descriptions>
            <div>
              <Typography.Text strong>正文</Typography.Text>
              <pre style={{ marginTop: 8 }}>{selected.content}</pre>
            </div>
            <Collapse
              items={[
                { key: 'render_context', label: 'render_context', children: <JsonBlock value={selected.render_context} /> },
                { key: 'source_refs', label: 'source_refs', children: <JsonBlock value={selected.source_refs} /> },
                { key: 'scope', label: 'scope', children: <JsonBlock value={selected.scope} /> },
                { key: 'input_payload', label: 'input_payload', children: <JsonBlock value={selected.input_payload} /> }
              ]}
            />
          </Space>
        )}
      </Drawer>

      <Modal title={editing ? '编辑报告' : '新建报告'} open={editorOpen} onCancel={() => setEditorOpen(false)} onOk={() => form.submit()} width={760}>
        <Form form={form} layout="vertical" onFinish={(values) => save.mutate(values)}>
          <Form.Item name="title" label="标题" rules={[{ required: true, message: '请填写标题' }]}>
            <Input />
          </Form.Item>
          <Form.Item name="report_category" label="分类">
            <Input />
          </Form.Item>
          <Form.Item name="tags" label="标签">
            <Input placeholder="多个标签用逗号或空格分隔" />
          </Form.Item>
          <Form.Item name="content" label="正文">
            <Input.TextArea rows={14} />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
}
