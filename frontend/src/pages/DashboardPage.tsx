import { useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { Alert, Card, Col, DatePicker, Empty, Row, Statistic, Table, Tag, Typography, Space, Tooltip as AntTooltip, Button, Modal, message, Select } from 'antd';
import { InfoCircleOutlined, FileTextOutlined, CopyOutlined } from '@ant-design/icons';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import dayjs from 'dayjs';
import type { Dayjs } from 'dayjs';
import { api, reportApi } from '../api/client';
import type { Template } from '../api/types';

const { Text, Title } = Typography;

const statusColor: Record<string, string> = {
  analysis: '#1890ff',
  disposal: '#faad14',
  false_positive: '#eb2f96',
  ignored: '#8c8c8c',
  disposed: '#52c41a',
  total: '#2f54eb',
  mttd: '#fa8c16',
  mttr: '#52c41a'
};

const statusLabel: Record<string, string> = {
  analysis: '研判中',
  disposal: '处置中',
  false_positive: '误报',
  ignored: '忽略',
  disposed: '已处置'
};

const statusSeries = [
  'analysis',
  'disposal',
  'false_positive',
  'ignored',
  'disposed'
] as const;

function formatDuration(seconds: number | null): string {
  if (seconds === null || seconds === undefined) return '--';
  if (seconds < 60) return `${Math.round(seconds)}秒`;
  const mins = Math.floor(seconds / 60);
  const secs = Math.round(seconds % 60);
  if (mins < 60) return `${mins}分${secs}秒`;
  const hours = Math.floor(mins / 60);
  const remMins = mins % 60;
  return `${hours}小时${remMins}分`;
}

function EmptyChart() {
  return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无数据" />;
}

export default function DashboardPage() {
  const [range, setRange] = useState<[Dayjs, Dayjs] | null>([dayjs().startOf('day'), dayjs().endOf('day')]);
  const [reportModal, setReportModal] = useState<{ open: boolean; content: string; templateId?: number }>({ open: false, content: '' });

  const { data, isLoading, error } = useQuery({
    queryKey: ['dashboard', range?.[0]?.format('YYYY-MM-DD HH:mm:ss'), range?.[1]?.format('YYYY-MM-DD HH:mm:ss')],
    queryFn: async () => (await api.get('/api/dashboard/summary', {
      params: range ? {
        start_date: range[0].format('YYYY-MM-DD HH:mm:ss'),
        end_date: range[1].format('YYYY-MM-DD HH:mm:ss')
      } : {}
    })).data
  });

  const { data: templates = [] } = useQuery({
    queryKey: ['templates'],
    queryFn: async () => (await api.get<Template[]>('/api/templates')).data
  });

  const generateReport = useMutation({
    mutationFn: async (tplId?: number) => (await api.get('/api/dashboard/report', { params: { template_id: tplId } })).data,
    onSuccess: (res, tplId) => {
      setReportModal(prev => ({ ...prev, open: true, content: res.report, templateId: tplId }));
    },
    onError: () => {
      message.error('生成报告失败，请重试');
    }
  });

  const saveReport = useMutation({
    mutationFn: async () => reportApi.generateReport({
      title: `运营统计报告 - ${dayjs().format('YYYY-MM-DD')}`,
      report_category: '运营统计',
      source_type: 'module',
      source_module: 'dashboard',
      template_id: reportModal.templateId,
      period_start: range?.[0]?.toISOString(),
      period_end: range?.[1]?.toISOString(),
      render_context: data || {},
      source_refs: { template_id: reportModal.templateId },
      content: reportModal.content,
      save: true,
      tags: ['运营总览']
    }),
    onSuccess: () => message.success('报告已保存到报告中心'),
    onError: (error: any) => message.error(error?.response?.data?.detail || '报告保存失败')
  });

  const handleOpenReportModal = () => {
    const defaultTpl = templates.find(t => t.name.includes('日报')) || templates[0];
    generateReport.mutate(defaultTpl?.id);
  };

  const copyReport = () => {
    navigator.clipboard.writeText(reportModal.content);
    message.success('报告内容已复制到剪贴板');
  };

  const trend = data?.trend || [];
  const hasMttrTrend = trend.some((item: any) => item.mttr !== null && item.mttr !== undefined);

  return (
    <div className="page">
      <div className="page-toolbar">
        <div>
          <Typography.Title level={4}>运营总览</Typography.Title>
          <Typography.Text type="secondary">实时监控告警处理进度、增长趋势与处置效能</Typography.Text>
        </div>
        <Space wrap>
          <Button 
            icon={<FileTextOutlined />} 
            onClick={handleOpenReportModal}
            loading={generateReport.isPending}
          >
            生成报告
          </Button>
          <DatePicker.RangePicker 
            showTime
            value={range} 
            onChange={(val) => setRange(val as [Dayjs, Dayjs] | null)} 
          />
        </Space>
      </div>

      <Modal
        title="运营报告生成"
        open={reportModal.open}
        onCancel={() => setReportModal({ ...reportModal, open: false })}
        width={700}
        footer={[
          <Button key="close" onClick={() => setReportModal({ ...reportModal, open: false })}>
            关闭
          </Button>,
          <Button key="copy" type="primary" icon={<CopyOutlined />} onClick={copyReport}>
            复制报告
          </Button>,
          <Button key="save" type="primary" icon={<FileTextOutlined />} onClick={() => saveReport.mutate()} loading={saveReport.isPending} disabled={!reportModal.content}>
            保存到报告中心
          </Button>
        ]}
      >
        <Space direction="vertical" className="full-width" size={16}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span>选择模板：</span>
            <Select
              style={{ flex: 1 }}
              placeholder="请选择报告模板"
              value={reportModal.templateId}
              onChange={(val) => generateReport.mutate(val)}
              options={[
                { value: undefined, label: '系统默认报告' },
                ...templates.filter(t => t.type === 'message').map(t => ({ value: t.id, label: t.name }))
              ]}
            />
          </div>
          <div style={{ 
            background: '#f5f5f5', 
            padding: '16px', 
            borderRadius: '4px', 
            whiteSpace: 'pre-wrap', 
            fontFamily: 'monospace',
            minHeight: '300px',
            maxHeight: '500px',
            overflowY: 'auto',
            border: '1px solid #d9d9d9'
          }}>
            {generateReport.isPending ? '正在生成中...' : reportModal.content}
          </div>
        </Space>
      </Modal>

      {error && (
        <Alert
          type="error"
          showIcon
          message="运营总览数据加载失败"
          description="请检查后端服务是否正常，或刷新页面重试。"
          style={{ marginBottom: 16 }}
        />
      )}

      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={6}>
          <Card size="small">
            <Statistic title="所选期间告警总量" value={data?.total || 0} valueStyle={{ color: statusColor.total }} />
          </Card>
        </Col>
        <Col span={6}>
          <Card size="small">
            <Statistic title="待处理告警" value={data?.pending || 0} valueStyle={{ color: statusColor.analysis }} />
          </Card>
        </Col>
        <Col span={6}>
          <Card size="small">
            <Statistic title="已完成告警" value={data?.confirmed || 0} valueStyle={{ color: statusColor.disposed }} />
          </Card>
        </Col>
        <Col span={6}>
          <Card size="small">
            <Statistic 
              title={
                <Space>
                  平均处置耗时
                  <AntTooltip title={`平均处置耗时按告警从“研判中”进入“误报、忽略、已处置”的时间计算，当前样本 ${data?.mttr_count || 0} 条。`}>
                    <InfoCircleOutlined style={{ fontSize: '12px' }} />
                  </AntTooltip>
                </Space>
              } 
              value={formatDuration(data?.avg_mttr)} 
              valueStyle={{ color: statusColor.mttr }} 
            />
          </Card>
        </Col>
      </Row>

      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={14}>
          <Card title="告警增长趋势" size="small" loading={isLoading}>
            <div style={{ height: 350 }}>
              {trend.length ? (
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={trend} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
                    <CartesianGrid strokeDasharray="3 3" vertical={false} />
                    <XAxis dataKey="time" />
                    <YAxis allowDecimals={false} />
                    <Tooltip contentStyle={{ borderRadius: '8px', border: 'none', boxShadow: '0 4px 12px rgba(0,0,0,0.1)' }} />
                    <Legend iconType="circle" />
                    <Line name="总量" type="monotone" dataKey="total" stroke={statusColor.total} strokeWidth={3} dot={false} activeDot={{ r: 6 }} />
                    {statusSeries.map((key) => (
                      <Line
                        key={key}
                        name={statusLabel[key]}
                        type="monotone"
                        dataKey={key}
                        stroke={statusColor[key]}
                        strokeWidth={2}
                        dot={false}
                      />
                    ))}
                  </LineChart>
                </ResponsiveContainer>
              ) : <EmptyChart />}
            </div>
          </Card>
        </Col>
        <Col span={10}>
          <Card title="处置耗时趋势" size="small" loading={isLoading}>
            <div style={{ height: 350 }}>
              {hasMttrTrend ? (
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={trend} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
                    <CartesianGrid strokeDasharray="3 3" vertical={false} />
                    <XAxis dataKey="time" />
                    <YAxis width={72} tickFormatter={(value) => formatDuration(Number(value))} />
                    <Tooltip
                      labelStyle={{ marginBottom: 8, fontWeight: 'bold' }}
                      formatter={(val: number, name: string) => [
                        name === '平均处置耗时' ? formatDuration(val) : val,
                        name
                      ]}
                    />
                    <Legend iconType="circle" />
                    <Line name="平均处置耗时" type="linear" dataKey="mttr" stroke={statusColor.mttr} strokeWidth={3} connectNulls dot={false} activeDot={{ r: 6 }} />
                  </LineChart>
                </ResponsiveContainer>
              ) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无已完成处置的告警耗时数据" />}
            </div>
          </Card>
        </Col>
      </Row>

      <Row gutter={16}>
        <Col span={24}>
          <Card title="最近告警" size="small" loading={isLoading}>
            <Table
              size="small"
              rowKey="id"
              dataSource={data?.latest || []}
              pagination={false}
              loading={isLoading}
              columns={[
                { title: '时间', dataIndex: 'created_at', render: (v) => dayjs(v).format('YYYY-MM-DD HH:mm:ss') },
                { title: '告警编号', dataIndex: 'alert_code', render: (v) => <Typography.Text code>{v}</Typography.Text> },
                { title: '源 IP', dataIndex: 'source_ip' },
                { title: '目的 IP', dataIndex: 'destination_ip' },
                { title: '事件类型', dataIndex: 'event_type' },
                { title: '状态', dataIndex: 'status', render: (v: string) => <Tag color={statusColor[v]}>{statusLabel[v] || v}</Tag> }
              ]}
            />
          </Card>
        </Col>
      </Row>
    </div>
  );
}
