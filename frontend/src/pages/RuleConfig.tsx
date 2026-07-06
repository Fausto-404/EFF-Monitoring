import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Alert, AutoComplete, Button, Form, Input, InputNumber, Modal, Popconfirm, Select, Space, Switch, Table, Tag, Tooltip, Typography, message } from 'antd';
import { api } from '../api/client';
import type { Device, ParseRule, User } from '../api/types';
import HelpTip from '../components/HelpTip';
import { Eye, EyeOff } from 'lucide-react';

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
  { id: -22, name: '源资产重要性', field_key: 'src_asset_criticality', match_type: 'asset', category: '源资产详情', pattern: '源资产的重要程度等级', enabled: true },
  { id: -23, name: '源资产环境', field_key: 'src_asset_environment', match_type: 'asset', category: '源资产详情', pattern: '源资产所在的网络环境', enabled: true },
  { id: -24, name: '源资产指纹', field_key: 'src_asset_fingerprints', match_type: 'asset', category: '源资产详情', pattern: '源资产的详细指纹信息', enabled: true },
  { id: -25, name: '源IP地理位置', field_key: 'src_ip_location', match_type: 'system', category: '源资产详情', pattern: '源IP所属地理位置', enabled: true },

  // 目的资产详情 (7项)
  { id: -26, name: '目的资产名称', field_key: 'dst_asset_name', match_type: 'asset', category: '目的资产详情', pattern: '命中的目的资产名', enabled: true },
  { id: -27, name: '目的资产区域', field_key: 'dst_asset_area', match_type: 'asset', category: '目的资产详情', pattern: '目的资产所属的业务区域', enabled: true },
  { id: -28, name: '目的资产负责人', field_key: 'dst_asset_owner', match_type: 'asset', category: '目的资产详情', pattern: '目的资产的归属负责人', enabled: true },
  { id: -29, name: '目的资产重要性', field_key: 'dst_asset_criticality', match_type: 'asset', category: '目的资产详情', pattern: '目的资产的重要程度等级', enabled: true },
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

export default function RuleConfig({ isSubModule }: { isSubModule?: boolean }) {
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<ParseRule | null>(null);
  const [deviceFilter, setDeviceFilter] = useState<number | undefined>();
  const [showSystem, setShowSystem] = useState(false);
  const [form] = Form.useForm();
  const queryClient = useQueryClient();

  const { data: currentUser } = useQuery({
    queryKey: ['me'],
    queryFn: async () => (await api.get<User>('/api/auth/me')).data
  });
  const isAdmin = currentUser?.role === 'admin';

  const { data = [], isLoading } = useQuery({
    queryKey: ['rules'],
    queryFn: async () => (await api.get<ParseRule[]>('/api/rules')).data
  });

  const { data: devices = [] } = useQuery({
    queryKey: ['devices'],
    queryFn: async () => (await api.get<Device[]>('/api/devices')).data
  });

  const displayData = useMemo(() => {
    const customRules = deviceFilter ? data.filter((item) => item.device_id === deviceFilter) : data;
    return showSystem ? [...(systemBuiltinRules as ParseRule[]), ...customRules] : customRules;
  }, [data, deviceFilter, showSystem]);

  const create = useMutation({
    mutationFn: async (payload: Partial<ParseRule>) => {
      if (editing) {
        return (await api.patch(`/api/rules/${editing.id}`, payload)).data;
      }
      return (await api.post('/api/rules', payload)).data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rules'] });
      setOpen(false);
      setEditing(null);
      form.resetFields();
      message.success('规则已保存');
    },
    onError: (error: any) => message.error(error?.response?.data?.detail || '规则保存失败')
  });

  const remove = useMutation({
    mutationFn: async (id: number) => (await api.delete(`/api/rules/${id}`)).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rules'] });
      message.success('规则已删除');
    }
  });

  const content = (
    <>
      <div className="page-toolbar" style={isSubModule ? { padding: '0 0 16px 0', borderBottom: 'none' } : {}}>
        {!isSubModule && (
          <div>
            <Typography.Title level={4}>规则配置</Typography.Title>
            <Typography.Text type="secondary">配置内容解析正则表达式与字段提取规则</Typography.Text>
          </div>
        )}
        <div style={isSubModule ? { display: 'flex', justifyContent: 'flex-end', width: '100%' } : {}}>
          <Space wrap>
            <Tooltip title={showSystem ? '点击隐藏系统内置的只读规则' : '点击显示系统内置的只读规则'}>
              <Button 
                icon={showSystem ? <EyeOff size={16} /> : <Eye size={16} />} 
                onClick={() => setShowSystem(!showSystem)}
                type={showSystem ? 'primary' : 'default'}
                ghost={showSystem}
              >
                {showSystem ? '内置规则：显示中' : '内置规则：屏蔽中'}
              </Button>
            </Tooltip>
            <Select
              allowClear
              placeholder="按设备筛选"
              style={{ width: 180 }}
              value={deviceFilter}
              onChange={setDeviceFilter}
              options={devices.map((item) => ({ value: item.id, label: item.name }))}
            />
            {isAdmin && (
              <Button type="primary" onClick={() => { setEditing(null); form.resetFields(); setOpen(true); }}>新增规则</Button>
            )}
          </Space>
        </div>
      </div>
      <Table
        rowKey="id"
        loading={isLoading}
        dataSource={displayData}
        pagination={{ pageSizeOptions: ['10', '20', '50', '100'], showSizeChanger: true }}
        columns={[
          { title: '设备', dataIndex: 'device_id', width: 160, render: (v: number | null) => devices.find((item) => item.id === v)?.name || '通用' },
          { title: '字段类型', dataIndex: 'field_key', width: 140 },
          { 
            title: '规则名称', 
            dataIndex: 'name', 
            width: 180,
            render: (v: string, row: ParseRule) => (
              <Space>
                {v}
                {row.is_meta && <Tag color="orange">元规则</Tag>}
                {row.match_type === 'system' && <Tag color="blue">内置</Tag>}
                {row.match_type === 'asset' && <Tag color="cyan">资产</Tag>}
              </Space>
            )
          },
          { title: '方式', dataIndex: 'match_type', width: 120, render: (v: string) => ({ regex: '正则', builtin: '变量', system: '内置', asset: '资产' }[v] || v) },
          { title: '优先级', dataIndex: 'priority', width: 100 },
          { title: '启用', dataIndex: 'enabled', width: 80, render: (v: boolean) => (v ? '是' : '否') },
          { title: '规则', dataIndex: 'pattern' },
          {
            title: '操作',
            width: 150,
            render: (_: unknown, row: ParseRule) => {
              if (row.match_type === 'system' || row.match_type === 'asset') {
                return <Typography.Text type="secondary">系统内置</Typography.Text>;
              }
              if (!isAdmin) {
                return <Typography.Text type="secondary">无权修改</Typography.Text>;
              }
              return (
                <Space>
                  <Button size="small" onClick={() => { setEditing(row); form.setFieldsValue(row); setOpen(true); }}>编辑</Button>
                  {!row.is_meta && (
                    <Popconfirm title="删除该规则？" onConfirm={() => remove.mutate(row.id)}>
                      <Button size="small" danger>删除</Button>
                    </Popconfirm>
                  )}
                </Space>
              );
            }
          }
        ]}
      />

      <Modal title={editing ? (editing.is_meta ? '配置元规则' : '编辑规则') : '新增规则'} open={open} onCancel={() => { setOpen(false); setEditing(null); }} onOk={() => form.submit()} width={720}>
        {editing?.is_meta && <Alert message="元规则是系统核心字段，其名称、类型和解析方式固定不可修改，仅允许调整匹配规则与适用设备。" type="info" showIcon style={{ marginBottom: 16 }} />}
        <Form form={form} layout="vertical" initialValues={{ match_type: 'regex', priority: 100, enabled: true, match_all: false }} onFinish={(values) => create.mutate(values)}>
          <Form.Item name="device_id" label={<>设备<HelpTip title="选择设备后，该规则只在内容解析选择同一设备时生效；不选择则为通用规则。" /></>}><Select allowClear options={devices.map((item) => ({ value: item.id, label: item.name }))} /></Form.Item>
          <Form.Item name="name" label={<>规则名称 (作为模版变量使用)<HelpTip title="规则名称将直接作为模板占位符，例如规则名为“攻击源IP”，模板中即可写 {{攻击源IP}}。" /></>} rules={[{ required: true }]}><Input disabled={editing?.is_meta} variant={editing?.is_meta ? 'borderless' : 'outlined'} style={editing?.is_meta ? { background: '#f5f5f5' } : {}} /></Form.Item>
          <Form.Item
            name="field_key"
            label={<>字段类型 (系统识别标识)<HelpTip title="字段类型是系统逻辑（如资产关联）识别数据的依据。您可以选择预设类型，或直接输入自定义名称（仅限英文和下划线）。" /></>}
            rules={[
              { required: true },
              { pattern: /^[a-z0-9_]+$/, message: '仅支持小写字母、数字和下划线' }
            ]}
          >
            <AutoComplete
              disabled={editing?.is_meta}
              options={systemBuiltinRules.map(r => ({ value: r.field_key!, label: `${r.field_key} - ${r.name}` }))}
              filterOption={(inputValue, option) =>
                (option?.label || '').toUpperCase().indexOf(inputValue.toUpperCase()) !== -1
              }
              placeholder="选择预设或输入自定义 Key"
            />
          </Form.Item>
          <Form.Item name="field_label" label={<>字段名称<HelpTip title="字段名称用于展示和模板拼接，可写中文名；字段类型用于系统取值。" /></>}><Input disabled={editing?.is_meta} variant={editing?.is_meta ? 'borderless' : 'outlined'} style={editing?.is_meta ? { background: '#f5f5f5' } : {}} /></Form.Item>
          <Form.Item name="match_type" label={<>方式<HelpTip title="正则提取适合从日志中提取动态数据；内置变量用于引用当前时间、用户等系统信息。" /></>} rules={[{ required: true }]}>
            <Select disabled={editing?.is_meta} variant={editing?.is_meta ? 'borderless' : 'outlined'} style={editing?.is_meta ? { background: '#f5f5f5' } : {}} options={[
              { value: 'regex', label: '正则提取' },
              { value: 'builtin', label: '内置变量' }
            ]} />
          </Form.Item>
          <Form.Item noStyle shouldUpdate={(prev, next) => prev.match_type !== next.match_type || prev.field_key !== next.field_key}>
            {({ getFieldValue }) => {
              const type = getFieldValue('match_type');
              if (type === 'builtin') {
                return (
                  <Form.Item name="pattern" label={<>变量映射<HelpTip title="选择需要映射的系统变量。分组展示方便快速查找。" /></>} rules={[{ required: true }]}>
                    <Select showSearch optionFilterProp="label">
                      {Object.keys(categoryColors).map(cat => (
                        <Select.OptGroup key={cat} label={cat}>
                          {systemBuiltinRules.filter(r => r.category === cat).map(r => (
                            <Select.Option key={r.field_key!} value={r.field_key!} label={r.name!}>{r.name!}</Select.Option>
                          ))}
                        </Select.OptGroup>
                      ))}
                    </Select>
                  </Form.Item>
                );
              }
              return (
                <>
                  <Form.Item name="pattern" label={<>匹配规则<HelpTip title="正则必须包含捕获组，系统会取第一个捕获组作为字段值。跨行内容可使用 [\\s\\S]+?。" /></>} rules={[{ required: true }]}><Input.TextArea rows={4} /></Form.Item>
                  <Form.Item name="match_all" label={<>提取多个值<HelpTip title="开启后将提取日志中所有符合规则的内容（以逗号分隔），关闭则仅提取第一个。" /></>} valuePropName="checked"><Switch /></Form.Item>
                </>
              );
            }}
          </Form.Item>
          <Form.Item name="priority" label={<>优先级<HelpTip title="数字越小越先执行。同一字段有多个规则时，优先级高的规则会更早命中。" /></>}><InputNumber min={1} max={9999} /></Form.Item>
          <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal>
    </>
  );

  return isSubModule ? content : <div className="page">{content}</div>;
}
