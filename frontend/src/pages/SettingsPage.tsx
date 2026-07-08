import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Alert, Button, Card, Col, Form, Input, Row, Select, Space, Switch, Tabs, Typography, message, Divider, Badge, AutoComplete, Tooltip } from 'antd';
import { api } from '../api/client';
import type { User } from '../api/types';
import HelpTip from '../components/HelpTip';
import { Globe, User as UserIcon, Zap, Shield, Cpu, Cloud, Database, Activity, CheckCircle2, XCircle, Sparkles, MessageSquare, Bot, RefreshCcw, Info } from 'lucide-react';

type Scope = 'global' | 'personal';

interface AiProvider {
  value: string;
  label: string;
  icon: React.ReactNode;
  color: string;
  baseUrl: string;
  model: string;
  models?: string[];
}

const PROVIDERS: AiProvider[] = [
  { 
    value: 'openai-compatible', 
    label: 'OpenAI 协议适配', 
    icon: <Zap size={16} />, 
    color: '#747bff', 
    baseUrl: '', 
    model: '',
    models: ['gpt-4o', 'gpt-4o-mini', 'gpt-3.5-turbo']
  },
  { 
    value: 'deepseek', 
    label: 'DeepSeek', 
    icon: <Shield size={16} />, 
    color: '#0052D9', 
    baseUrl: 'https://api.deepseek.com', 
    model: '',
    models: ['deepseek-chat', 'deepseek-reasoner', 'deepseek-coder']
  },
  { 
    value: 'siliconflow', 
    label: 'SiliconFlow', 
    icon: <Cpu size={16} />, 
    color: '#ff4d4f', 
    baseUrl: 'https://api.siliconflow.cn/v1', 
    model: '',
    models: ['deepseek-ai/DeepSeek-V3', 'deepseek-ai/DeepSeek-R1', 'Qwen/Qwen2.5-72B-Instruct', 'THUDM/glm-4-9b-chat']
  },
  { 
    value: 'qwen', 
    label: '通义千问', 
    icon: <Cloud size={16} />, 
    color: '#ff9c6e', 
    baseUrl: 'https://dashscope.aliyuncs.com/compatible-mode/v1', 
    model: '',
    models: ['qwen-max', 'qwen-plus', 'qwen-turbo', 'qwen-long']
  },
  { 
    value: 'zhipu', 
    label: '智谱 AI', 
    icon: <Activity size={16} />, 
    color: '#36cfc9', 
    baseUrl: 'https://open.bigmodel.cn/api/paas/v4', 
    model: '',
    models: ['glm-4-plus', 'glm-4-air', 'glm-4-flash', 'glm-4v-plus']
  },
  { 
    value: 'moonshot', 
    label: '月之暗面 (Kimi)', 
    icon: <Sparkles size={16} />, 
    color: '#323232', 
    baseUrl: 'https://api.moonshot.cn/v1', 
    model: '',
    models: ['moonshot-v1-8k', 'moonshot-v1-32k', 'moonshot-v1-128k']
  },
  { 
    value: 'anthropic', 
    label: 'Anthropic (Claude)', 
    icon: <MessageSquare size={16} />, 
    color: '#d97757', 
    baseUrl: 'https://api.anthropic.com/v1', 
    model: '',
    models: ['claude-3-5-sonnet-20241022', 'claude-3-5-haiku-20241022', 'claude-3-opus-20240229']
  },
  { 
    value: 'google', 
    label: 'Google (Gemini)', 
    icon: <Bot size={16} />, 
    color: '#4285f4', 
    baseUrl: 'https://generativelanguage.googleapis.com/v1beta/openai', 
    model: '',
    models: ['gemini-1.5-pro', 'gemini-1.5-flash', 'gemini-1.0-pro']
  },
  { 
    value: 'ollama', 
    label: 'Ollama (本地)', 
    icon: <Database size={16} />, 
    color: '#52c41a', 
    baseUrl: 'http://localhost:11434', 
    model: '',
    models: ['llama3', 'qwen2.5', 'deepseek-r1', 'mistral', 'phi3']
  },
];

function AiConfigForm({ scope, initialValues, onSave, isSaving }: any) {
  const [form] = Form.useForm();
  const [testResult, setTestResult] = useState<{ status: 'idle' | 'loading' | 'success' | 'error'; message?: string }>({ status: 'idle' });
  const [dynamicModels, setDynamicModels] = useState<Array<{ id: string, owned_by: string }>>([]);
  const isPersonal = scope === 'personal';

  useEffect(() => {
    form.resetFields();
    form.setFieldsValue(initialValues);
    setTestResult({ status: 'idle' });
    setDynamicModels([]);
  }, [initialValues, scope, form]);

  const testConnection = useMutation({
    mutationFn: async (payload: any) => (await api.post('/api/ai/test-connection', payload)).data,
    onMutate: () => setTestResult({ status: 'loading' }),
    onSuccess: (data) => {
      setTestResult({ status: 'success', message: `连接成功！模型响应: ${data.response.substring(0, 50)}...` });
    },
    onError: (error: any) => {
      setTestResult({ status: 'error', message: error?.response?.data?.detail || '连接失败，请检查配置' });
    }
  });

  const fetchModels = useMutation({
    mutationFn: async (payload: any) => (await api.post('/api/ai/models', payload)).data,
    onSuccess: (data) => {
      if (data.models && data.models.length > 0) {
        setDynamicModels(data.models);
        message.success(`成功获取 ${data.models.length} 个可用模型`);
      } else {
        message.warning('未获取到模型列表，请确认地址和 Key 是否正确');
      }
    },
    onError: (error: any) => {
      message.error(error?.response?.data?.detail || '获取模型列表失败');
    }
  });

  return (
    <Card 
      size="small" 
      title={
        <Space>
          <span>AI 模型代理配置</span>
          <Typography.Text type="secondary" style={{ fontSize: '12px', fontWeight: 'normal' }}>
            {isPersonal ? '(仅自己有效，可覆盖全局配置)' : '(全局默认，对所有成员生效)'}
          </Typography.Text>
        </Space>
      } 
      extra={
        <Space>
          <Badge status={testResult.status === 'success' ? 'success' : testResult.status === 'error' ? 'error' : 'default'} />
          <Typography.Text type="secondary">
            {testResult.status === 'success' ? '已连通' : testResult.status === 'error' ? '连通失败' : '未测试'}
          </Typography.Text>
        </Space>
      }
    >
      <Form 
        form={form}
        layout="vertical" 
        onFinish={(value) => onSave(value)}
      >
        <Row gutter={24}>
          <Col span={24}>
            <Form.Item label="模型服务商" required>
              <Form.Item name="provider" noStyle rules={[{ required: true }]}>
                <Input type="hidden" />
              </Form.Item>
              <Form.Item noStyle shouldUpdate={(prev, next) => prev.provider !== next.provider}>
                {({ getFieldValue, setFieldValue }) => {
                  const currentProvider = getFieldValue('provider');
                  return (
                    <Row gutter={[12, 12]}>
                      {PROVIDERS.map(p => (
                        <Col key={p.value} xs={12} sm={8} md={6}>
                          <div 
                            className={`provider-card ${currentProvider === p.value ? 'active' : ''}`}
                            onClick={() => {
                              setFieldValue('provider', p.value);
                              const provider = PROVIDERS.find(item => item.value === p.value);
                              if (provider) {
                                setFieldValue('base_url', provider.baseUrl);
                                setFieldValue('model', provider.model);
                              }
                              setDynamicModels([]); // 清空当前组件的模型列表
                            }}
                            style={{
                              border: `1px solid ${currentProvider === p.value ? p.color : '#f0f0f0'}`,
                              background: currentProvider === p.value ? `${p.color}08` : '#fff',
                              color: currentProvider === p.value ? p.color : 'inherit'
                            }}
                          >
                            {p.icon}
                            <span>{p.label}</span>
                          </div>
                        </Col>
                      ))}
                    </Row>
                  );
                }}
              </Form.Item>
            </Form.Item>
          </Col>
          
          <Col span={14}>
            <Form.Item name="base_url" label="接口地址 (Base URL)" rules={[{ required: true }]}>
              <Input placeholder="例如 https://api.openai.com/v1" prefix={<Globe size={14} />} />
            </Form.Item>
          </Col>
          <Col span={10}>
            <Form.Item noStyle shouldUpdate={(prev, next) => prev.provider !== next.provider}>
              {({ getFieldValue }) => {
                const providerValue = getFieldValue('provider');
                const provider = PROVIDERS.find(p => p.value === providerValue);
                const grouped: Record<string, string[]> = { '推荐模型': provider?.models || [] };
                
                dynamicModels.forEach((m: any) => {
                  const vendor = m.owned_by || '其他厂商';
                  if (!grouped[vendor]) grouped[vendor] = [];
                  if (!grouped[vendor].includes(m.id)) {
                    grouped[vendor].push(m.id);
                  }
                });

                const options = Object.keys(grouped).filter(v => grouped[v].length > 0).map(vendor => ({
                  label: vendor,
                  options: grouped[vendor].map(id => ({ value: id, label: id }))
                }));
                
                return (
                  <Form.Item 
                    name="model" 
                    label={
                      <Space size={4}>
                        模型名称 (Model ID)
                        <Tooltip title="从服务端同步模型列表">
                          <Button 
                            type="link" 
                            size="small" 
                            icon={<RefreshCcw size={12} className={fetchModels.isPending ? 'spin-icon' : ''} />} 
                            style={{ padding: 0, height: 'auto' }}
                            onClick={() => fetchModels.mutate(form.getFieldsValue())}
                            disabled={fetchModels.isPending}
                          />
                        </Tooltip>
                      </Space>
                    } 
                    rules={[{ required: true }]}
                  >
                    <AutoComplete
                      options={options}
                      placeholder="选择预设或输入模型 ID"
                      filterOption={(inputValue, option) => {
                        const val = (option as any)?.value;
                        return val ? String(val).toUpperCase().indexOf(inputValue.toUpperCase()) !== -1 : false;
                      }}
                    />
                  </Form.Item>
                );
              }}
            </Form.Item>
          </Col>

          <Col span={24}>
            <Form.Item noStyle shouldUpdate={(prev, next) => prev.provider !== next.provider}>
              {({ getFieldValue }) => {
                const provider = getFieldValue('provider');
                const isOllama = provider === 'ollama';
                return (
                  <Form.Item
                    name="api_key"
                    label="接口密钥 (API Key)"
                    rules={isOllama ? [] : [{ required: true, message: '请输入接口密钥' }]}
                  >
                    <Input.Password placeholder={isOllama ? 'Ollama 本地部署通常不需要密钥' : '请输入 API 密钥'} />
                  </Form.Item>
                );
              }}
            </Form.Item>
          </Col>

          <Col span={12}>
            <Form.Item name="temperature" label="采样温度 (Temperature)">
              <Input type="number" min={0} max={2} step={0.1} />
            </Form.Item>
          </Col>
          
          <Col span={12} style={{ display: 'flex', alignItems: 'flex-end', paddingBottom: 24 }}>
            <Button 
              icon={testResult.status === 'success' ? <CheckCircle2 size={16} /> : testResult.status === 'error' ? <XCircle size={16} /> : <Zap size={16} />}
              loading={testConnection.isPending}
              onClick={() => testConnection.mutate(form.getFieldsValue())}
              className="test-btn"
            >
              测试连通性
            </Button>
          </Col>
        </Row>

        {testResult.message && (
          <Alert 
            message={testResult.status === 'success' ? '测试通过' : '测试失败'} 
            description={testResult.message}
            type={testResult.status === 'success' ? 'success' : 'error'}
            showIcon
            style={{ marginBottom: 16 }}
          />
        )}

        <Divider style={{ margin: '12px 0 24px' }} />
        <Button type="primary" size="large" htmlType="submit" loading={isSaving}>
          保存{isPersonal ? '个人配置' : '全员配置'}
        </Button>
      </Form>
    </Card>
  );
}

function TiConfigForm({ initialValues, onSave, scope, isSaving }: any) {
  const [form] = Form.useForm();
  const isPersonal = scope === 'personal';

  useEffect(() => {
    form.resetFields();
    form.setFieldsValue(initialValues);
  }, [initialValues, scope, form]);

  return (
    <Card 
      size="small" 
      title={
        <Space>
          <span>威胁情报配置</span>
          <Typography.Text type="secondary" style={{ fontSize: '12px', fontWeight: 'normal' }}>
            {isPersonal ? '(仅自己有效)' : '(全员生效)'}
          </Typography.Text>
        </Space>
      }
    >
      <Form 
        form={form}
        layout="vertical" 
        onFinish={(value) => onSave(value)}
      >
        <Form.Item name="enabled" label="启用全局情报增强" valuePropName="checked"><Switch /></Form.Item>
        <Form.Item name="active_provider" label="当前激活的情报源"><Select options={[
          { value: 'threatbook', label: '微步TI (ThreatBook)' },
          { value: 'nsfocus', label: '绿盟 NTI (NSFocus)' },
          { value: 'qianxin', label: '奇安信 TI (QiAnXin)' },
          { value: 'dbapp', label: '安恒 TI (DBAppSecurity)' }
        ]} /></Form.Item>
        <Form.Item name="mode" label="查询对象"><Select options={[{ value: 'both', label: '源和目的' }, { value: 'src', label: '仅源 IP' }, { value: 'dst', label: '仅目的 IP' }]} /></Form.Item>
        
        <Form.Item noStyle shouldUpdate={(prev, next) => prev.active_provider !== next.active_provider}>
          {({ getFieldValue }) => {
            const provider = getFieldValue('active_provider') || 'threatbook';
            
            if (provider === 'threatbook') {
              return (
                <>
                  <Typography.Title level={5} style={{ marginTop: 16 }}>
                    微步威胁情报配置 
                    <HelpTip title={<>官方 API 模式：在 <a href="https://x.threatbook.com/v5/serviceCenter?tab=myKey" target="_blank" rel="noreferrer">微步服务中心</a> 获取 API Key。<br/>网页 Cookie 模式：登录微步在线后抓包获取。</>} />
                  </Typography.Title>
                  <Form.Item name={['threatbook', 'mode']} label="接入方式"><Select options={[
                    { value: 'api', label: '官方 API 模式 (推荐)' },
                    { value: 'web', label: '网页 Cookie 模式 (配额不足时使用)' }
                  ]} /></Form.Item>

                  <Form.Item noStyle shouldUpdate={(p, n) => p.threatbook?.mode !== n.threatbook?.mode}>
                    {({ getFieldValue: getInner }) => {
                      const mode = getInner(['threatbook', 'mode']) || 'api';
                      if (mode === 'api') {
                        return <Form.Item name={['threatbook', 'api_key']} label="API Key"><Input.Password placeholder="微步标准接口密钥" /></Form.Item>;
                      }
                      return (
                        <>
                          <Form.Item name={['threatbook', 'http_cookie']} label="浏览器 Cookie"><Input.TextArea rows={3} /></Form.Item>
                          <Row gutter={16}>
                            <Col span={12}><Form.Item name={['threatbook', 'x_csrf_token']} label="x-csrf-token"><Input /></Form.Item></Col>
                            <Col span={12}><Form.Item name={['threatbook', 'xx_csrf']} label="xx-csrf"><Input /></Form.Item></Col>
                          </Row>
                        </>
                      );
                    }}
                  </Form.Item>
                </>
              );
            }
            if (provider === 'nsfocus') {
              return (
                <>
                  <Typography.Title level={5} style={{ marginTop: 16 }}>
                    绿盟 (NSFocus NTI) 配置 
                    <HelpTip title={<>访问 <a href="https://ti.nsfocus.com/profile" target="_blank" rel="noreferrer">绿盟 NTI 个人中心</a> 获取您的 API Key。</>} />
                  </Typography.Title>
                  <Typography.Text type="secondary" style={{ display: 'block', marginBottom: 12 }}>
                    绿盟 NTI 仅需配置 API Key，无需额外模式参数。
                  </Typography.Text>
                  <Form.Item name={['nsfocus', 'api_key']} label="API Key" rules={[{ required: true }]}><Input.Password placeholder="NTI 接口密钥" /></Form.Item>
                </>
              );
            }

            if (provider === 'qianxin') {
              return (
                <>
                  <Typography.Title level={5} style={{ marginTop: 16 }}>
                    奇安信 (QiAnXin TI) 配置 
                    <HelpTip title={<>访问 <a href="https://ti.qianxin.com/url/user/account/api" target="_blank" rel="noreferrer">奇安信 TI 控制台</a> 获取您的 API Key。</>} />
                  </Typography.Title>
                  <Typography.Text type="secondary" style={{ display: 'block', marginBottom: 12 }}>
                    奇安信 TI 仅需配置 API Key，无需额外模式参数。
                  </Typography.Text>
                  <Form.Item name={['qianxin', 'api_key']} label="API Key" rules={[{ required: true }]}><Input.Password placeholder="奇安信接口密钥" /></Form.Item>
                </>
              );
            }

            if (provider === 'dbapp') {
              return (
                <>
                  <Typography.Title level={5} style={{ marginTop: 16 }}>
                    安恒 (DBAppSecurity TI) 配置 
                    <HelpTip title={<>访问 <a href="https://ti.dbappsecurity.com.cn/personal-center?tab=apikeys" target="_blank" rel="noreferrer">访问安恒威胁情报中心控制台</a> 获取您的 API Key。</>} />
                  </Typography.Title>
                  <Typography.Text type="secondary" style={{ display: 'block', marginBottom: 12 }}>
                    安恒 TI 仅需配置 API Key，无需额外模式参数。
                  </Typography.Text>
                  <Form.Item name={['dbapp', 'api_key']} label="API Key" rules={[{ required: true }]}><Input.Password placeholder="安恒接口密钥" /></Form.Item>
                </>
              );
            }

            return <Alert message="该情报源暂无需特殊参数配置" type="info" />;
          }}
        </Form.Item>
        <Divider />
        <Button type="primary" htmlType="submit" loading={isSaving}>保存{isPersonal ? '个人配置' : '全员配置'}情报</Button>
      </Form>
    </Card>
  );
}

function WebhookConfigForm({ initialValues, onSave, onTest, scope, isSaving, isTesting }: any) {
  const [form] = Form.useForm();
  const isPersonal = scope === 'personal';

  useEffect(() => {
    form.resetFields();
    form.setFieldsValue(initialValues);
  }, [initialValues, scope, form]);

  return (
    <Card size="small" title="消息通知配置">
      <Form 
        form={form}
        layout="vertical" 
        onFinish={(value) => onSave(value)}
      >
        <Form.Item name="enabled" label="启用 Webhook 通知" valuePropName="checked"><Switch /></Form.Item>
        <Form.Item name="url" label="通知地址 (URL)"><Input placeholder="例如 飞书、钉钉、企业微信的机器人地址" /></Form.Item>
        <Form.Item name="secret" label="签名密钥 (可选)"><Input.Password placeholder="安全设置中的加签密钥" /></Form.Item>
        <Space>
          <Button type="primary" htmlType="submit" loading={isSaving}>
            保存{isPersonal ? '个人' : '全员'} Webhook 配置
          </Button>
          <Button onClick={() => onTest()} loading={isTesting}>发送测试消息</Button>
        </Space>
      </Form>
    </Card>
  );
}

export default function SettingsPage() {
  const [activeScope, setActiveScope] = useState<Scope>('personal');
  const queryClient = useQueryClient();

  const { data: currentUser } = useQuery({
    queryKey: ['me'],
    queryFn: async () => (await api.get<User>('/api/auth/me')).data
  });
  const isAdmin = currentUser?.role === 'admin';

  const { data = [] } = useQuery({
    queryKey: ['settings'],
    queryFn: async () => (await api.get<Array<{ key: string; value: any; user_id: number | null }>>('/api/settings')).data
  });

  const save = useMutation({
    mutationFn: async ({ key, value, scope }: { key: string; value: any; scope: Scope }) =>
      (await api.patch(`/api/settings/${key}`, { value }, { params: { scope } })).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings'] });
      message.success('配置已保存');
    }
  });

  const webhookTest = useMutation({
    mutationFn: async () => (await api.post('/api/webhook/test', { text: '这是一条来自 EFF-Monitoring 的测试推送消息。' })).data,
    onSuccess: () => message.success('测试消息已发出，请检查对应群聊'),
    onError: (error: any) => message.error(error?.response?.data?.detail || '发送失败')
  });

  const settingValue = (list: any[], key: string, scope: Scope) => {
    const found = list.find((item) => {
      if (scope === 'global') return item.key === key && item.user_id === null;
      return item.key === key && item.user_id === currentUser?.id;
    });
    return found?.value || {};
  };

  const renderConfigForms = (scope: Scope) => {
    const isPersonal = scope === 'personal';
    return (
      <Space direction="vertical" className="full-width" size="large">
        {isPersonal && (
          <Alert
            description={
              <Space direction="vertical" size={0}>
                <div>个人配置是一个独立的模块，仅对您自己生效。开启后将完全替代全员配置。</div>
                <div style={{ color: '#fa8c16' }}><Info size={12} style={{ verticalAlign: 'middle', marginRight: 4 }} /> 提示：个人配置采用“完全覆盖”机制。如果您希望在个人环境中使用 AI 或 威胁情报，请在此完整配置相关参数。</div>
              </Space>
            }
            type="info"
            showIcon
          />
        )}
        <Tabs
          tabPosition="left"
          destroyInactiveTabPane
          items={[
            {
              key: 'ai',
              label: 'AI 配置',
              children: (
                <AiConfigForm 
                  scope={scope}
                  initialValues={settingValue(data, 'ai', scope)}
                  onSave={(value: any) => save.mutate({ key: 'ai', value, scope })}
                  isSaving={save.isPending && (save.variables as any)?.key === 'ai'}
                />
              )
            },
            {
              key: 'ti',
              label: '威胁情报',
              children: (
                <TiConfigForm 
                  scope={scope}
                  initialValues={settingValue(data, 'ti', scope)}
                  onSave={(value: any) => save.mutate({ key: 'ti', value, scope })}
                  isSaving={save.isPending && (save.variables as any)?.key === 'ti'}
                />
              )
            },
            {
              key: 'webhook',
              label: '消息通知',
              children: (
                <WebhookConfigForm
                  scope={scope}
                  initialValues={settingValue(data, 'webhook', scope)}
                  onSave={(value: any) => save.mutate({ key: 'webhook', value, scope })}
                  onTest={() => webhookTest.mutate()}
                  isSaving={save.isPending && (save.variables as any)?.key === 'webhook'}
                  isTesting={webhookTest.isPending}
                />
              )
            }
          ]}
        />
        <style>{`
          .provider-card {
            border-radius: 8px;
            padding: 12px;
            cursor: pointer;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            gap: 8px;
            transition: all 0.2s;
            height: 80px;
          }
          .provider-card:hover {
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
          }
          .provider-card.active {
            font-weight: 500;
          }
          .test-btn {
            width: 100%;
            height: 40px;
            border-radius: 6px;
          }
          .spin-icon {
            animation: spin 1s linear infinite;
          }
          @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
          }
        `}</style>
      </Space>
    );
  };

  return (
    <div className="page">
      <div className="page-toolbar">
        <div>
          <Typography.Title level={4}>系统设置</Typography.Title>
          <Typography.Text type="secondary">配置 AI 模型网关、威胁情报源、消息通知等系统全局和个人参数。</Typography.Text>
        </div>
      </div>

      <Card size="small" tabList={[{ key: 'personal', tab: <Space><UserIcon size={16} /> 个人配置</Space> }, { key: 'global', tab: <Space><Globe size={16} /> 全员配置</Space>, disabled: !isAdmin }]} activeTabKey={activeScope} onTabChange={(key) => setActiveScope(key as Scope)}>
        <div key={activeScope}>
          {renderConfigForms(activeScope)}
        </div>
      </Card>
    </div>
  );
}
