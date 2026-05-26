import { useMemo, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Alert, Button, Card, Col, Form, Input, Row, Select, Space, Switch, Tabs, Typography, message } from 'antd';
import { api } from '../api/client';
import type { User } from '../api/types';
import HelpTip from '../components/HelpTip';
import { Globe, User as UserIcon } from 'lucide-react';

type Scope = 'global' | 'personal';

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
            message="帐号配置"
            description="账号配置仅对您自己生效。开启后将覆盖全员配置中的同名参数（如接口密钥）。"
            type="info"
            showIcon
          />
        )}
        <Tabs
          tabPosition="left"
          items={[
            {
              key: 'ai',
              label: 'AI 网关',
              children: (
                <Card size="small">
                  <Form key={`${scope}-ai-${JSON.stringify(settingValue(data, 'ai', scope))}`} layout="vertical" initialValues={settingValue(data, 'ai', scope)} onFinish={(value) => save.mutate({ key: 'ai', value, scope })}>
                    <Form.Item name="provider" label={<>模型服务商 <HelpTip title="选择底层对接的 AI 能力提供方。" /></>} rules={[{ required: true }]}><Select options={[
                      { value: 'openai-compatible', label: 'OpenAI 协议适配' },
                      { value: 'openai', label: 'OpenAI (官方)' },
                      { value: 'deepseek', label: 'DeepSeek (深度求索)' },
                      { value: 'qwen', label: '通义千问 (阿里)' },
                      { value: 'zhipu', label: '智谱 AI' },
                      { value: 'siliconflow', label: 'SiliconFlow (硅基流动)' },
                      { value: 'ollama', label: 'Ollama (本地私有化)' }
                    ]} /></Form.Item>
                    <Form.Item name="base_url" label={<>接口地址 (Base URL) <HelpTip title="API 的访问端点，通常以 /v1 结尾。" /></>} rules={[{ required: true }]}><Input placeholder="例如 http://host.docker.internal:11434/v1" /></Form.Item>
                    <Form.Item name="model" label={<>模型名称 (Model) <HelpTip title="具体使用的模型 ID，如 gpt-4o, qwen2.5:7b。" /></>} rules={[{ required: true }]}><Input placeholder="例如 qwen2.5:7b" /></Form.Item>
                    <Form.Item noStyle shouldUpdate={(prev, next) => prev.provider !== next.provider}>
                      {({ getFieldValue }) => {
                        const provider = getFieldValue('provider');
                        const isOllama = provider === 'ollama';
                        return (
                          <Form.Item
                            name="api_key"
                            label={<>接口密钥 (API Key) <HelpTip title={isOllama ? 'Ollama 本地私有化通常不需要 API Key，可留空。' : '用于鉴权的凭据。'} /></>}
                            rules={isOllama ? [] : [{ required: true, message: '请输入接口密钥' }]}
                          >
                            <Input.Password placeholder={isOllama ? 'Ollama 可留空' : '请输入接口密钥'} />
                          </Form.Item>
                        );
                      }}
                    </Form.Item>
                    <Form.Item name="temperature" label={<>采样温度 (Temperature) <HelpTip title="数值越高回答越随机，安全分析建议保持在 0.3 左右。" /></>}><Input type="number" min={0} max={2} step={0.1} /></Form.Item>
                    <Button type="primary" htmlType="submit" loading={save.isPending}>保存 {isPersonal ? '个人' : '全员'} AI 配置</Button>
                  </Form>
                </Card>
              )
            },
            {
              key: 'ti',
              label: '威胁情报',
              children: (
                <Card size="small">
                  <Form key={`${scope}-ti-${JSON.stringify(settingValue(data, 'ti', scope))}`} layout="vertical" initialValues={settingValue(data, 'ti', scope)} onFinish={(value) => save.mutate({ key: 'ti', value, scope })}>
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
                              <Form.Item name={['nsfocus', 'api_key']} label="API Key" rules={[{ required: true }]}><Input.Password placeholder="NTI 接口密钥" /></Form.Item>
                            </>
                          );
                        }

                        if (provider === 'qianxin') {
                          return (
                            <>
                              <Typography.Title level={5} style={{ marginTop: 16 }}>
                                奇安信 (QiAnXin TI) 配置 
                                <HelpTip title={<>访问 <a href="https://ti.qianxin.com/service/my-api" target="_blank" rel="noreferrer">奇安信 TI 控制台</a> 获取您的 API Key。</>} />
                              </Typography.Title>
                              <Form.Item name={['qianxin', 'api_key']} label="API Key"><Input.Password placeholder="奇安信接口密钥" /></Form.Item>
                            </>
                          );
                        }

                        if (provider === 'dbapp') {
                          return (
                            <>
                              <Typography.Title level={5} style={{ marginTop: 16 }}>
                                安恒 (DBAppSecurity TI) 配置 
                                <HelpTip title={<>访问安恒威胁情报中心获取您的 API Key。</>} />
                              </Typography.Title>
                              <Form.Item name={['dbapp', 'api_key']} label="API Key"><Input.Password placeholder="安恒接口密钥" /></Form.Item>
                            </>
                          );
                        }
                        
                        return null;
                      }}
                    </Form.Item>

                    <Button type="primary" htmlType="submit" loading={save.isPending} style={{ marginTop: 24 }}>保存 {isPersonal ? '个人' : '全员'} 威胁情报配置</Button>
                  </Form>
                </Card>
              )
            },
            {
              key: 'webhook',
              label: '消息推送',
              children: (
                <Card size="small">
                  <Form 
                    key={`${scope}-webhook-${JSON.stringify(settingValue(data, 'webhook', scope))}`} 
                    layout="vertical" 
                    initialValues={settingValue(data, 'webhook', scope)} 
                    onFinish={(value) => save.mutate({ key: 'webhook', value, scope })}
                    preserve={true}
                  >
                    <Form.Item name="enabled" label="总开关" valuePropName="checked"><Switch /></Form.Item>
                    <Typography.Title level={5}>钉钉 <HelpTip title="配置钉钉群机器人的 Webhook 信息。" /></Typography.Title>
                    <Space wrap className="full-width form-row">
                      <Form.Item name={['dingtalk', 'enabled']} label="启用" valuePropName="checked"><Switch /></Form.Item>
                      <Form.Item name={['dingtalk', 'url']} label="机器人地址"><Input placeholder="Webhook 地址" /></Form.Item>
                      <Form.Item name={['dingtalk', 'secret']} label={<>签名密钥 <HelpTip title="钉钉安全设置中的加签密钥。" /></>}><Input.Password /></Form.Item>
                    </Space>
                    <Typography.Title level={5}>企业微信 <HelpTip title="配置企业微信群机器人的 Webhook 信息。" /></Typography.Title>
                    <Space wrap className="full-width form-row">
                      <Form.Item name={['wecom', 'enabled']} label="启用" valuePropName="checked"><Switch /></Form.Item>
                      <Form.Item name={['wecom', 'url']} label="机器人地址"><Input placeholder="Webhook 地址" /></Form.Item>
                    </Space>
                    <Typography.Title level={5}>飞书 <HelpTip title="配置飞书群机器人的 Webhook 信息。" /></Typography.Title>
                    <Space wrap className="full-width form-row">
                      <Form.Item name={['feishu', 'enabled']} label="启用" valuePropName="checked"><Switch /></Form.Item>
                      <Form.Item name={['feishu', 'url']} label="机器人地址"><Input placeholder="Webhook 地址" /></Form.Item>
                      <Form.Item name={['feishu', 'secret']} label={<>签名密钥 <HelpTip title="飞书安全设置中的签名校验密钥。" /></>}><Input.Password /></Form.Item>
                    </Space>
                    <Space>
                      <Button type="primary" htmlType="submit" loading={save.isPending}>保存 {isPersonal ? '个人' : '全员'} 推送配置</Button>
                      <Button loading={webhookTest.isPending} onClick={() => webhookTest.mutate()}>发送测试消息</Button>
                    </Space>
                  </Form>
                </Card>
              )
            }
          ]}
        />
      </Space>
    );
  };

  const scopeItems = [
    isAdmin && {
      key: 'global',
      label: <Space><Globe size={16} />全员配置</Space>,
      children: renderConfigForms('global')
    },
    {
      key: 'personal',
      label: <Space><UserIcon size={16} />帐号配置</Space>,
      children: renderConfigForms('personal')
    }
  ].filter(Boolean) as any[];

  return (
    <div className="page">
      <div className="page-toolbar">
        <div>
          <Typography.Title level={4}>能力配置</Typography.Title>
          <Typography.Text type="secondary">管理 AI、威胁情报和消息推送的生效范围</Typography.Text>
        </div>
      </div>
      
      <Tabs
        activeKey={activeScope}
        onChange={(k) => setActiveScope(k as any)}
        items={scopeItems}
      />
    </div>
  );
}
