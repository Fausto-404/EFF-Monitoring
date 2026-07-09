import { useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { Alert, Button, Card, Input, Space, Tabs, Typography, message } from 'antd';
import { api } from '../api/client';
import type { User } from '../api/types';
import HelpTip from '../components/HelpTip';
import { Brain, Sparkles, Wand2 } from 'lucide-react';

export default function RuleGenerator({ isSubModule }: { isSubModule?: boolean }) {
  const [sampleLog, setSampleLog] = useState('');
  const [fieldContext, setFieldContext] = useState('');
  const [expectedOutput, setExpectedOutput] = useState('');
  const [generatedRegex, setGeneratedRegex] = useState('');
  const [testRegex, setTestRegex] = useState('');
  const [testMatches, setTestMatches] = useState<string[]>([]);

  const { data: currentUser } = useQuery({
    queryKey: ['me'],
    queryFn: async () => (await api.get<User>('/api/auth/me')).data
  });
  const isAdmin = currentUser?.role === 'admin';

  const generateAI = useMutation({
    mutationFn: async () => (await api.post('/api/rules/generate', { 
      sample_log: sampleLog, 
      field_name: fieldContext, 
      expected_output: expectedOutput,
      mode: 'ai'
    })).data,
    onSuccess: (data) => {
      setGeneratedRegex(data.regex || '');
      message.success('AI 生成正则成功');
    },
    onError: (error: any) => message.error(error?.response?.data?.detail || 'AI 生成正则失败')
  });

  const generateMatch = useMutation({
    mutationFn: async () => (await api.post('/api/rules/generate', { 
      sample_log: sampleLog, 
      field_name: fieldContext, 
      expected_output: expectedOutput,
      mode: 'match'
    })).data,
    onSuccess: (data) => {
      setGeneratedRegex(data.regex || '');
      if (data.regex) {
        message.success('规则匹配生成完成');
      } else {
        message.warning('未识别出有效的前缀/后缀，请尝试调整上下文或改用 AI 解析');
      }
    },
    onError: (error: any) => message.error(error?.response?.data?.detail || '规则匹配生成失败')
  });

  const regexTest = useMutation({
    mutationFn: async () => (await api.post('/api/rules/regex-test', { sample_log: sampleLog, regex: testRegex })).data,
    onSuccess: (data) => setTestMatches(data.matches || []),
    onError: (error: any) => message.error(error?.response?.data?.detail || '正则测试失败')
  });

  const CommonInputs = (
    <div className="regex-lab">
      <Input.TextArea value={sampleLog} onChange={(e) => setSampleLog(e.target.value)} rows={6} placeholder="粘贴原始日志..." />
      <Space direction="vertical" className="full-width">
        <Input.TextArea
          value={fieldContext}
          onChange={(e) => setFieldContext(e.target.value)}
          rows={3}
          placeholder={'填写目标字段附近的上下文，例如：\n响应内容: \n\n预期输出: 403'}
        />
        <Input value={expectedOutput} onChange={(e) => setExpectedOutput(e.target.value)} placeholder="预期提取的精确值" />
      </Space>
    </div>
  );

  const content = (
    <>
      {!isSubModule && (
        <div className="page-toolbar">
          <div>
            <Typography.Title level={4}>规则生成器</Typography.Title>
            <Typography.Text type="secondary">利用规则匹配或 AI 辅助生成高精度正则表达式</Typography.Text>
          </div>
        </div>
      )}

      <Card title="生成正则" className="plain-panel" style={isSubModule ? { marginTop: 0 } : {}}>
        <Tabs
          defaultActiveKey="match"
          items={[
            {
              key: 'match',
              label: <Space><Wand2 size={16} />规则匹配生成</Space>,
              children: (
                <Space direction="vertical" className="full-width">
                  <Typography.Text type="secondary">粘贴日志正文并提供上下文，系统将从模式库中检索并推导出最匹配的提取规则。</Typography.Text>
                  {CommonInputs}
                  <Button type="primary" icon={<Wand2 size={16} />} loading={generateMatch.isPending} onClick={() => generateMatch.mutate()}>规则匹配生成</Button>
                  {generatedRegex && (
                    <Alert
                      type="success"
                      message="匹配生成成功"
                      description={
                        <div>
                          <Typography.Text code copyable>{generatedRegex}</Typography.Text>
                          <Button type="link" onClick={() => setTestRegex(generatedRegex)}>应用到测试</Button>
                        </div>
                      }
                    />
                  )}
                </Space>
              )
            },
            {
              key: 'ai',
              label: <Space><Sparkles size={16} />AI 解析生成</Space>,
              children: (
                <Space direction="vertical" className="full-width">
                  <Typography.Text type="secondary">当规则匹配不够精准时，请利用 AI 为您编写高精度正则。</Typography.Text>
                  {CommonInputs}
                  <Button type="primary" block icon={<Brain size={16} />} loading={generateAI.isPending} disabled={!sampleLog || !fieldContext || !expectedOutput} onClick={() => generateAI.mutate()}>通过 AI 生成正则</Button>
                  {generatedRegex && (
                    <Alert
                      type="success"
                      message="AI 生成成功"
                      description={
                        <div>
                          <Typography.Text code copyable>{generatedRegex}</Typography.Text>
                          <Button type="link" onClick={() => setTestRegex(generatedRegex)}>应用到测试</Button>
                        </div>
                      }
                    />
                  )}
                </Space>
              )
            }
          ]}
        />
      </Card>

      <section className="plain-panel" style={{ marginTop: 24 }}>
        <Typography.Title level={5}>正则有效性测试 <HelpTip title="建议保存规则前先在此处测试，确认正则能正确提取你需要的字段。" /></Typography.Title>
        <div className="regex-lab">
          <Input.TextArea value={sampleLog} onChange={(e) => setSampleLog(e.target.value)} rows={6} placeholder="原始日志" />
          <Space direction="vertical" className="full-width">
            <Input.TextArea value={testRegex} onChange={(e) => setTestRegex(e.target.value)} rows={2} placeholder="在此输入正则表达式..." />
            <Button loading={regexTest.isPending} disabled={!sampleLog || !testRegex} onClick={() => regexTest.mutate()}>验证正则匹配</Button>
            <pre className="result-box small" style={{ maxHeight: 240, overflowY: 'auto' }}>{JSON.stringify(testMatches, null, 2)}</pre>
          </Space>
        </div>
      </section>
    </>
  );

  if (!isAdmin) {
    return (
      <div className="page">
        <Alert message="权限不足" description="只有管理员可以使用规则生成器。" type="error" showIcon />
      </div>
    );
  }

  return isSubModule ? content : <div className="page">{content}</div>;
}
