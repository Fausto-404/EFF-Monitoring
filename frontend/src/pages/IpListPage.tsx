import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Alert, Button, Col, Input, Row, Space, Tag, Typography, message } from 'antd';
import { api } from '../api/client';
import HelpTip from '../components/HelpTip';

interface Lists {
  whitelist: string[];
  blacklist: string[];
  updated_at?: string;
}

export default function IpListPage() {
  const [whiteText, setWhiteText] = useState('');
  const [blackText, setBlackText] = useState('');
  const [searchIp, setSearchIp] = useState('');
  const [searchResult, setSearchResult] = useState<{ ip: string; matched: boolean; matches: Array<{ label: string; range: string; list: string }> } | null>(null);
  const queryClient = useQueryClient();

  const { data: currentUser } = useQuery({
    queryKey: ['me'],
    queryFn: async () => (await api.get<any>('/api/auth/me')).data
  });
  const isViewer = currentUser?.role === 'viewer';

  const { data } = useQuery({
    queryKey: ['ip-lists'],
    queryFn: async () => (await api.get<Lists>('/api/ip-lists')).data
  });

  const whiteCount = useMemo(() => whiteText.split(/\r?\n/).filter((v) => v.trim()).length, [whiteText]);
  const blackCount = useMemo(() => blackText.split(/\r?\n/).filter((v) => v.trim()).length, [blackText]);

  const save = useMutation({
    mutationFn: async () => (
      await api.put('/api/ip-lists', {
        whitelist: whiteText.split(/\r?\n/),
        blacklist: blackText.split(/\r?\n/),
        updated_at: data?.updated_at
      })
    ).data,
    onSuccess: (updatedData) => {
      queryClient.setQueryData(['ip-lists'], updatedData);
      setWhiteText((updatedData.whitelist || []).join('\n'));
      setBlackText((updatedData.blacklist || []).join('\n'));
      message.success('IP 名单已保存并已自动去重');
    },
    onError: (err: any) => {
      if (err.response?.status === 409) {
        message.error(err.response.data.detail || '保存失败：名单已被他人修改，请刷新页面');
      } else {
        message.error('保存失败');
      }
    }
  });

  const check = useMutation({
    mutationFn: async () => (await api.post('/api/ip-lists/check', { ip: searchIp })).data,
    onSuccess: (data) => setSearchResult(data),
    onError: (error: any) => message.error(error?.response?.data?.detail || '检测失败')
  });

  const exportTxt = async (type: 'whitelist' | 'blacklist') => {
    const response = await api.get('/api/ip-lists/export.txt', {
      params: { type },
      responseType: 'blob'
    });
    const blob = new Blob([response.data], { type: 'text/plain;charset=utf-8' });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = type === 'whitelist' ? 'whitelist.txt' : 'blacklist.txt';
    link.click();
    window.URL.revokeObjectURL(url);
  };

  useEffect(() => {
    if (data) {
      setWhiteText((data.whitelist || []).join('\n'));
      setBlackText((data.blacklist || []).join('\n'));
    }
  }, [data]);

  return (
    <div className="page">
      <div className="page-toolbar">
        <div>
          <Typography.Title level={4}>IP 名单</Typography.Title>
          <Typography.Text type="secondary">支持单 IP、CIDR 和范围格式；可在后续研判流程中自动复用</Typography.Text>
        </div>
        <Space wrap>
          <Button onClick={() => exportTxt('whitelist')}>导出白名单</Button>
          <Button onClick={() => exportTxt('blacklist')}>导出黑名单</Button>
          <Button type="primary" loading={save.isPending} onClick={() => save.mutate()} disabled={isViewer}>保存名单</Button>
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
              description={
                <Space wrap>
                  {searchResult.matches.map((item) => (
                    <Tag color={item.list === 'blacklist' ? 'red' : 'blue'} key={`${item.list}-${item.range}`}>{item.label}: {item.range}</Tag>
                  ))}
                </Space>
              }
            />
          )}
        </Space>
      </section>
      <Row gutter={[16, 16]}>
        <Col xs={24} xl={12}>
          <Typography.Title level={5}>
            白名单 ({whiteCount}) <HelpTip title="命中白名单时，内容解析会弹出提醒，避免误封或重复处置可信 IP。" />
          </Typography.Title>
          <Input.TextArea rows={24} value={whiteText} onChange={(e) => setWhiteText(e.target.value)} placeholder="192.168.1.1&#10;10.0.0.0/24" />
        </Col>
        <Col xs={24} xl={12}>
          <Typography.Title level={5}>
            黑名单 ({blackCount}) <HelpTip title="命中黑名单时，内容解析会弹出高风险提醒，帮助值守人员快速识别重复封禁或已知恶意 IP。" />
          </Typography.Title>
          <Input.TextArea rows={24} value={blackText} onChange={(e) => setBlackText(e.target.value)} placeholder="8.8.8.8&#10;1.1.1.1-100" />
        </Col>
      </Row>
    </div>
  );
}
