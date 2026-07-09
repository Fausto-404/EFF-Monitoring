import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Badge, Button, Layout, Menu, Space, Tooltip, Typography, Popover, List, Divider, Empty } from 'antd';
import { Bell, Brain, Database, FileText, Files, LayoutDashboard, ListChecks, LogOut, ScrollText, Settings, ShieldCheck, Table2, Users } from 'lucide-react';
import { api } from './api/client';
import type { User } from './api/types';
import LoginPage from './pages/LoginPage';
import AlertWorkbench from './pages/AlertWorkbench';
import LogParser from './pages/LogParser';
import RuleCenter from './pages/RuleCenter';
import TemplateCenter from './pages/TemplateCenter';
import SettingsPage from './pages/SettingsPage';
import TeamPage from './pages/TeamPage';
import DashboardPage from './pages/DashboardPage';
import IpListPage from './pages/IpListPage';
import AssetCenter from './pages/AssetCenter';
import MessageCenter from './pages/MessageCenter';
import AiCenter from './pages/AiCenter';
import ReportCenter from './pages/ReportCenter';

const { Header, Sider, Content } = Layout;

type PageKey = 'dashboard' | 'alerts' | 'parser' | 'ai' | 'assets' | 'messages' | 'reports' | 'team' | 'rules' | 'templates' | 'ipLists' | 'settings';

const pageNames: Record<PageKey, string> = {
  dashboard: '运营总览',
  alerts: '告警工作台',
  parser: '内容解析',
  ai: 'AI 中心',
  assets: '资产中心',
  messages: '消息中心',
  reports: '报告中心',
  team: '系统管理',
  rules: '规则中心',
  templates: '模板中心',
  ipLists: 'IP 名单',
  settings: '能力配置'
};

const roleLabels: Record<string, string> = {
  admin: '管理员',
  monitor: '监测组',
  analyst: '研判组',
  disposer: '处置组',
  viewer: '只读人员'
};

function initialPage(): PageKey {
  const params = new URLSearchParams(window.location.search);
  const page = params.get('page') as PageKey | null;
  return page && page in pageNames ? page : 'dashboard';
}

export default function App() {
  const [token, setToken] = useState(localStorage.getItem('eff_token') || '');
  const [page, setPage] = useState<PageKey>(initialPage());
  const [alertHash, setAlertHash] = useState(new URLSearchParams(window.location.search).get('alert_hash') || '');

  const { data: currentUser } = useQuery({
    queryKey: ['me'],
    queryFn: async () => (await api.get<User>('/api/auth/me')).data,
    enabled: !!token
  });

  const isAdmin = currentUser?.role === 'admin';
  const { data: unread } = useQuery({
    queryKey: ['messages-unread'],
    queryFn: async () => (await api.get<{ count: number }>('/api/messages/unread-count')).data,
    enabled: !!token
  });

  const { data: recentMessages = [] } = useQuery({
    queryKey: ['messages-recent', currentUser?.id],
    queryFn: async () => (await api.get<any[]>('/api/messages', { params: { limit: 5, unread_only: true, recipient_id: currentUser?.id } })).data,
    enabled: !!token && !!currentUser?.id
  });

  const notificationContent = (
    <div style={{ width: 300 }}>
      <Typography.Title level={5} style={{ margin: '0 0 12px 0', fontSize: '14px' }}>
        最近未读消息
      </Typography.Title>
      <List
        size="small"
        dataSource={recentMessages}
        locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无未读消息" /> }}
        renderItem={(item: any) => (
          <List.Item
            style={{ cursor: 'pointer', padding: '8px 4px' }}
            onClick={() => navigate('messages')}
          >
            <List.Item.Meta
              title={<span style={{ fontSize: '13px' }}>{item.title}</span>}
              description={<div style={{ fontSize: '12px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{item.content}</div>}
            />
          </List.Item>
        )}
      />
      <Divider style={{ margin: '8px 0' }} />
      <div style={{ textAlign: 'center' }}>
        <Button type="link" size="small" onClick={() => navigate('messages')}>
          查看全部消息
        </Button>
      </div>
    </div>
  );

  const navigate = (nextPage: PageKey, nextAlertHash = '') => {
    setPage(nextPage);
    setAlertHash(nextAlertHash);
    const params = new URLSearchParams();
    params.set('page', nextPage);
    if (nextAlertHash) params.set('alert_hash', nextAlertHash);
    window.history.replaceState(null, '', `?${params.toString()}`);
  };

  const clearAlertHash = () => {
    setAlertHash('');
    const params = new URLSearchParams(window.location.search);
    params.delete('alert_hash');
    window.history.replaceState(null, '', `?${params.toString()}`);
  };

  const pageView: Record<PageKey, JSX.Element> = {
    dashboard: <DashboardPage />,
    alerts: <AlertWorkbench initialAlertHash={alertHash} onClearInitialAlertHash={clearAlertHash} />,
    parser: <LogParser />,
    ai: <AiCenter />,
    assets: <AssetCenter />,
    messages: <MessageCenter onOpenAlert={(hash) => navigate('alerts', hash)} />,
    reports: <ReportCenter />,
    team: <TeamPage />,
    rules: <RuleCenter />,
    templates: <TemplateCenter />,
    ipLists: <IpListPage />,
    settings: <SettingsPage />
  };

  if (!token) {
    return <LoginPage onLogin={(nextToken) => setToken(nextToken)} />;
  }

  const logout = () => {
    localStorage.removeItem('eff_token');
    setToken('');
    window.location.reload();
  };

  return (
    <Layout className="app-shell">
      <Sider width={216} className="app-sider">
        <div className="brand" style={{ height: '120px', borderBottom: '1px solid #f0f0f0', padding: '0 24px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <img src="/logo-full.svg" alt="安全运营协作平台" style={{ height: '80px', maxWidth: '100%', objectFit: 'contain' }} />
        </div>
        <Menu
          theme="light"
          mode="inline"
          selectedKeys={[page]}
          onClick={(item) => navigate(item.key as PageKey)}
          items={[
            { key: 'dashboard', icon: <LayoutDashboard size={17} />, label: '运营总览' },
            { key: 'parser', icon: <ScrollText size={17} />, label: '内容解析' },
            { key: 'alerts', icon: <Table2 size={17} />, label: '告警工作台' },
            { key: 'ai', icon: <Brain size={17} />, label: 'AI 中心' },
            { key: 'assets', icon: <Database size={17} />, label: '资产中心' },
            { key: 'messages', icon: <Badge count={unread?.count || 0} size="small" offset={[5, 0]}><Bell size={17} /></Badge>, label: '消息中心' },
            { key: 'reports', icon: <Files size={17} />, label: '报告中心' },
            { type: 'divider' },
            { key: 'rules', icon: <ShieldCheck size={17} />, label: '规则中心' },
            { key: 'templates', icon: <FileText size={17} />, label: '模板中心' },
            { key: 'ipLists', icon: <ListChecks size={17} />, label: 'IP 名单' },
            { type: 'divider' },
            { key: 'settings', icon: <Settings size={17} />, label: '能力配置' },
            isAdmin && { key: 'team', icon: <Users size={17} />, label: '系统管理' },
          ].filter(Boolean) as any}
        />
      </Sider>
      <Layout>
        <Header className="app-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 24px', background: '#fff', borderBottom: '1px solid #f0f0f0' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Typography.Text type="secondary">首页 /</Typography.Text>
            <Typography.Title level={5} style={{ margin: 0 }}>
              {pageNames[page]}
            </Typography.Title>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            {currentUser && (
              <Space size={4}>
                <Typography.Text strong>{currentUser.display_name || currentUser.username}</Typography.Text>
                <Typography.Text type="secondary" style={{ fontSize: '12px' }}>({roleLabels[currentUser.role] || currentUser.role})</Typography.Text>
              </Space>
            )}
            <Popover content={notificationContent} trigger="click" placement="bottomRight">
              <Badge count={unread?.count || 0} size="small">
                <Button icon={<Bell size={18} />} type="text" />
              </Badge>
            </Popover>
            <Tooltip title="退出登录">
              <Button icon={<LogOut size={18} />} type="text" onClick={logout} />
            </Tooltip>
          </div>
        </Header>
        <Content className="app-content">
          <div className="content-container">
            {pageView[page]}
          </div>
        </Content>
      </Layout>
    </Layout>
  );
}
