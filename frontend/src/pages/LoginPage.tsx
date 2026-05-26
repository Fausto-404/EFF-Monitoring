import { Button, Card, Form, Input, Typography, message } from 'antd';
import { api } from '../api/client';

interface Props {
  onLogin: (token: string) => void;
}

export default function LoginPage({ onLogin }: Props) {
  return (
    <div className="login-page">
      <Card className="login-card">
        <div style={{ textAlign: 'center', marginBottom: 24 }}>
          <img src="/logo-full.svg" alt="logo" style={{ height: '50px', marginBottom: 4, objectFit: 'contain' }} />
          <Typography.Paragraph type="secondary" style={{ fontSize: '15px', letterSpacing: '2px', fontWeight: 500, opacity: 0.9, marginBottom: 0 }}>
            安全运营协作平台
          </Typography.Paragraph>
        </div>
        <Form
          layout="vertical"
          initialValues={{ username: 'admin', password: 'admin123' }}
          onFinish={async (values) => {
            try {
              const response = await api.post('/api/auth/login', values);
              const token = response.data.access_token;
              localStorage.setItem('eff_token', token);
              onLogin(token);
            } catch {
              message.error('登录失败，请检查用户名和密码');
            }
          }}
        >
          <Form.Item name="username" label="用户名" rules={[{ required: true }]}>
            <Input autoComplete="username" />
          </Form.Item>
          <Form.Item name="password" label="密码" rules={[{ required: true }]}>
            <Input.Password autoComplete="current-password" />
          </Form.Item>
          <Button type="primary" htmlType="submit" block>
            登录
          </Button>
        </Form>
        <div style={{ textAlign: 'center', marginTop: 24, opacity: 0.5, fontSize: '12px' }}>
          <Typography.Text>
            Powered by <a href="https://github.com/Fausto-404/EFF-Monitoring" target="_blank" rel="noreferrer" style={{ color: 'inherit' }}>Fausto</a>
          </Typography.Text>
        </div>
      </Card>
    </div>
  );
}
