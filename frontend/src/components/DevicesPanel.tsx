import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Alert, Button, Form, Input, Modal, Popconfirm, Select, Space, Switch, Table, Tag, Upload, message } from 'antd';
import type { UploadProps } from 'antd';
import { api } from '../api/client';
import type { Device, User } from '../api/types';
import { hasRole } from '../utils/roles';

const deviceRoleLabel: Record<string, string> = {
  monitor: '监测设备',
  block: '封禁设备'
};

const deviceRoleOptions = [
  { value: 'monitor', label: '监测设备' },
  { value: 'block', label: '封禁设备' }
];

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

export default function DevicesPanel() {
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<Device | null>(null);
  const [scriptDeviceId, setScriptDeviceId] = useState<number | null>(null);
  const [scriptSource, setScriptSource] = useState('');
  const [scriptLoading, setScriptLoading] = useState(false);
  const [form] = Form.useForm();
  const watchedDeviceRole = Form.useWatch('device_role', form);
  const queryClient = useQueryClient();
  const { data: currentUser } = useQuery({ queryKey: ['me'], queryFn: async () => (await api.get<User>('/api/auth/me')).data });
  const canManageDevices = hasRole(currentUser, 'admin');
  const { data = [], isLoading } = useQuery({ queryKey: ['devices'], queryFn: async () => (await api.get<Device[]>('/api/devices')).data });
  const create = useMutation({
    mutationFn: async (payload: Record<string, unknown>) => {
      const values = {
        ...payload,
        browser_url_patterns: String(payload.browser_url_patterns_text || '')
          .split(/[\n,，]/)
          .map((item) => item.trim())
          .filter(Boolean)
      };
      delete (values as any).browser_url_patterns_text;
      if (editing) {
        return (await api.patch(`/api/devices/${editing.id}`, values)).data;
      }
      return (await api.post('/api/devices', values)).data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['devices'] });
      setOpen(false);
      setEditing(null);
      form.resetFields();
      message.success('设备已保存');
    },
    onError: (err: any) => {
      const detail = err?.response?.data?.detail;
      message.error(detail || '保存失败，请重试');
    }
  });
  const remove = useMutation({
    mutationFn: async (id: number) => (await api.delete(`/api/devices/${id}`)).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['devices'] });
      message.success('设备已删除');
    },
    onError: (err: any) => message.error(err?.response?.data?.detail || '删除失败')
  });
  const openScriptEditor = async (deviceId: number) => {
    setScriptLoading(true);
    try {
      const { data } = await api.get<{ script: string }>(`/api/devices/${deviceId}/block-script`);
      setScriptSource(data.script || '');
      setScriptDeviceId(deviceId);
    } catch (err: any) {
      message.error(err?.response?.data?.detail || '读取脚本失败');
    } finally {
      setScriptLoading(false);
    }
  };
  const saveScript = useMutation({
    mutationFn: async () => (await api.put(`/api/devices/${scriptDeviceId}/block-script`, { script: scriptSource })).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['devices'] });
      setScriptDeviceId(null);
      message.success('联动封堵脚本已保存');
    },
    onError: (err: any) => message.error(err?.response?.data?.detail || '保存脚本失败')
  });
  const exportPackage = async (row: Device) => {
    const response = await api.get(`/api/devices/${row.id}/package`, { responseType: 'blob' });
    downloadBlob(response.data, `${row.name}-规则模板导入包.json`);
  };
  const importPackage = useMutation({
    mutationFn: async ({ id, file }: { id: number; file: File }) => {
      const formData = new FormData();
      formData.append('file', file);
      return (await api.post(`/api/devices/${id}/package`, formData)).data;
    },
    onSuccess: (data) => {
      message.success(`导入完成：规则新增 ${data.rules.created} / 更新 ${data.rules.updated}，模板新增 ${data.templates.created} / 更新 ${data.templates.updated}`);
      queryClient.invalidateQueries({ queryKey: ['rules'] });
      queryClient.invalidateQueries({ queryKey: ['templates'] });
    },
    onError: (err: any) => {
      const detail = err?.response?.data?.detail;
      message.error(detail || '导入失败，请检查导入包');
    }
  });
  const uploadProps = (row: Device): UploadProps => ({
    accept: '.json,application/json',
    showUploadList: false,
    beforeUpload: (file) => {
      importPackage.mutate({ id: row.id, file });
      return false;
    }
  });

  return (
    <>
      {canManageDevices && (
        <div className="panel-toolbar">
          <Button type="primary" onClick={() => { setEditing(null); form.resetFields(); setOpen(true); }}>新增设备</Button>
        </div>
      )}
      <Table rowKey="id" loading={isLoading} dataSource={data} pagination={{ pageSizeOptions: ['10', '20', '50', '100'], showSizeChanger: true }} columns={[
        { title: '设备名称', dataIndex: 'name', width: 220 },
        { title: '设备类型', dataIndex: 'device_role', width: 120, render: (v: string) => deviceRoleLabel[v] || v },
        { title: '厂商', dataIndex: 'vendor', width: 160 },
        { title: '产品', dataIndex: 'product', width: 180 },
        { title: '设备 IP', dataIndex: 'version', width: 140 },
        { title: '浏览器助手', dataIndex: 'browser_assistant_enabled', width: 120, render: (v: boolean) => v ? <Tag color="green">启用</Tag> : <Tag>停用</Tag> },
        { title: '联动脚本', width: 105, render: (_: unknown, row: Device) => row.device_role === 'block' && row.has_block_script ? <Tag color="blue">已配置</Tag> : <Tag>未配置</Tag> },
        {
          title: '操作',
          width: canManageDevices ? 300 : 90,
          render: (_: unknown, row: Device) => (
            <Space>
              {canManageDevices && <Button size="small" onClick={() => { setEditing(row); form.setFieldsValue({ ...row, browser_url_patterns_text: (row.browser_url_patterns || []).join('\n') }); setOpen(true); }}>编辑</Button>}
              <Button size="small" onClick={() => exportPackage(row)}>导出包</Button>
              {canManageDevices && (
                <Upload {...uploadProps(row)}>
                  <Button size="small" loading={importPackage.isPending}>导入包</Button>
                </Upload>
              )}
              {canManageDevices && (
                <Popconfirm title="删除该设备？" onConfirm={() => remove.mutate(row.id)}>
                  <Button size="small" danger>删除</Button>
                </Popconfirm>
              )}
            </Space>
          )
        }
      ]} />
      <Modal title={editing ? '编辑设备' : '新增设备'} open={open} onCancel={() => { setOpen(false); setEditing(null); }} onOk={() => form.submit()}>
        <Form form={form} layout="vertical" initialValues={{ device_role: 'monitor', browser_assistant_enabled: true, browser_url_patterns_text: 'http://*/*\nhttps://*/*' }} onFinish={(values) => create.mutate(values)}>
          <Form.Item name="name" label="设备名称" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="device_role" label="设备类型" rules={[{ required: true }]}><Select options={deviceRoleOptions} /></Form.Item>
          {watchedDeviceRole === 'block' && (
            <Form.Item label="一键联动封堵脚本">
              <Space direction="vertical" size="small">
                <Button loading={scriptLoading} disabled={!editing || editing.device_role !== 'block'} onClick={() => editing && void openScriptEditor(editing.id)}>
                  {editing?.has_block_script ? '编辑联动封堵脚本' : '创建联动封堵脚本'}
                </Button>
                <span style={{ color: '#888' }}>{editing?.device_role === 'block' ? '脚本单独保存，仅管理员可编辑；不会因选择设备而自动执行。' : '请先保存为封禁设备，再创建脚本。'}</span>
              </Space>
            </Form.Item>
          )}
          <Form.Item name="vendor" label="厂商"><Input /></Form.Item>
          <Form.Item name="product" label="产品"><Input /></Form.Item>
          <Form.Item name="version" label="设备 IP"><Input placeholder="例如：10.4.6.8" /></Form.Item>
          <Form.Item name="browser_assistant_enabled" label="启用浏览器助手" valuePropName="checked"><Switch /></Form.Item>
          <Form.Item name="browser_url_patterns_text" label="浏览器 URL 匹配规则">
            <Input.TextArea rows={4} placeholder="例如：https://waf.example.com/*" />
          </Form.Item>
        </Form>
      </Modal>
      <Modal title="联动封堵脚本（Python）" open={scriptDeviceId !== null} width={840}
        onCancel={() => setScriptDeviceId(null)} onOk={() => saveScript.mutate()}
        okText="保存脚本" confirmLoading={saveScript.isPending} destroyOnClose>
        <Space direction="vertical" size="middle" className="full-width">
          <Alert type="warning" showIcon message="仅允许可信管理员编写脚本"
            description="脚本会在独立的低权限容器内执行，并可能访问目标设备网络。不要把设备密钥写进源码；使用 BLOCK_DEVICE_TOKEN 环境变量。保存不执行，实际联动需在告警处置时显式勾选。" />
          <div>标准输入是一行 JSON：<code>{'{"ip":"203.0.113.5","alert_id":123,"device_id":4}'}</code>。脚本须从标准输出返回 JSON：<code>{'{"ok":true,"message":"封堵成功"}'}</code>；失败返回 <code>{'{"ok":false,"message":"原因"}'}</code>。</div>
          <Input.TextArea rows={16} value={scriptSource} onChange={(event) => setScriptSource(event.target.value)}
            style={{ fontFamily: 'monospace', fontSize: 13 }} placeholder={'import json, sys\nrequest = json.load(sys.stdin)\nip = request["ip"]\n# 在这里调用设备 API（仅示例；先在测试设备验证）\nprint(json.dumps({"ok": False, "message": "尚未实现设备调用"}))'} />
        </Space>
      </Modal>
    </>
  );
}
