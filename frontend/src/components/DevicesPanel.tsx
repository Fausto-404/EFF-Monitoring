import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Button, Form, Input, Modal, Popconfirm, Select, Space, Table, Upload, message } from 'antd';
import type { UploadProps } from 'antd';
import { api } from '../api/client';
import type { Device, User } from '../api/types';

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
  const [form] = Form.useForm();
  const queryClient = useQueryClient();
  const { data: currentUser } = useQuery({ queryKey: ['me'], queryFn: async () => (await api.get<User>('/api/auth/me')).data });
  const canManageDevices = currentUser?.role === 'admin';
  const { data = [], isLoading } = useQuery({ queryKey: ['devices'], queryFn: async () => (await api.get<Device[]>('/api/devices')).data });
  const create = useMutation({
    mutationFn: async (payload: Record<string, unknown>) => {
      if (editing) {
        return (await api.patch(`/api/devices/${editing.id}`, payload)).data;
      }
      return (await api.post('/api/devices', payload)).data;
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
        {
          title: '操作',
          width: canManageDevices ? 300 : 90,
          render: (_: unknown, row: Device) => (
            <Space>
              {canManageDevices && <Button size="small" onClick={() => { setEditing(row); form.setFieldsValue(row); setOpen(true); }}>编辑</Button>}
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
        <Form form={form} layout="vertical" initialValues={{ device_role: 'monitor' }} onFinish={(values) => create.mutate(values)}>
          <Form.Item name="name" label="设备名称" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="device_role" label="设备类型" rules={[{ required: true }]}><Select options={deviceRoleOptions} /></Form.Item>
          <Form.Item name="vendor" label="厂商"><Input /></Form.Item>
          <Form.Item name="product" label="产品"><Input /></Form.Item>
          <Form.Item name="version" label="设备 IP"><Input placeholder="例如：10.4.6.8" /></Form.Item>
        </Form>
      </Modal>
    </>
  );
}
