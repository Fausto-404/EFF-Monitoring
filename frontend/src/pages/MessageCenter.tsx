import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Button, DatePicker, Empty, List, Popconfirm, Select, Space, Tag, Typography, message, Checkbox } from 'antd';
import dayjs from 'dayjs';
import type { Dayjs } from 'dayjs';
import { api } from '../api/client';
import type { MessageItem, User } from '../api/types';

export default function MessageCenter({ onOpenAlert }: { onOpenAlert: (alertHash: string) => void }) {
  const [range, setRange] = useState<[Dayjs, Dayjs] | null>(null);
  const [recipientId, setRecipientId] = useState<number | undefined>();
  const [actorId, setActorId] = useState<number | undefined>();
  const [readStatus, setReadStatus] = useState<string | undefined>();
  const [selectedIds, setSelectedIds] = useState<number[]>([]);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  
  const queryClient = useQueryClient();

  const { data: currentUser } = useQuery({
    queryKey: ['me'],
    queryFn: async () => (await api.get<User>('/api/auth/me')).data,
    staleTime: 5 * 60 * 1000,
  });
  const isAdmin = currentUser?.role === 'admin';

  const { data: users = [] } = useQuery({
    queryKey: ['users'],
    queryFn: async () => (await api.get<User[]>('/api/users')).data,
    staleTime: 5 * 60 * 1000,
  });

  const { data = [], isLoading } = useQuery({
    queryKey: ['messages', range?.[0]?.valueOf(), range?.[1]?.valueOf(), recipientId, actorId, readStatus, page, pageSize],
    queryFn: async () => (await api.get<MessageItem[]>('/api/messages', {
      params: {
        recipient_id: recipientId,
        actor_id: actorId,
        read_status: readStatus,
        start_date: range?.[0]?.format('YYYY-MM-DD HH:mm:ss'),
        end_date: range?.[1]?.format('YYYY-MM-DD HH:mm:ss'),
        limit: pageSize,
        offset: (page - 1) * pageSize
      }
    })).data
  });

  const read = useMutation({
    mutationFn: async (id: number) => (await api.post<MessageItem>(`/api/messages/${id}/read`)).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['messages'] });
      queryClient.invalidateQueries({ queryKey: ['messages-unread'] });
      queryClient.invalidateQueries({ queryKey: ['messages-recent'] });
    }
  });

  const batchRead = useMutation({
    mutationFn: async (ids: number[]) => (await api.post('/api/messages/batch-read', { ids })).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['messages'] });
      queryClient.invalidateQueries({ queryKey: ['messages-unread'] });
      queryClient.invalidateQueries({ queryKey: ['messages-recent'] });
      setSelectedIds([]);
      message.success('选中的消息已标记为已读');
    }
  });

  const readAll = useMutation({
    mutationFn: async () => (await api.post('/api/messages/read-all')).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['messages'] });
      queryClient.invalidateQueries({ queryKey: ['messages-unread'] });
      queryClient.invalidateQueries({ queryKey: ['messages-recent'] });
      message.success('消息已全部标记为已读');
    }
  });

  const remove = useMutation({
    mutationFn: async (id: number) => (await api.delete(`/api/messages/${id}`)).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['messages'] });
      queryClient.invalidateQueries({ queryKey: ['messages-unread'] });
      queryClient.invalidateQueries({ queryKey: ['messages-recent'] });
      message.success('消息已删除');
    }
  });

  const openAlert = async (item: MessageItem) => {
    if (!item.is_read && item.recipient_id === currentUser?.id) await read.mutateAsync(item.id);
    if (item.alert_hash) onOpenAlert(item.alert_hash);
  };

  const toggleSelect = (id: number) => {
    setSelectedIds(prev => prev.includes(id) ? prev.filter(i => i !== id) : [...prev, id]);
  };

  return (
    <div className="page">
      <div className="page-toolbar">
        <div>
          <Typography.Title level={4}>消息中心</Typography.Title>
          <Typography.Text type="secondary">查看告警流转、认领和名单联动通知</Typography.Text>
        </div>
        <Space wrap>
          <DatePicker.RangePicker 
            showTime 
            value={range} 
            onChange={(val) => {
              setRange(val as [Dayjs, Dayjs] | null);
              setPage(1);
            }} 
            placeholder={['开始时间', '结束时间']}
          />
          {isAdmin && (
            <Select
              allowClear
              placeholder="接收人员 (仅管理员)"
              style={{ width: 160 }}
              value={recipientId}
              onChange={(val) => {
                setRecipientId(val);
                setPage(1);
              }}
              options={users.map(u => ({ value: u.id, label: u.display_name }))}
            />
          )}
          <Select
            allowClear
            placeholder="发信人员 (触发者)"
            style={{ width: 160 }}
            value={actorId}
            onChange={(val) => {
              setActorId(val);
              setPage(1);
            }}
            options={users.map(u => ({ value: u.id, label: u.display_name }))}
          />
          <Select
            allowClear
            placeholder="阅读状态"
            style={{ width: 120 }}
            value={readStatus}
            onChange={(val) => {
              setReadStatus(val);
              setPage(1);
            }}
            options={[
              { value: 'unread', label: '未读' },
              { value: 'read', label: '已读' }
            ]}
          />
          {selectedIds.length > 0 && (
            <Button type="primary" onClick={() => batchRead.mutate(selectedIds)} loading={batchRead.isPending}>
              标记选中已读 ({selectedIds.length})
            </Button>
          )}
          <Button onClick={() => readAll.mutate()} disabled={!data.some((item) => !item.is_read && item.recipient_id === currentUser?.id)} loading={readAll.isPending}>
            全部已读
          </Button>
        </Space>
      </div>
      <List
        loading={isLoading}
        dataSource={data}
        pagination={{
          current: page,
          pageSize: pageSize,
          total: data.length === pageSize ? page * pageSize + 1 : (page - 1) * pageSize + data.length,
          showSizeChanger: true,
          pageSizeOptions: ['10', '20', '50', '100'],
          onChange: (p, size) => {
            setPage(p);
            setPageSize(size || 20);
          },
          onShowSizeChange: (_p, size) => {
            setPage(1);
            setPageSize(size);
          },
          size: 'small',
          style: { marginTop: 16, textAlign: 'right' }
        }}
        locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无消息" /> }}
        renderItem={(item) => (
          <List.Item
            actions={[
              item.alert_hash ? <Button size="small" type="link" onClick={() => openAlert(item)}>查看告警</Button> : null,
              !item.is_read && item.recipient_id === currentUser?.id ? <Button size="small" onClick={() => read.mutate(item.id)}>标记已读</Button> : null,
              isAdmin ? (
                <Popconfirm title="删除该消息？" onConfirm={() => remove.mutate(item.id)}>
                  <Button size="small" danger loading={remove.isPending}>删除</Button>
                </Popconfirm>
              ) : null
            ].filter(Boolean)}
          >
            <List.Item.Meta
              avatar={<Checkbox checked={selectedIds.includes(item.id)} onChange={() => toggleSelect(item.id)} disabled={item.is_read || item.recipient_id !== currentUser?.id} />}
              title={
                <Space wrap>
                  {!item.is_read && <Tag color="red">未读</Tag>}
                  <Typography.Text strong={!item.is_read}>{item.title}</Typography.Text>
                  {isAdmin && <Tag>收信: {item.recipient_name}</Tag>}
                  <Tag color="cyan">发信: {item.actor_name}</Tag>
                  {item.alert_hash && <Typography.Text code copyable>{item.alert_hash}</Typography.Text>}
                </Space>
              }
              description={
                <Space direction="vertical" size={2}>
                  <Typography.Text>{item.content || '无内容'}</Typography.Text>
                  <Typography.Text type="secondary">{dayjs(item.created_at).format('YYYY-MM-DD HH:mm:ss')}</Typography.Text>
                </Space>
              }
            />
          </List.Item>
        )}
      />
    </div>
  );
}
