import { useEffect, useMemo, useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { Button, Form, Input, Modal, Space, Switch, Typography, message } from 'antd';
import { reportApi } from '../api/client';
import type { ReportGenerateResult } from '../api/types';

interface ReportGenerateModalProps {
  open: boolean;
  onClose: () => void;
  sourceType?: string;
  sourceModule?: string;
  sourceId?: number;
  templateId?: number;
  ruleId?: number;
  projectId?: number;
  deviceId?: number;
  defaultTitle?: string;
  defaultCategory?: string;
  defaultReportKey?: string;
  defaultTags?: string[];
  defaultContext?: Record<string, any>;
  defaultSourceRefs?: Record<string, any>;
  defaultContent?: string;
  rawTemplate?: string;
  onGenerated?: (result: ReportGenerateResult) => void;
}

function parseTags(value: string | undefined): string[] {
  return (value || '')
    .split(/[,，\s]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

export default function ReportGenerateModal(props: ReportGenerateModalProps) {
  const [form] = Form.useForm();
  const [preview, setPreview] = useState('');

  const bodyText = useMemo(() => props.defaultContent || props.rawTemplate || '', [props.defaultContent, props.rawTemplate]);
  const contextText = useMemo(() => JSON.stringify(props.defaultContext || {}, null, 2), [props.defaultContext]);

  useEffect(() => {
    if (!props.open) return;
    form.setFieldsValue({
      title: props.defaultTitle || '',
      report_category: props.defaultCategory || '',
      tags: (props.defaultTags || []).join(', '),
      save: true,
      body: bodyText
    });
    setPreview('');
  }, [bodyText, form, props.defaultCategory, props.defaultTags, props.defaultTitle, props.open]);

  const generate = useMutation({
    mutationFn: async (save: boolean) => {
      const values = form.getFieldsValue();
      return reportApi.generateReport({
        title: values.title || undefined,
        report_category: values.report_category || undefined,
        report_key: props.defaultReportKey,
        source_type: props.sourceType || 'manual',
        source_module: props.sourceModule || 'report_center',
        source_id: props.sourceId,
        template_id: props.templateId,
        rule_id: props.ruleId,
        project_id: props.projectId,
        device_id: props.deviceId,
        render_context: props.defaultContext || {},
        source_refs: props.defaultSourceRefs || {},
        content: props.defaultContent ? values.body : undefined,
        raw_template: !props.defaultContent && !props.templateId ? values.body : props.rawTemplate,
        save,
        tags: parseTags(values.tags)
      });
    },
    onSuccess: (result, save) => {
      setPreview(result.content);
      props.onGenerated?.(result);
      message.success(save ? '报告已生成并保存' : '报告预览已生成');
      if (save) props.onClose();
    },
    onError: (error: any) => message.error(error?.response?.data?.detail || '报告生成失败')
  });

  return (
    <Modal
      title="生成报告"
      open={props.open}
      onCancel={props.onClose}
      width={760}
      footer={[
        <Button key="cancel" onClick={props.onClose}>取消</Button>,
        <Button key="preview" onClick={() => generate.mutate(false)} loading={generate.isPending}>预览</Button>,
        <Button key="save" type="primary" onClick={() => generate.mutate(true)} loading={generate.isPending}>生成并保存</Button>
      ]}
    >
      <Space direction="vertical" className="full-width" size={14}>
        <Form form={form} layout="vertical" initialValues={{ save: true }}>
          <Form.Item name="title" label="报告标题">
            <Input placeholder="不填写时由系统按分类和时间生成" />
          </Form.Item>
          <Form.Item name="report_category" label="报告分类">
            <Input placeholder="例如：规则生成报告" />
          </Form.Item>
          <Form.Item name="tags" label="标签">
            <Input placeholder="多个标签用逗号或空格分隔" />
          </Form.Item>
          <Form.Item name="save" label="是否保存到报告中心" valuePropName="checked">
            <Switch checkedChildren="保存" unCheckedChildren="仅预览" />
          </Form.Item>
          <Form.Item name="body" label={props.defaultContent ? '正文预览' : '模板预览'}>
            <Input.TextArea rows={8} disabled={!!props.templateId && !props.defaultContent} />
          </Form.Item>
        </Form>
        <div>
          <Typography.Text strong>render_context 预览</Typography.Text>
          <pre style={{ marginTop: 8 }}>{contextText}</pre>
        </div>
        {preview && (
          <div>
            <Typography.Text strong>生成结果</Typography.Text>
            <pre style={{ marginTop: 8, maxHeight: 260, overflow: 'auto' }}>{preview}</pre>
          </div>
        )}
      </Space>
    </Modal>
  );
}
