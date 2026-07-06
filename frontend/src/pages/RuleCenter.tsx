import { Tabs, Typography } from 'antd';
import { ListChecks, Wand2 } from 'lucide-react';
import RuleConfig from './RuleConfig';
import RuleGenerator from './RuleGenerator';

export default function RuleCenter() {
  return (
    <div className="page">
      <div className="page-toolbar">
        <div>
          <Typography.Title level={4}>规则中心</Typography.Title>
          <Typography.Text type="secondary">统一管理内容解析规则、字段提取与自动生成工具</Typography.Text>
        </div>
      </div>
      <Tabs
        defaultActiveKey="config"
        type="card"
        items={[
          {
            key: 'config',
            label: <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}><ListChecks size={16} /> 规则配置</span>,
            children: <RuleConfig isSubModule />
          },
          {
            key: 'generator',
            label: <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}><Wand2 size={16} /> 规则生成器</span>,
            children: <RuleGenerator isSubModule />
          }
        ]}
      />
    </div>
  );
}
