import { ReactNode } from 'react';
import { QuestionCircleOutlined } from '@ant-design/icons';
import { Tooltip } from 'antd';

interface HelpTipProps {
  title: ReactNode;
}

export default function HelpTip({ title }: HelpTipProps) {
  return (
    <Tooltip title={title}>
      <QuestionCircleOutlined className="help-tip" />
    </Tooltip>
  );
}
