import React, { useState } from 'react';
import { Button, Space } from 'antd';
import { DownOutlined, UpOutlined } from '@ant-design/icons';

type CollapsibleBlockProps = {
  title: React.ReactNode;
  children: React.ReactNode;
  defaultExpanded?: boolean;
  collapsedHeight?: number;
  expandedMaxHeight?: number;
  collapsible?: boolean;
  extra?: React.ReactNode;
  className?: string;
  bodyStyle?: React.CSSProperties;
  onExpandChange?: (expanded: boolean) => void;
};

const CollapsibleBlock: React.FC<CollapsibleBlockProps> = ({
  title,
  children,
  defaultExpanded = false,
  collapsedHeight = 240,
  expandedMaxHeight = 520,
  collapsible = true,
  extra,
  className,
  bodyStyle,
  onExpandChange,
}) => {
  const [expanded, setExpanded] = useState(defaultExpanded);

  const toggle = () => {
    const next = !expanded;
    setExpanded(next);
    onExpandChange?.(next);
  };

  const containerStyle: React.CSSProperties = {
    background: '#fafafa',
    border: '1px solid #f0f0f0',
    borderRadius: 8,
    padding: '12px',
    position: 'relative',
    ...bodyStyle,
  };

  const contentStyle: React.CSSProperties = {
    maxHeight: collapsible ? (expanded ? expandedMaxHeight : collapsedHeight) : 'none',
    overflow: collapsible ? (expanded ? 'auto' : 'hidden') : 'visible',
    transition: 'max-height 0.2s ease',
  };

  return (
    <div className={className} style={{ marginBottom: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
        <span style={{ fontWeight: 600, fontSize: 14 }}>{title}</span>
        <Space>
          {extra}
          {collapsible && (
            <Button
              type="link"
              size="small"
              onClick={toggle}
              icon={expanded ? <UpOutlined /> : <DownOutlined />}
            >
              {expanded ? '收起' : '展开'}
            </Button>
          )}
        </Space>
      </div>
      <div style={containerStyle}>
        <div style={contentStyle}>
          {children}
        </div>
      </div>
    </div>
  );
};

export default CollapsibleBlock;
