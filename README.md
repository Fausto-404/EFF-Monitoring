# EFF-Monitoring 安全告警处理系统

安全监测人员的效能提升神器，一款基于 PySide6 开发的安全告警处理工具，围绕“高效日志处理、快捷辅助 研判 ”为安全监测人员的工作进行减负增效。

## 功能特性

### 1. 日志处理 📋
- 支持通过「规则管理」页面自定义正则规则，解析安全设备告警日志。
- 内置基础 KV 解析（分号、制表符、换行等），兼容非结构化文本。
- 提取 6 个必填字段：`src_ip`、`dst_ip`、`event_type`、`request`、`response`、`payload`。
- 解析结果同时以「消息格式」和「Excel 格式」展示，方便复制到聊天工具或表格。

### 2. 威胁情报 🔍
- 集成微步 ThreatBook：
  - **API 请求模式**：使用官方 `ip_reputation` 接口。
  - **HTTP 请求模式**：使用浏览器 Cookie 访问 `https://x.threatbook.com/v5/ip/<ip>` 页面（适合 API 配额紧张场景）。
- 根据配置对源 IP / 目的 IP 分别查询，结果统一渲染为：
  - 顶部「总体概览」。
  - 下方「源 IP 威胁情报」和「目的 IP 威胁情报」分区。

### 3. AI 研判 🤖
- 使用 SiliconFlow 的 Chat Completions 接口（默认 DeepSeek 模型）。
- 采用 CO-STAR 风格提示词，将：
  - 日志解析结果（含 6 个必填字段），
  - 请求 / 响应载荷，
  - 威胁情报结果
  组合成上下文，自动生成结构化研判结论。
- 支持配置：
  - 分析目标（Objective）
  - 受众（客户 / 专家 / 初学者）
  - 输出模式（结构化 / 简要 / 报告）

### 4. IP 列表管理 📝
- 图形界面管理白名单 / 黑名单：
  - 支持单 IP、CIDR、范围、简写范围（例如 `192.168.1.1-100`）。
- 日志处理时自动检查源 / 目的 IP 是否在白 / 黑名单，并弹出提醒。
- 提供脚本将文本名单迁移到 SQLite 数据库（`scripts/migrate_ip_lists.py`）。

### 5. 消息推送 📤
- 将格式化后的告警结果发送到：
  - 钉钉（支持签名鉴权）
  - 企业微信
  - 飞书
- 支持同时向多个渠道发送，界面中可以查看发送结果提示。

### 6. 规则与配置管理 ⚙️
- **规则管理**（RulePage）：
  - 以表格形式管理字段规则（字段 / 匹配方式 / 正则或固定值）。
  - 6 个必填字段固定置顶并高亮，且至少保留一条规则。
  - 编辑统一通过弹窗进行，避免误改必填字段。
- **配置管理**（ConfigPage）：
  - GUI 配置 ThreatBook、AI、Webhook、字段顺序、历史记录等。
  - 支持重新加载配置、保存配置，并在各页面自动生效。

## 项目结构

```text
EFF-Monitoring/
├── app/                     # 应用层（PySide6 GUI）
│   ├── main.py              # GUI 启动入口
│   ├── main_window.py       # 主窗口与导航
│   ├── log_page.py          # 日志处理页
│   ├── history_page.py      # 解析历史页
│   ├── ip_page.py           # IP 管理页（白/黑名单）
│   ├── rule_page.py         # 规则管理页（正则/固定值配置）
│   ├── config_page.py       # 配置管理页（TI/AI/Webhook/字段/历史）
│   ├── logic.py             # 业务处理逻辑封装
│   ├── workers.py           # 后台线程（TI 查询、AI 调用、Webhook）
│   └── ui_common.py         # Qt 公共导入与类型封装
├── core/                    # 核心能力模块
│   ├── config.py            # 默认配置与 JSON 读写
│   ├── parser.py            # 文本解析与日志解析
│   ├── regex.py             # 正则引擎（从配置编译模式）
│   ├── lists.py             # IP 名单读写与匹配
│   └── ti_service.py        # ThreatBook 威胁情报查询与聚合
├── integration/
│   └── webhook.py           # 钉钉 / 企业微信 / 飞书 Webhook 发送
├── output/
│   └── formatter.py         # 聊天 / Excel / TI / AI 格式化输出
├── lists/
│   ├── whitelist.txt        # 默认白名单（文本模式）
│   └── blocked.txt          # 默认黑名单（文本模式）
├── config.json              # 运行时配置（首次启动自动生成）
├── run.py                   # 启动 GUI 的主脚本
├── requirements.txt         # 依赖清单
└── README.md                # 本文件
```

## 安装与运行

### 环境要求

- Python 3.10+
- 支持 macOS / Linux / Windows

### 安装依赖

```bash
pip install -r requirements.txt
```

### 启动应用

```bash
python run.py
```

首次启动会自动生成默认的 `config.json`、白名单 / 黑名单文件等。

## 快速上手

### 示例：处理 Web 告警日志并做 TI + AI 研判

1. 打开 **日志处理** 页面。
2. 将原始告警日志粘贴到左侧输入框，例如：

   ```text
   源IP: 172.21.112.184
   目的IP: 172.16.1.80
   事件类型: HTTP目录遍历请求尝试
   请求内容: GET /../../../../etc/passwd HTTP/1.1
   响应内容: HTTP/1.1 403 Forbidden
   ```

3. 点击 **处理日志**：
   - 使用当前规则解析日志，提取必填字段及其它字段。
   - 若源 / 目的 IP 命中白 / 黑名单，会弹出提示。
   - 右侧展示「消息格式」和「Excel 格式」两种输出。
4. 点击 **告警研判**：
   - 根据配置选择是否对源 / 目的 IP 查询 ThreatBook。
   - 在「威胁情报」标签页查看总体概览和详细情报。
   - 在「AI 研判结果」标签页查看 AI 给出的结构化结论。
5. 若需推送到群聊，点击 **发送到群聊**，在「配置管理 → 消息推送」中预先填好钉钉 / 企业微信 / 飞书的 Webhook 即可。

### IP 管理

1. 打开 **IP 管理** 页面。
2. 通过顶部按钮在「白名单 / 黑名单」之间切换当前列表。
3. 使用「添加 / 删除选中 / 导入 / 导出 / 保存」管理名单。
4. 支持的 IP 表达方式：
   - 单 IP：`192.168.1.1`
   - CIDR：`192.168.1.0/24`
   - 范围：`192.168.1.1-192.168.1.100`
   - 简写范围：`192.168.1.1-100`

### 配置 ThreatBook / AI / Webhook

1. 打开 **配置管理** 页面。
2. 在「威胁情报」标签页：
   - 请求模式按钮在「禁用 / API 请求 / HTTP 请求」之间点击切换。
   - API 请求模式：填写 ThreatBook API Key。
   - HTTP 请求模式：在浏览器登录微步社区后复制 Cookie 填入 HTTP Cookie 字段。
   - 查询模式：选择查询源 IP、目的 IP，或两者。
   - 使用「测试查询」按钮验证配置是否有效（HTTP 模式下若返回空结果，会弹出可点击链接提醒，可在浏览器手动校验是否触发机器人验证）。
3. 在「AI 配置」标签页：
   - 启用 AI，并填写模型名称、API Key、Base URL。
   - 配置分析目标（Objective）、受众（Audience）和输出模式（Response Mode）。
4. 在「消息推送」标签页配置钉钉 / 企业微信 / 飞书 Webhook。
5. 在「解析配置」标签页调整字段顺序、历史记录最大条数等。

## 配置文件结构概览

`core/config.py` 中的 `get_default_config()` 定义了默认配置结构，典型形态如下（部分字段简化展示）：

```jsonc
{
  "regex": {
    "five_tuple": {
      "src_ip": "[\\d.]+|[\\da-fA-F:]+",
      "dst_ip_port": "[\\d.]+(?::\\d+)?|[\\da-fA-F:]+(?::\\d+)?",
      "protocol": "TCP|UDP|ICMP|HTTP|HTTPS"
    },
    "extra_fields": {}
  },
  "providers": {
    "threatbook": {
      "enabled": false,
      "api_key": "",
      "mode": "both",          // both | src | dst
      "request_mode": "api",   // off | api | http
      "http_cookie": ""
    }
  },
  "ai": {
    "enabled": false,
    "model": "deepseek-ai/DeepSeek-V2",
    "api_key": "",
    "base_url": "https://api.siliconflow.cn",
    "objective": "对该告警进行专业安全威胁研判...",
    "audience": "expert",          // customer | expert | beginner
    "response_mode": "structured"  // structured | brief | report
  },
  "webhook": {
    "dingtalk": { "enabled": false, "url": "", "secret": "" },
    "wecom":    { "enabled": false, "url": "" },
    "feishu":   { "enabled": false, "url": "" }
  },
  "fields": {
    "order": [
      "src_ip", "dst_ip", "event_name",
      "alert_device", "analyst", "alert_id",
      "compromised", "event_type", "suggestion"
    ],
    "auto_append_extra": false
  },
  "lists": {
    "whitelist_path": "lists/whitelist.txt",
    "blocked_path":   "lists/blocked.txt",
    "whitelist_skip_ti": true
  },
  "static_fields": {},
  "manual_fields": [
    { "key": "alert_device", "label": "告警设备", "type": "text" },
    { "key": "analyst",      "label": "研判人员", "type": "text" },
    { "key": "alert_id",     "label": "告警编号", "type": "text" },
    { "key": "compromised",  "label": "是否失陷", "type": "select", "options": ["否", "是"] },
    { "key": "event_type",   "label": "事件类型", "type": "text" },
    { "key": "suggestion",   "label": "处置建议", "type": "textarea" }
  ],
  "field_labels": {
    "src_ip": "源IP",
    "dst_ip": "目的IP",
    "event_name": "事件名称",
    "alert_device": "告警设备",
    "analyst": "研判人员",
    "alert_id": "告警编号",
    "compromised": "是否失陷",
    "event_type": "事件类型",
    "suggestion": "处置建议"
  },
  "history": {
    "enabled": true,
    "max_entries": 200,
    "file": "output/log_history.json"
  }
}
```

## 关键模块一览

- `core/config.py`：配置文件的生成、加载与保存（`ensure_config`, `load_config`, `save_config`）。
- `core/parser.py`：基础文本解析与日志解析（`parse_text`, `parse_log`）。
- `core/regex.py`：从配置加载正则引擎并提取字段（`RegexEngine`, `load_engine`）。
- `core/lists.py`：IP 白 / 黑名单读写与范围匹配（`read_lines`, `write_lines`, `is_ip_in_list`）。
- `core/ti_service.py`：ThreatBook API / HTTP 查询与结果规范化（`ThreatIntelService`, `query_pair`）。
- `output/formatter.py`：聊天 / Excel / TI / AI 文本格式化（`render_chat`, `render_excel`, `render_ti_info`, `render_ai_result`）。
- `integration/webhook.py`：发送消息到钉钉 / 企业微信 / 飞书（`send_record`）。
- `app/logic.py`：封装日志处理全流程（`process_log_data`）。

