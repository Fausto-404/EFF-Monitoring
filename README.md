<h1 align="center">EFF-Monitoring</h1>

<div align="center">

![Release](https://img.shields.io/github/v/release/Fausto-404/EFF-Monitoring)
![Stars](https://img.shields.io/github/stars/Fausto-404/EFF-Monitoring)
![Forks](https://img.shields.io/github/forks/Fausto-404/EFF-Monitoring)
![Issues](https://img.shields.io/github/issues/Fausto-404/EFF-Monitoring)
![License](https://img.shields.io/github/license/Fausto-404/EFF-Monitoring)

</div>




EFF-Monitoring（Efficient Monitoring，高效监控），是一款面向安全运营 / 蓝队的本地告警处理工具，聚焦“高效日志处理 + 自动化情报补全 + AI 研判”，帮助安全监测人员在攻防演练和日常值班中快速看懂告警、打通上下游。

## 核心价值

- **把“堆满终端的原始日志”变成“结构化视图”**  
  一次性解析出安全监测人员进行事件记录的所有字段（包括手动添加和日志识别），并自动生成可复制到聊天工具/Excel 的两种格式。

- **把威胁分析的动作收敛到一屏**  
  集成微步 ThreatBook，对源/目的 IP 统一查询，自动聚合情报并以“总体概览 + 详细分区”的方式呈现。

- **把“分析研判”交给 AI，自己专注于决策**  
  基于 CO-STAR 提示词，将解析结果 + 请求/响应 + TI 结果拼成上下文，一键生成结构化研判结论；支持单条告警和多条告警（按历史记录批量研判）两种模式。

- **把“重复劳动”沉到规则和配置里**  
  通过 GUI 配置规则、字段顺序、静态字段、消息模板等，把经验固化为规则；后续只需粘日志、点按钮，大量日常工作变成“确认而不是重做”。

- **赋能初级研判人员，小白秒入门**  
  威胁情报分析、AI辅助分析、白名单黑名单匹配从技术层面解决了初级监测人员看不懂告警、弄不清威胁、易封错ip的问题。

- **把“信息碎片”汇成可复盘的历史**  
  对每次解析结果及 TI / AI 输出做持久化，支持导出 CSV、批量 AI 复盘，为演练复盘/报告撰写提供原始素材。

## 功能特性

### 1. 日志处理 📋
- 支持通过「规则管理」页面自定义正则规则，解析安全设备告警日志。
- 内置基础 KV 解析（分号、制表符、换行等），兼容非结构化文本。
- 解析结果同时以「消息格式」和「Excel 格式」展示，方便复制到聊天工具或表格。
<img width="1191" height="819" alt="image" src="https://github.com/user-attachments/assets/9ebdb7ef-9144-4957-9c09-428933486ba1" />


### 2. 威胁情报 🔍
- 集成微步 ThreatBook：
  - **API 请求模式**：使用官方 `ip_reputation` 接口。
  - **HTTP 请求模式**：使用浏览器 Cookie 访问 `https://x.threatbook.com/v5/ip/<ip>` 页面（适合 API 配额紧张场景）。
- 根据配置对源 IP / 目的 IP 分别查询，结果统一渲染。
<img width="1195" height="822" alt="image" src="https://github.com/user-attachments/assets/c407987b-dd6d-4e83-a7a3-45d19cafb79f" />

### 3. AI 研判 🤖
- 使用 SiliconFlow 的 Chat Completions 接口。
- 采用 CO-STAR 风格提示词，将：
  - 日志解析结果，
  - 请求/响应/载荷，
  - 威胁情报结果
  组合成上下文，自动生成结构化研判结论。
- 支持配置：
  - 分析目标（Objective）
  - 受众（客户 / 专家 / 初学者）
  - 输出模式（结构化 / 简要 / 报告）
<img width="1188" height="822" alt="image" src="https://github.com/user-attachments/assets/e1ad19d9-5b56-426c-bf68-73d06c403ffc" />

### 4. IP 列表管理 📝
- 图形界面管理白名单 / 黑名单：
  - 支持单 IP、CIDR、范围、简写范围（例如 `192.168.1.1-100`）。
- 日志处理时自动检查源 / 目的 IP 是否在白 / 黑名单，并弹出提醒。
<img width="1190" height="819" alt="image" src="https://github.com/user-attachments/assets/54c6a75c-7c0f-4fb7-ac94-84fe1b3e73de" />

### 5. 消息推送 📤
- 将格式化后的告警结果发送到：
  - 钉钉
  - 企业微信
  - 飞书
- 支持同时向多个渠道发送，界面中可以查看发送结果提示。
<img width="1191" height="816" alt="image" src="https://github.com/user-attachments/assets/6c9ddee6-c88e-4441-bb50-136334bb39cf" />

### 6. 规则与配置管理 ⚙️
- **规则管理**（RulePage）：
  - 以表格形式管理字段规则（字段 / 匹配方式 / 正则或固定值）。
<img width="1193" height="817" alt="image" src="https://github.com/user-attachments/assets/105727f5-2890-4356-a755-4bf7b1eb97f4" />

- **配置管理**（ConfigPage）：
  - GUI 配置 ThreatBook、AI、Webhook、字段顺序、历史记录等。
  - 支持重新加载配置、保存配置，并在各页面自动生效。
<img width="1193" height="819" alt="image" src="https://github.com/user-attachments/assets/257f26df-6f57-4194-89bc-08d3b67c4958" />


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
编译版本直接双击运行即可

## 快速上手

### 示例：处理 Web 告警日志并做 TI + AI 研判

1. 打开 **日志处理** 页面。
2. 将原始告警日志粘贴（`Ctrl+A` 全选复制即可）到左侧输入框，例如：
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
   - 填写模型名称、API Key、Base URL。
   - 配置分析目标（Objective）、受众（Audience）和输出模式（Response Mode）。
4. 在「消息推送」标签页配置钉钉 / 企业微信 / 飞书 Webhook。
5. 在「解析配置」标签页调整字段顺序、历史记录最大条数等。
