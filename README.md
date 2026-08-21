<h1 align="center">EFF-Monitoring 安全运营协作平台</h1>

<div align="center">

<p align="center">
  <a href="https://github.com/Fausto-404/EFF-Monitoring/releases">
    <img src="https://img.shields.io/github/v/release/Fausto-404/EFF-Monitoring?style=flat-square&label=release&color=blue&cacheSeconds=3600" alt="Release">
  </a>

  <a href="https://github.com/Fausto-404/EFF-Monitoring/stargazers">
    <img src="https://img.shields.io/github/stars/Fausto-404/EFF-Monitoring?style=flat-square&label=stars&color=brightgreen&cacheSeconds=3600" alt="GitHub Stars">
  </a>

  <a href="https://github.com/Fausto-404/EFF-Monitoring/network/members">
    <img src="https://img.shields.io/github/forks/Fausto-404/EFF-Monitoring?style=flat-square&label=forks&color=orange&cacheSeconds=3600" alt="GitHub Forks">
  </a>

  <a href="https://github.com/Fausto-404/EFF-Monitoring/releases">
    <img src="https://img.shields.io/github/downloads/Fausto-404/EFF-Monitoring/total?style=flat-square&label=downloads&color=success&cacheSeconds=3600" alt="Downloads">
  </a>
</p>

</div>

EFF-Monitoring（Efficient Monitoring，高效监控）是一款面向安全运营场景的告警协作与 AI 研判平台。平台围绕安全事件全生命周期，提供内容解析、资产关联、智能研判、处置流转、经验沉淀、插件接入、备份迁移与报告输出等能力，通过证据驱动的分析与协同机制，帮助安全团队快速看懂告警、定位风险、联动上下游并提升处置效率。

---

**详细功能操作与最佳实践请查看：** [操作手册.md](./操作手册.md)  
**浏览器插件请查看：** [EFF-Assistant](https://github.com/Fausto-404/EFF-Assistant)

## 平台价值
+ **统一解析**：将不同设备、不同格式的原始日志转换为标准研判字段。
+ **资产关联**：统一化管理并关联资产、威胁情报、黑白名单、告警信息等内容。
+ **协作闭环**：内置监测组、研判组、处置组协作流程，支持认领、释放、强制解锁、状态流转和消息提醒。
+ **AI 增强**：AI 中心支持威胁分析、通用问答、报告生成三类 Agent，并提供快速 / 思考两种问答复杂度；告警详情内置智能研判引擎，统一输出研判标签、结论、置信度、风险等级和证据链。
+ **可追踪**：每条告警都有独立 `alert_hash`，用于生命周期跟踪、搜索、审计和复盘。
+ **可复盘**：闭环告警可沉淀为 STE 经验，后续 AI 研判可检索并复用相似经验。
+ **可输出**：支持报告生成、消息模板、Excel 模板、CSV 模板、Webhook 和告警导出。
+ **可接入插件**：支持 EFF Assistant 浏览器助手通过个人 PAT 接入平台，完成设备同步、页面解析、生成工单和平台证据增强研判。
+ **可迁移恢复**：系统管理提供备份与还原能力，备份包携带版本和字段结构，适合升级、迁移和灾备。

## 适用场景
+ 攻防演练期间快速同步、研判和分发安全事件。
+ SOC 值守人员统一处理来自态势感知、WAF、NDR、IPS 等设备的告警。
+ 需要把告警与资产、负责人、区域、重要性和处置结果打通的企业安全团队。
+ 需要积累可复用研判经验，并让 AI 持续吸收闭环结果的团队。
+ 需要把安全告警规范化输出到群机器人、报表、CSV 或 Excel 的运营场景。

## 核心场景流程
### 1、AI Agent 执行链路
<img width="1672" height="941" alt="Agent架构设计图" src="https://github.com/user-attachments/assets/80fb66ac-429e-4fe8-8ebf-b50d977ba9fd" />

### 2、告警闭环与分组协作机制
<!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/28328372/1779764135445-c1674106-9e43-4d6c-bf4c-debd1a56694e.png)

### 3、日志到告警的完整数据链路
<!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/28328372/1779761999718-bb47057c-9f3d-4d43-b355-fd20f4c4c398.png)

## 核心亮点功能展示
### 1、告警全生命周期管理与信息聚合
1.1、告警闭环全流程记录
<img width="2936" height="1508" alt="image" src="https://github.com/user-attachments/assets/16d726ca-a2f2-47ac-8ffd-956564bc332f" />
1.2、关联威胁情报、资产等信息
<img width="2834" height="1530" alt="image" src="https://github.com/user-attachments/assets/b0609e34-f443-411c-8174-e1470a63ce9c" />
### 2、Agent自主规划并调用工具
2.1、具备规划、调用、反思等全链路思考的Agent
<img width="2964" height="1518" alt="image" src="https://github.com/user-attachments/assets/ea8cb3e7-dbcc-4173-b09d-1684faa648ab" />
2.2、基于所有已知信息生成高可信的输出
<img width="2952" height="1530" alt="image" src="https://github.com/user-attachments/assets/39d02e30-7168-4929-9b7a-01bd1ad0fcec" />


### 3、高自定义的模版定义
3.1、可以基于所有内置变量、规则生成所需的报告
<img width="2978" height="1530" alt="image" src="https://github.com/user-attachments/assets/a626d46d-7c31-4f6c-b00c-6247d7cc7332" />
3.2、生成所需要的execl表格、效果格式
<img width="2992" height="1530" alt="image" src="https://github.com/user-attachments/assets/b1858d67-5f44-4897-b0ec-9c9a4d536377" />
3.3、导出成高自定义的csv文件
<img width="2952" height="1354" alt="image" src="https://github.com/user-attachments/assets/94c4b47f-5f34-46d3-812d-bdd8a4a9c139" />


### AI Agent 执行链路


## 项目目录
```latex
EFF-Monitoring/
├── backend/                 # 后端服务代码
│   ├── app/api              # REST API 路由
│   ├── app/core             # 配置与安全
│   ├── app/models           # ORM 模型、数据库和启动逻辑
│   ├── app/schemas          # Pydantic 请求/响应 schema
│   ├── app/services         # 业务逻辑服务
│   └── app/workers          # Worker 入口
├── core/                    # 内容解析、IP 名单、威胁情报核心能力
├── frontend/                # React Web 客户端
├── integration/             # Webhook 集成逻辑
├── output/                  # 消息与 Excel 格式化工具
├── docker/                  # nginx 等容器配置
├── Dockerfile.backend       # 后端镜像构建
├── Dockerfile.frontend      # 前端镜像构建
├── docker-compose.yml       # 一键部署容器编排
├── install.sh               # GitHub Release 一键安装入口
├── deploy.sh                # 使用本地离线包部署入口
├── scripts/                 # 镜像打包、日志和兼容脚本
├── .env.example             # 环境变量模板
└── 操作手册.md              # 功能操作与最佳实践
```

## 快速启动
### Docker 一键部署

#### 方式一：Git 一条命令部署（推荐）

```bash
git clone --depth 1 --branch v2.2.1 https://github.com/Fausto-404/EFF-Monitoring.git && cd EFF-Monitoring && ./install.sh
```

`install.sh` 会检测 CPU 架构：ARM64 自动下载 `eff-monitoring-v2.2.1-images-arm.tar`，amd64/x86_64 自动下载 `eff-monitoring-v2.2.1-images-amd.tar`，然后导入镜像并自动生成安全密码。

脚本会在启动前检查 Docker、磁盘空间、CPU 架构和端口；默认使用 8000（API）和 8080（前端），端口被占用时会自动选择下一个可用端口，也可以手动指定：

```bash
./install.sh --api-port 8001 --web-port 8081
```

离线镜像包需要与目标机器 CPU 架构一致。Release 中应同时上传 `arm` 和 `amd` 两个架构的镜像包。

#### 方式二：已有离线镜像包部署

如果已经将镜像包下载到本地：

```bash
./deploy.sh --offline /path/to/eff-monitoring-v2.2.1-images.tar
```

该方式不会下载任何镜像，也不会执行镜像构建。

#### 方式三：直接使用 Docker Compose

适合不想下载 600MB 以上离线镜像包、希望直接从源码构建镜像的场景。该方式需要目标机器能够访问 Docker 基础镜像和依赖包仓库。

复制环境变量模板并修改密码和密钥：

```bash
cp .env.example .env
```

至少修改 `.env` 中的以下配置：

```dotenv
POSTGRES_PASSWORD=请替换为随机密码
DATABASE_URL=postgresql+psycopg://eff:请替换为随机密码@eff-postgres:5432/eff_monitoring
JWT_SECRET=请替换为随机密钥
INITIAL_ADMIN_PASSWORD=请替换为管理员初始密码
```

然后启动服务：

```bash
docker compose up -d --build
```

该方式会根据 `Dockerfile.backend`、`Dockerfile.frontend` 和 `docker-compose.yml` 构建 API、Worker 和前端镜像；首次使用前必须完成 `.env` 配置。

发布制作者可按目标机器架构制作离线包：

```bash
./scripts/export-images.sh --platform linux/amd64 --output ./eff-monitoring-v2.2.1-images-amd.tar
./scripts/export-images.sh --platform linux/arm64 --output ./eff-monitoring-v2.2.1-images-arm.tar
```

打包脚本会在导出前校验镜像架构，普通用户不需要执行。

首次部署结束时请保存终端输出的管理员密码。密码同时保存在当前目录 `.env` 中。

默认访问地址（如果端口未被占用）：

+ 前端页面：`http://localhost:8080`

<!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/28328372/1779760276673-caeef1f8-9351-4246-a8a6-c4de59b78c71.png)

+ FastAPI 文档：`http://localhost:8000/docs`

<!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/28328372/1779760326253-e0659f93-9a9c-4e90-9305-9b9dc89534c5.png)

+ 后端 API：`http://localhost:8000`
+ 健康检查：`http://localhost:8000/healthz`


### 本地开发
后端：

```bash
cd backend
pip install -r requirements.txt
PYTHONPATH=backend:. uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

前端：

```bash
cd frontend
npm install
npm run dev
```

默认前端开发地址通常为：`http://localhost:5173`

## 功能模块概览
| 模块 | 主要能力 |
| :--- | :--- |
| 运营总览 | 告警总量、状态趋势、平均处置耗时、最近告警和运营统计 |
| 内容解析 | 原始日志解析、资产命中、IP 名单检测、模板输出、保存告警 |
| 告警工作台 | Hash 搜索、认领机制、状态流转、智能研判、威胁情报、资产上下文、闭环反馈、手动/自动刷新、服务端分页、CSV 导出 |
| AI 中心 | 威胁分析 / 通用问答 / 报告生成 Agent、快速 / 思考模式、Markdown 对话、会话记忆、执行链路/证据包查看、STE 经验库、AI 经验提取、AI 生成消息模板 |
| 资产中心 | 个体资产、网段资产、Excel 导入导出、资产指纹、负责人和区域维护 |
| 消息中心 | 工作流消息、未读提醒、按告警 Hash 快捷跳转 |
| 报告中心 | 报告新建、编辑、复制、导出 MD、删除，支持从模板和规则一键生成 |
| 规则中心 | 元规则、自定义规则、正则测试、设备规则适配、规则生成 |
| 模板中心 | 消息模板、Excel 模板、CSV 模板 |
| IP 名单 | 白名单、黑名单、CIDR/IP 范围检测、表格化维护、批量导入、名单导出 |
| 能力配置 | AI 模型网关、威胁情报、消息通知、浏览器插件接入的全员配置与个人配置，支持连通性测试、模型列表获取和插件 PAT 管理 |
| 系统管理 | 成员、设备、时间同步、备份与还原、审计日志、后台任务、历史导入 |


## 界面预览
### 运营总览
可查看告警事件数量、增长趋势、处理耗时等信息
<!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/28328372/1779762676402-950e56ff-29fc-43c9-9b30-5671c67d7743.png)

### 内容解析
可粘贴告警事件日志，点击解析日志进行自动解析，保存为事件工单进行流转处置
<!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/28328372/1779762559396-21a82d94-fb78-4aae-8b4e-21e016add271.png)

### 告警工作台
可查询、筛选已录入的安全告警事件，并进行认领、流转、指派等处置操作，并在详情处查看关联的AI研判结果、威胁情报、资产信息等。支持手动刷新和自动刷新，自动刷新频率可选 30 秒、1 分钟、3 分钟、5 分钟；列表使用服务端分页，适合较大告警量场景。
<!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/28328372/1779762589395-57be5a18-8881-4304-a042-4f6f3844d127.png)

### AI 中心
可通过对话式 AI 查询平台安全事件、进行威胁分析、通用问答和报告生成。威胁分析 Agent 会优先使用平台告警、资产、情报、相似经验等证据；通用问答 Agent 更适合普通问题；报告生成 Agent 面向总结、复盘和汇报材料生成。
<img width="2986" height="1512" alt="image" src="https://github.com/user-attachments/assets/37a131af-29c3-4139-90a1-2c72285ed201" />


### 资产中心
可配置资产网段信息，用于自动关联安全事件的源目IP地址资产
<!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/28328372/1779762740740-b54b16bd-fd9e-458c-b3cb-1d7ed1fcf189.png)

### 消息中心
根据事件处置动作或流程，推送对应的平台消息到具体的人员
<!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/28328372/1779762798116-03ccbc85-5656-4c5a-bcae-140ef128e5fa.png)

### 规则中心
支持灵活配置字段提取规则（正则表达式），支持规则生成器功能
<!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/28328372/1779765125867-f2089574-0ead-4407-92cd-97302c24aa43.png)

### 模板中心
：支持拖拽规则字段拼接消息模板、Execl模版、Csv模版
<!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/28328372/1779762995697-4db2dacd-2e06-4e57-9b8e-162addb47448.png)

### IP 名单
支持对 IP 地址进行黑白名单的快速匹配。名单按单条记录维护，支持单 IP、CIDR 和 IP 范围规则；批量导入会保留 CIDR/范围为规则条目，不会拆分为单 IP。
<img width="2998" height="1536" alt="image" src="https://github.com/user-attachments/assets/5a6d7a53-2cbc-4e48-b0ca-00d214cfe728" />

### 能力配置
适配常见大模型 API、威胁情报和消息通知，支持个人配置覆盖全员配置。并支持浏览器插件PAT接入。
<img width="3002" height="1522" alt="image" src="https://github.com/user-attachments/assets/3849fa0a-844f-4eb0-ac57-386e7fb4b41b" />


### 系统管理
支持成员、设备、时间同步、备份与还原、任务记录和审计日志管理。成员角色支持多选，方便同一人员同时承担研判与处置职责；备份文件可用于版本升级、迁移和灾备。
<!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/28328372/1779763048331-8fbc06d0-c817-4df4-9bdd-2f8ae67a150a.png)

## 角色与协作
平台内置五类角色：

+ `admin` 管理员：拥有系统管理、强制解锁、重新指派、删除、全员配置等权限。
+ `monitor` 监测组：负责同步告警。
+ `analyst` 研判组：负责研判中告警的认领、误报/忽略闭环或转处置。
+ `disposer` 处置组：负责处置中告警的认领、退回研判、纠正误报、忽略或已处置闭环。
+ `viewer` 只读人员：只读查看平台数据，不能执行写操作。

详细权限矩阵见：[操作手册.md#权限矩阵](./操作手册.md#权限矩阵)

## 技术架构
+ 后端：FastAPI + SQLAlchemy + Pydantic
+ 前端：React + TypeScript + Ant Design + Vite
+ 数据库：Docker Compose 默认 PostgreSQL，本地开发可使用 SQLite
+ Excel：openpyxl
+ AI：OpenAI 协议适配、DeepSeek、通义千问、智谱 AI、月之暗面、Anthropic 协议适配、Google Gemini、Ollama
+ Agent：LangGraph
+ 集成：威胁情报、Webhook、CSV / Excel 导出

## 可选演示数据
默认打包配置为 `ENABLE_DEMO_DATA=false`，首次启动只初始化系统默认规则、内置模板和管理员账号，不自动写入演示告警、演示资产和演示用户。

如需快速验证平台能力，可在 `.env` 中设置：

```bash
ENABLE_DEMO_DATA=true
```

开启后，系统会自动初始化一组演示数据，便于快速验证功能：

+ 演示用户：`demo_analyst / demo_viewer` 等，密码通过 `DEMO_USER_PASSWORD` 环境变量配置（默认 `demo123456`）
+ 演示设备：WAF、NDR、态势感知
+ 演示资产：门户、交易 API、数据库、办公终端、WebLogic 业务服务器、网段资产
+ 演示规则：通用规则、WAF/NDR 规则、态势感知日志解析规则
+ 演示模板：态势感知研判通报、Excel 行、CSV 资产导出
+ 演示告警：可验证资产命中、AI 研判、Hash 搜索、重复限制、运营总览和导出功能

演示日志中的公网 IP 使用文档保留地址段，不包含真实客户 IP。

## 更新记录

<details>
<summary><strong>v2.2.1</strong></summary>

### 修复
- **BUG修复**：修复了一些已知BUG
###  新增功能
- **认领后自动流转**：认领告警后自动弹出流转对话框。
- **资产 IP 名单展示**：告警详情显示源资产和目的资产的白名单/黑名单匹配状态。
- **表格列宽调整**：支持拖拽调整告警工作台列宽。
- **分页支持 1000 条/页**：方便批量查看和导出告警。
- **告警数据合并**：支持从 CSV 文件导入 136 条告警数据到备份内容。

### 性能优化

- **前端查询缓存**：用户、设备、模板、设置数据缓存 5 分钟。
- **告警列表翻页优化**：使用 keepPreviousData保留上一页数据，避免翻页闪烁。
- **后端数据库索引**：添加 5 个复合索引，覆盖 workspace_id 与状态、分组、认领人、创建时间等字段。
- **后端分页缓存**：告警列表查询采用 2 秒 TTL 缓存。
- **前端虚拟滚动**：支持大数据量告警渲染。
- **Nginx 上传优化**：上传上限调整为 `500m`
</details>

<details>
<summary><strong>v2.2.0</strong></summary>

- **AI 能力重构**：AI 中心拆分为威胁分析、通用问答和报告生成 Agent，并支持快速 / 思考模式。威胁分析 Agent 可回答威胁分析类问题，思考模式会主动调用平台只读工具查询告警、资产、威胁情报、经验和运营数据。
- **告警智能研判升级**：告警详情 AI 研判改为结构化展示，默认展开并突出研判结论、研判标签、风险等级、置信度、证据链和分析步骤；告警工作台与插件智能研判共用平台证据增强链路。
- **浏览器插件接入**：新增插件 API 与个人 PAT，支持 EFF Assistant 同步设备、解析页面、生成工单和智能研判。插件快速研判可独立运行，智能研判使用平台资产、情报、相似告警和 STE 经验增强。
- **系统配置优化**：插件接入配置仅保留在个人配置中，PAT 绑定当前用户，平台记录创建人、运行状态和操作审计。
- **协作与权限增强**：成员角色支持多选；告警详情重构为概览、资产与情报、AI 研判、原始证据和协作流转；插件生成告警会写入创建状态记录。
- **备份与还原**：系统管理新增备份与还原，可导出当前工作区 JSON 备份，并在恢复时根据当前版本字段自动兼容。
- **任务与审计清理**：任务记录和审计日志支持单条删除和批量删除。

</details>

<details>
<summary><strong>v2.1.4</strong></summary>

- **系统时间管理**：系统管理新增“时间同步”页，可配置应用时区和 NTP 服务器列表；业务时间生成、默认今日统计、消息已读、告警认领和报表生成按应用时区执行，当前时间在页面实时跳动显示。
- **告警工作台刷新增强**：新增手动刷新按钮和自动刷新开关，支持 30 秒、1 分钟、3 分钟、5 分钟刷新频率；告警列表改为服务端分页，适合每日数千告警的协作查看。
- **IP 名单表格化**：IP 名单从文本框改为单条记录管理，支持新增、编辑、删除、批量删除、筛选、导出和批量导入，CIDR 与范围保留为规则条目，兼容告警流转与解析命中检测。
- **消息通知增强**：消息通知改为按平台选择钉钉、企业微信、飞书，并分别维护 Webhook URL、签名 Secret、企业微信 @ 成员等专属参数；发送失败会返回第三方错误详情。
- **部署兼容增强**：新增 `scripts/compose-up.sh`，自动兼容 Docker Compose v1/v2，降低不同 Linux 环境部署差异。

</details>

<details>
<summary><strong>v2.1.3</strong></summary>

- **设备规则/模板导入包**：系统管理的设备列表新增按设备导出、导入“规则/模板导入包”功能。导出包为 JSON，包含设备信息、该设备绑定的解析规则和模板。

</details>

<details>
<summary><strong>v2.1.2</strong></summary>

- **安全事件跟踪表导出增强**：系统内置 `安全事件跟踪表` CSV 模板，支持导出告警编号、事件ID、告警设备、攻击源/目的 IP、研判结果、封禁位置、处置描述等字段。
- **设备类型与处置补充**：设备支持区分监测设备/封禁设备；封禁处置可选择封禁设备，应急处置可填写非必填处置描述。
- **交付包默认无历史测试数据**：默认关闭演示数据初始化，交付目录不携带当前环境 Docker 数据卷。

</details>

<details>
<summary><strong>v2.1.1</strong></summary>

- **配置整合**：`.env` 作为唯一配置来源，`docker-compose.yml` 中所有密码/secrets 统一通过 `${VAR}` 引用，修改密码只需改 `.env` 一处。新增 `POSTGRES_PASSWORD`、`DEMO_USER_PASSWORD` 独立变量，演示用户密码改为可配置。
- **Docker 兼容性修复**：`VITE_API_BASE_URL` 从根 `.env` 中移除（改为 `Dockerfile.frontend` 构建参数），不再注入后端容器导致 Pydantic `extra_forbidden` 校验崩溃。`docker-compose.yml` 兼容 Docker Compose v1（Python `docker-compose`）与 v2（Go `docker compose`）全版本。
- **安全加固**：新增 `backend/app/core/startup.py` 启动校验模块，检测 JWT_SECRET / INITIAL_ADMIN_PASSWORD 是否使用不安全默认值。生产环境（PostgreSQL）下使用默认密码时在日志中输出 `=== SECURITY WARNING ===` 醒目告警。
- **健康检查增强**：`/healthz` 和 `/readyz` 端点改为实际执行 `SELECT 1` 验证数据库连通性，数据库不可达时返回 `degraded`/`not_ready` 状态（`/readyz` 返回 HTTP 503）。
- **启动可靠性**：后端容器新增 `docker/entrypoint.sh`，从 `DATABASE_URL` 解析 host:port 并轮询等待 PostgreSQL 就绪（最多 60 秒），避免数据库未就绪时容器反复重启。
- **前端错误反馈**：系统管理页新增/编辑成员、设备的 mutation 增加 `onError` 回调，API 失败时通过 `message.error()` 显示后端返回的具体错误信息。
- **`.gitignore`**：新增防止 `.env` 等敏感文件被提交。

</details>

<details>
<summary><strong>v2.1</strong></summary>

- **新增报告中心**：支持新建、编辑、复制、导出 MD 和删除报告；支持从内容解析、运营总览等模块一键生成报告并保存。
- **权限修复**：修复 viewer 只读用户可绕过前端直接调用写接口（规则创建、模板创建/编辑、配置修改、Webhook 发送）的安全漏洞。

</details>
