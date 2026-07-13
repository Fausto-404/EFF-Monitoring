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

EFF-Monitoring（Efficient Monitoring，高效监控）是一款以内置 Agent 为核心的安全运营协作平台。平台围绕安全事件全生命周期，提供内容解析、资产关联、AI研判、处置流转、经验沉淀与报告输出等能力，通过证据驱动的分析与协同机制，帮助安全团队快速看懂告警、定位风险、联动上下游并提升处置效率。

---

**<font style="color:#000000;background-color:#FBF5CB;">详细功能操作与最佳实践请查看：</font>**[**<font style="color:#000000;background-color:#FBF5CB;">操作手册.md</font>**](./操作手册.md)

## 引言
使用这个平台前，可以先想想您的场景是否有以下痛点:
1. **时间断节，写报告难：** 发现和封禁没有精确时间记录，写复盘报告时全凭记忆倒推，费时费力。
2. **疯狂切窗口，研判效率低：** 查情报、对资产、找负责人，要在好几个 Excel 、平台之间来回切换。
3. **纯手工 CV，机械重复：** 确认一条高危，要重复复制粘贴到 Word 模板、防守台账 Excel 和微信工作群。
4. **汇报全靠人肉凑：** 日报、周报、成效报告数据无法一键生成，每到交报告节点，只能加班人工统计。
5. **用 AI 像当保姆：** 不仅要现写提示词，还要手动粘贴大量信息喂给 AI，没有适配安全保障/安全运营场景，用起来比自己看还累。
6. **封禁两头受气，查名单费劲：** 怕误封业务背锅，怕漏封挨批，但每次去翻死板的黑白名单列表又极繁琐。
7. **设备各自为战，协同成孤岛：** 现场各类安全设备各管一摊，其内置的协助机制根本无法跨厂商互通，导致告警散落四处，缺少一个能统一处理、集中协作的“总指挥部”。

## 平台价值
+ **统一解析**：将不同设备、不同格式的原始日志转换为标准研判字段。
+ **资产关联**：统一化管理并关联资产、威胁情报、黑白名单、告警信息等内容。
+ **协作闭环**：内置监测组、研判组、处置组协作流程，支持认领、释放、强制解锁、状态流转和消息提醒。
+ **AI 增强**：内置 Agent 支持任务建模、证据检索、统计分析、结构化反思、模板生成和经验提取。
+ **可追踪**：每条告警都有独立 `alert_hash`，用于生命周期跟踪、搜索、审计和复盘。
+ **可复盘**：闭环告警可沉淀为 STE 经验，后续 AI 研判可检索并复用相似经验。
+ **可输出**：支持报告生成、消息模板、Excel 模板、CSV 模板、Webhook 和告警导出。

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
<img width="2978" height="1530" alt="image" src="https://github.com/user-attachments/assets/db169cc9-8035-4075-a8b5-5282f9ba0603" />
1.2、关联威胁情报、资产等信息
<img width="2954" height="1524" alt="image" src="https://github.com/user-attachments/assets/54736820-9d74-4243-9235-d1e2719b95aa" />
### 2、Agent自主规划并调用工具
2.1、具备规划、调用、反思等全链路思考的Agent
<img width="2922" height="1494" alt="image" src="https://github.com/user-attachments/assets/0b8ab31f-09da-434b-a485-47d23a189788" />
2.2、基于所有已知信息生成高可信的输出
<img width="2944" height="1540" alt="image" src="https://github.com/user-attachments/assets/cf8c7f4e-1134-484f-90a9-9d6f9c1b7710" />

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
EFF-Monitoring-2.1/
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
└── 操作手册.md              # 功能操作与最佳实践
```

## 快速启动
### Docker 一键部署
```bash
./scripts/compose-up.sh
```

脚本会自动选择 `docker compose`（Compose v2）或 `docker-compose`（Compose v1），并在缺少 `.env` 时从 `.env.example` 初始化。也可以手动执行：

```bash
cp .env.example .env
docker compose up -d --build
# 或旧版 Compose:
docker-compose up -d --build
```

默认访问地址：

+ 前端页面：`http://localhost:8080`

<!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/28328372/1779760276673-caeef1f8-9351-4246-a8a6-c4de59b78c71.png)

+ FastAPI 文档：`http://localhost:8000/docs`

<!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/28328372/1779760326253-e0659f93-9a9c-4e90-9305-9b9dc89534c5.png)

+ 后端 API：`http://localhost:8000`
+ 健康检查：`http://localhost:8000/healthz`

默认管理员账号：

> 管理员账号密码通过 `.env` 文件中的 `INITIAL_ADMIN_USERNAME` 和 `INITIAL_ADMIN_PASSWORD` 配置。
> 默认值（仅开发环境）：`admin / admin123`

生产环境务必修改 `.env` 中的所有安全相关配置（`JWT_SECRET`、`POSTGRES_PASSWORD`、`INITIAL_ADMIN_PASSWORD` 等），详见 `.env.example` 中的注释。

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
| 告警工作台 | Hash 搜索、认领机制、状态流转、AI 研判、威胁情报、闭环反馈、手动/自动刷新、服务端分页、CSV 导出 |
| AI 中心 | 提示词管理、AI 对话、执行链路/证据包查看、STE 经验库、AI 经验提取、AI 生成消息模板 |
| 资产中心 | 个体资产、网段资产、Excel 导入导出、资产指纹、负责人和区域维护 |
| 消息中心 | 工作流消息、未读提醒、按告警 Hash 快捷跳转 |
| 报告中心 | 报告新建、编辑、复制、导出 MD、删除，支持从模板和规则一键生成 |
| 规则中心 | 元规则、自定义规则、正则测试、设备规则适配、规则生成 |
| 模板中心 | 消息模板、Excel 模板、CSV 模板 |
| IP 名单 | 白名单、黑名单、CIDR/IP 范围检测、表格化维护、批量导入、名单导出 |
| 系统设置 | AI 模型网关、威胁情报、消息通知的全员配置与个人配置，支持连通性测试和模型列表获取 |
| 系统管理 | 用户、项目、设备、时间同步、审计日志、后台任务、历史导入 |


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
可通过AI对话问答方式了解平台安全事件信息，并进行辅助分析、报告编写等操作
<!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/28328372/1779762760530-6a233408-85e0-4ea1-a47b-c752a1d17ace.png)

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
<!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/28328372/1779763009423-5d75c0b1-952c-4658-9bd1-28d91288fb0b.png)

### 能力配置
适配常见大模型 API、威胁情报和消息通知，支持个人配置覆盖全员配置。消息通知按平台分别配置钉钉自定义机器人、企业微信群机器人、飞书自定义机器人，避免不同 Webhook 参数混用。
<img width="2978" height="1504" alt="image" src="https://github.com/user-attachments/assets/ad46d622-6ba1-42bc-b4fe-0ba994e7fc79" />


### 系统管理
支持成员、项目、设备、时间同步等管理功能，支持查看任务记录、审计日志。时间同步页显示应用时间、UTC 和服务器本地时间，页面时间会实时跳动。
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
+ AI：OpenAI-Compatible、OpenAI、DeepSeek、通义千问、智谱 AI、硅基流动、Ollama
+ Agent：LangGraph
+ 集成：威胁情报、Webhook、CSV / Excel 导出

## 可选演示数据
默认打包配置为 `ENABLE_DEMO_DATA=false`，首次启动只初始化系统默认规则、内置模板和管理员账号，不自动写入演示告警、演示资产、演示项目和演示用户。

如需快速验证平台能力，可在 `.env` 中设置：

```bash
ENABLE_DEMO_DATA=true
```

开启后，系统会自动初始化一组演示数据，便于快速验证功能：

+ 演示用户：`demo_analyst / demo_viewer` 等，密码通过 `DEMO_USER_PASSWORD` 环境变量配置（默认 `demo123456`）
+ 演示项目：攻防演练、日常运营
+ 演示设备：WAF、NDR、态势感知
+ 演示资产：门户、交易 API、数据库、办公终端、WebLogic 业务服务器、网段资产
+ 演示规则：通用规则、WAF/NDR 规则、态势感知日志解析规则
+ 演示模板：态势感知研判通报、Excel 行、CSV 资产导出
+ 演示告警：可验证资产命中、AI 研判、Hash 搜索、重复限制、运营总览和导出功能

演示日志中的公网 IP 使用文档保留地址段，不包含真实客户 IP。

## 更新记录
### v2.1.4
+ **系统时间管理**：系统管理新增“时间同步”页，可配置应用时区和 NTP 服务器列表；业务时间生成、默认今日统计、消息已读、告警认领和报表生成按应用时区执行，当前时间在页面实时跳动显示。
+ **告警工作台刷新增强**：新增手动刷新按钮和自动刷新开关，支持 30 秒、1 分钟、3 分钟、5 分钟刷新频率；告警列表改为服务端分页，适合每日数千告警的协作查看。
+ **IP 名单表格化**：IP 名单从文本框改为单条记录管理，支持新增、编辑、删除、批量删除、筛选、导出和批量导入，CIDR 与范围保留为规则条目，兼容告警流转与解析命中检测。
+ **消息通知增强**：消息通知改为按平台选择钉钉、企业微信、飞书，并分别维护 Webhook URL、签名 Secret、企业微信 @ 成员等专属参数；发送失败会返回第三方错误详情。
+ **部署兼容增强**：新增 `scripts/compose-up.sh`，自动兼容 Docker Compose v1/v2，降低不同 Linux 环境部署差异。

### v2.1.3
+ **设备规则/模板导入包**：系统管理的设备列表新增按设备导出、导入“规则/模板导入包”功能。导出包为 JSON，包含设备信息、该设备绑定的解析规则和模板。

### v2.1.2
+ **安全事件跟踪表导出增强**：系统内置 `安全事件跟踪表` CSV 模板，支持导出告警编号、事件ID、告警设备、攻击源/目的 IP、研判结果、封禁位置、处置描述等字段。
+ **设备类型与处置补充**：设备支持区分监测设备/封禁设备；封禁处置可选择封禁设备，应急处置可填写非必填处置描述。
+ **交付包默认无历史测试数据**：默认关闭演示数据初始化，交付目录不携带当前环境 Docker 数据卷。

### v2.1.1
+ **配置整合**：`.env` 作为唯一配置来源，`docker-compose.yml` 中所有密码/secrets 统一通过 `${VAR}` 引用，修改密码只需改 `.env` 一处。新增 `POSTGRES_PASSWORD`、`DEMO_USER_PASSWORD` 独立变量，演示用户密码改为可配置。
+ **Docker 兼容性修复**：`VITE_API_BASE_URL` 从根 `.env` 中移除（改为 `Dockerfile.frontend` 构建参数），不再注入后端容器导致 Pydantic `extra_forbidden` 校验崩溃。`docker-compose.yml` 兼容 Docker Compose v1（Python `docker-compose`）与 v2（Go `docker compose`）全版本。
+ **安全加固**：新增 `backend/app/core/startup.py` 启动校验模块，检测 JWT_SECRET / INITIAL_ADMIN_PASSWORD 是否使用不安全默认值。生产环境（PostgreSQL）下使用默认密码时在日志中输出 `=== SECURITY WARNING ===` 醒目告警。
+ **健康检查增强**：`/healthz` 和 `/readyz` 端点改为实际执行 `SELECT 1` 验证数据库连通性，数据库不可达时返回 `degraded`/`not_ready` 状态（`/readyz` 返回 HTTP 503）。
+ **启动可靠性**：后端容器新增 `docker/entrypoint.sh`，从 `DATABASE_URL` 解析 host:port 并轮询等待 PostgreSQL 就绪（最多 60 秒），避免数据库未就绪时容器反复重启。
+ **前端错误反馈**：系统管理页新增/编辑成员、项目、设备的 mutation 增加 `onError` 回调，API 失败时通过 `message.error()` 显示后端返回的具体错误信息。
+ **`.gitignore`**：新增防止 `.env` 等敏感文件被提交。

### v2.1
+ **新增报告中心**：支持新建、编辑、复制、导出 MD 和删除报告；支持从内容解析、运营总览等模块一键生成报告并保存。
+ **权限修复**：修复 viewer 只读用户可绕过前端直接调用写接口（规则创建、模板创建/编辑、配置修改、Webhook 发送）的安全漏洞。

### v2.0.1
+ **Agent 链路重构**：新增任务建模、证据覆盖检查、结构化反思和定向补查，问答更稳。
+ **系统设置升级**：支持 AI 连通性测试、模型列表获取，个人配置与全员配置隔离，密钥脱敏保存更安全。
+ **规则与部署修复**：解析规则支持 `match_all` 多命中提取。
+ **BUG修复**：修复一些使用上的小BUG。
