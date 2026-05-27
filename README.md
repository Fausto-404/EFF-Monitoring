<h1 align="center">EFF-Monitoring 安全运营协作平台</h1>

<div align="center">

![Release](https://img.shields.io/github/v/release/Fausto-404/EFF-Monitoring)
![Stars](https://img.shields.io/github/stars/Fausto-404/EFF-Monitoring)
![Forks](https://img.shields.io/github/forks/Fausto-404/EFF-Monitoring)
![Issues](https://img.shields.io/github/issues/Fausto-404/EFF-Monitoring)
![downloads](https://img.shields.io/github/downloads/Fausto-404/EFF-Monitoring/latest/total)

</div>

EFF-Monitoring（Efficient Monitoring，高效监控）是一款以内置 Agent 为核心的安全运营协作平台。平台围绕安全事件全生命周期，提供日志解析、资产关联、AI研判、处置流转、经验沉淀与报告输出等能力，通过证据驱动的分析与协同机制，帮助安全团队快速看懂告警、定位风险、联动上下游并提升处置效率。

---

**<font style="color:#000000;background-color:#FBF5CB;">详细功能操作与最佳实践请查看：</font>**[**<font style="color:#000000;background-color:#FBF5CB;">操作手册.md</font>**](./操作手册.md)

## 引言
使用这个平台前，可以先想想您的场景是否有以下痛点:

1. **时间断节，写报告难：**发现和封禁没有精确时间记录，写复盘报告时全凭记忆倒推，费时费力。
2. **疯狂切窗口，研判效率低：**查情报、对资产、找负责人，要在好几个 Excel 、平台之间来回切换。
3. **纯手工 CV，机械重复：**确认一条高危，要重复复制粘贴到 Word 模板、防守台账 Excel 和微信工作群。
4. **汇报全靠人肉凑：**日报、周报、成效报告数据无法一键生成，每到交报告节点，只能加班人工统计。
5. **用 AI 像当保姆：**不仅要现写提示词，还要手动粘贴大量信息喂给 AI，没有适配安全保障/安全运营场景，用起来比自己看还累。
6. **封禁两头受气，查名单费劲：**怕误封业务背锅，怕漏封挨批，但每次去翻死板的黑白名单列表又极繁琐。
7. **设备各自为战，协同成孤岛：**现场各类安全设备各管一摊，其内置的协助机制根本无法跨厂商互通，导致告警散落四处，缺少一个能统一处理、集中协作的“总指挥部”。

## 平台价值
+ **统一解析**：将不同设备、不同格式的原始日志转换为标准研判字段。
+ **资产关联**：统一化管理并关联资产、威胁情报、黑白名单、告警信息等内容。
+ **协作闭环**：内置监测组、研判组、处置组协作流程，支持认领、释放、强制解锁、状态流转和消息提醒。
+ **AI 增强**：内置具备所有查询能力的Agent助力问题答疑、研判、模板生成、经验提取。
+ **可追踪**：每条告警都有独立 `alert_hash`，用于生命周期跟踪、搜索、审计和复盘。
+ **可复盘**：闭环告警可沉淀为 STE 经验，后续 AI 研判可检索并复用相似经验。
+ **可输出**：支持报告生成、消息模板、Excel 模板、CSV 模板、Webhook 和告警导出。

## 适用场景
### 对应场景
+ 攻防演练期间快速同步、研判和分发安全事件。
+ SOC 值守人员统一处理来自态势感知、WAF、NDR、IPS 等设备的告警。
+ 需要把告警与资产、负责人、区域、重要性和处置结果打通的企业安全团队。
+ 需要积累可复用研判经验，并让 AI 持续吸收闭环结果的团队。
+ 需要把安全告警规范化输出到群机器人、报表、CSV 或 Excel 的运营场景。

### 对应效果
+ 将单个告警的研判流程，如：填写模板、查询威胁情报、查询黑白名单、查找对应资产、发送给AI分析、工单流转的耗时从平均3～5分钟压缩至了秒级
+ 将重保日报、周报的数据统计流程缩短至秒级，自动生成初稿台账，大幅度降低拼凑、去重、统计数据的负担。
+ 将复盘报告时间线梳理流程简化为系统内置的时间轴审计，数据留痕完整，省去了人工倒推、核对各个节点时间戳的对账时间。
+ 将高危 IP 处置与名单管控流程的执行时间压缩至秒级，通过前置校验，防止了由于漏看白名单导致的误封、重复上报同一封禁IP的问题。
+ 将跨组协同与状态流转流程的确认时间缩短至 1～2 分钟内，通过系统的认领和锁定机制，避免了责任划分不清、沟通时间消耗过高的问题。
+ 将打通误报审计与知识闭环流程，发现误报后可以反向同步原因，告警闭环后可以进行AI经验提取，提高人工/AI后续对同类特征的研判准确度。

## 核心亮点
### 日志到告警的完整数据链路
<!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/28328372/1779761999718-bb47057c-9f3d-4d43-b355-fd20f4c4c398.png)

### 告警闭环与分组协作机制
<!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/28328372/1779764135445-c1674106-9e43-4d6c-bf4c-debd1a56694e.png)

### AI Agent P-E-R 执行链路
<!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/28328372/1779760614522-4765dbc7-45dd-4b66-9578-ba978ed36e1d.png)

## 项目目录
```latex
EFF-Monitoring-2.0/
├── backend/                 # 后端服务代码
│   ├── app/api              # REST API 路由
│   ├── app/core             # 配置与安全
│   ├── app/models           # ORM 模型、数据库和启动逻辑
│   ├── app/schemas          # Pydantic 请求/响应 schema
│   ├── app/services         # 业务逻辑服务
│   └── app/workers          # Worker 入口
├── core/                    # 日志解析、IP 名单、威胁情报核心能力
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
cp .env.example .env
docker compose up -d --build
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

```latex
admin / admin123
```

生产环境务必修改 `.env` 中的 `JWT_SECRET`、`INITIAL_ADMIN_PASSWORD`、`DATABASE_URL`、`REDIS_URL` 和 Webhook/AI/威胁情报密钥。

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
| 日志解析 | 原始日志解析、资产命中、IP 名单检测、模板输出、保存告警 |
| 告警工作台 | Hash 搜索、认领机制、状态流转、AI 研判、威胁情报、闭环反馈、CSV 导出 |
| AI 中心 | 提示词管理、AI 对话、Agent 工具查询、STE 经验库、AI 经验提取、AI 生成消息模板 |
| 资产中心 | 个体资产、网段资产、Excel 导入导出、资产指纹、负责人和区域维护 |
| 消息中心 | 工作流消息、未读提醒、按告警 Hash 快捷跳转 |
| 规则中心 | 元规则、自定义规则、正则测试、设备规则适配、规则生成 |
| 模板中心 | 消息模板、Excel 模板、CSV 模板 |
| IP 名单 | 白名单、黑名单、CIDR/IP 范围检测、名单导出 |
| 能力配置 | AI、威胁情报、Webhook 的全员配置与个人配置 |
| 系统管理 | 用户、项目、设备、审计日志、后台任务、历史导入 |


## 界面预览
### 运营总览
<!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/28328372/1779762676402-950e56ff-29fc-43c9-9b30-5671c67d7743.png)

### 日志解析
<!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/28328372/1779762559396-21a82d94-fb78-4aae-8b4e-21e016add271.png)

### 告警工作台
<!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/28328372/1779762589395-57be5a18-8881-4304-a042-4f6f3844d127.png)

### AI 中心
<!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/28328372/1779762760530-6a233408-85e0-4ea1-a47b-c752a1d17ace.png)

### 资产中心
<!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/28328372/1779762740740-b54b16bd-fd9e-458c-b3cb-1d7ed1fcf189.png)

### 消息中心
<!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/28328372/1779762798116-03ccbc85-5656-4c5a-bcae-140ef128e5fa.png)

### 规则中心
<!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/28328372/1779765125867-f2089574-0ead-4407-92cd-97302c24aa43.png)

### 模板中心
<!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/28328372/1779762995697-4db2dacd-2e06-4e57-9b8e-162addb47448.png)

### IP 名单
<!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/28328372/1779763009423-5d75c0b1-952c-4658-9bd1-28d91288fb0b.png)

### 能力配置
<!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/28328372/1779768070080-703a77e5-a86b-42a6-98ec-0d7f75e9c42f.png)

### 系统管理
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

## 内置演示数据
初始化后会保留一组演示数据，便于快速验证功能：

+ 演示用户：`demo_analyst / demo123456`、`demo_viewer / demo123456`
+ 演示项目：攻防演练、日常运营
+ 演示设备：WAF、NDR、态势感知
+ 演示资产：门户、交易 API、数据库、办公终端、WebLogic 业务服务器、网段资产
+ 演示规则：通用规则、WAF/NDR 规则、态势感知日志解析规则
+ 演示模板：态势感知研判通报、Excel 行、CSV 资产导出
+ 演示告警：可验证资产命中、AI 研判、Hash 搜索、重复限制、运营总览和导出功能

演示日志中的公网 IP 使用文档保留地址段，不包含真实客户 IP。



