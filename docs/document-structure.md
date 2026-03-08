# 文档结构说明

## 📁 新的文档目录结构（英文名称）

```
docs/
├── README.md                           # 文档总索引（入口）
├── document-structure.md               # 文档结构说明（中文）
├── document-structure_en.md            # 文档结构说明（英文）
├── 01-getting-started/                 # 新手入门
│   ├── 01-00_document_guide.md            # 🌟 从这里开始！
│   ├── 01-01_project_introduction.md      # NetXFW 是什么
│   ├── 01-02_project_introduction_en.md
│   ├── index.md                        # 快速导航
│   └── 01-01_document_index.md            # 详细索引
│
├── 02-installation/                    # 安装部署
│   ├── 02-01_security_best_practices.md    # 安全配置建议
│   └── 02-01_security_best_practices_en.md
│
├── 03-quick-start/                     # 快速开始
│   ├── 03-01_cli.md                    # CLI 命令手册
│   ├── 03-01_cli_en.md
│   ├── 03-02_rule_import_export.md     # 规则批量管理
│   └── 03-02_rule_import_export_en.md
│
├── 04-configuration/                   # 配置管理
│   ├── 04-01_performance_tuning.md     # 性能调优
│   ├── 04-01_performance_tuning_en.md
│   ├── 04-02_bpf_map_capacity.md       # 容量配置
│   └── 04-02_bpf_map_capacity_en.md
│
├── 05-advanced-features/               # 高级功能
│   ├── 05-01_realip.md                 # 云环境真实 IP
│   ├── 05-01_realip_en.md
│   ├── 05-02_interface_specific_agent.md   # 接口特定模式
│   ├── 05-02_interface_specific_agent_en.md
│   ├── 05-03_log_engine.md             # 日志引擎
│   ├── 05-03_log_engine_en.md
│   ├── 05-04_dynamic_modules.md        # 动态模块顺序
│   ├── 05-04_dynamic_modules_en.md
│   ├── 05-05_health_check.md           # 健康检查系统
│   ├── 05-05_health_check_en.md
│   ├── 05-06_performance_monitoring.md # 性能监控
│   ├── 05-06_performance_monitoring_en.md
│   └── config_example.yaml             # 配置示例
│
├── 06-plugin-development/              # 插件开发
│   ├── 06-01_plugins.md                # 插件系统介绍
│   ├── 06-01_plugins_en.md
│   ├── 06-02_xdp_development_guide.md  # XDP 插件开发
│   └── 06-03_golang_development_guide.md   # Go 插件开发
│
├── 07-performance-tuning/              # 性能调优
│   ├── 07-01_benchmarks.md             # 性能测试
│   └── 07-01_benchmarks_en.md
│
├── 08-troubleshooting/                 # 故障排查
│   ├── 08-01_troubleshooting.md        # 问题诊断
│   └── 08-01_troubleshooting_en.md
│
├── 09-api-reference/                   # API 参考
│   ├── 09-01_config_management_unification.md  # 配置 API
│   ├── 09-01_config_management_unification_en.md
│   ├── 09-02_unified_web_api_metrics.md        # 监控 API
│   ├── 09-02_unified_web_api_metrics_en.md
│   ├── 09-03_api_reference.md          # REST API
│   ├── 09-03_api_reference_en.md
│   └── openapi.yaml                    # OpenAPI 规范
│
└── 10-appendix/                        # 附录
    ├── 10-01_architecture.md           # 系统架构
    ├── 10-01_architecture_en.md
    ├── 10-02_architecture_diagrams.md  # 架构图
    ├── 10-02_architecture_diagrams_en.md
    ├── 10-03_packet_filter_flow.md     # 数据包过滤流程
    ├── 10-04_summary_packet_filter.md
    ├── 10-05_testing.md                # 测试指南
    ├── 10-05_testing_en.md
    ├── 10-06_evaluation.md             # 项目评估
    └── 10-06_evaluation_en.md
```

---

## 🎯 重组原则

### 1. **使用英文目录名**
- 目录名称使用英文，符合技术项目惯例
- 保持与代码目录命名风格一致
- 便于命令行操作和脚本引用

### 2. **按功能模块划分**
- 不再按照数字编号，而是按照**功能用途**分类
- 每个目录都有明确的功能定位

### 3. **符合逻辑思维**
- **Getting Started** → 先了解项目
- **Installation** → 再安装系统
- **Quick Start** → 学习基本操作
- **Configuration** → 深入配置优化
- **Advanced Features** → 探索高级特性
- **Plugin Development** → 自定义扩展
- **Performance Tuning** → 优化性能
- **Troubleshooting** → 解决问题
- **API Reference** → 开发集成
- **Appendix** → 技术细节

### 4. **用户导向**
- 新增"文档导读"帮助用户快速定位
- 提供多种学习路径（普通用户、高级用户、开发者）
- 每个章节都有明确的目标读者和必读指数

### 5. **文件命名规范**
- 文件名格式：`目录编号-文件编号-描述.md`
- 例如：`01-00_document_guide.md`
- 保持目录编号与文件编号对齐

---

## 📊 文档分类

### 📘 01-getting-started (新手入门)
**目标读者**：所有用户
**内容**：项目介绍、快速导航、文档索引
**必读指数**：⭐⭐⭐⭐⭐

### 📗 02-installation (安装部署)
**目标读者**：首次安装用户
**内容**：安全配置、初始化步骤
**必读指数**：⭐⭐⭐⭐⭐

### 📙 03-quick-start (快速开始)
**目标读者**：日常运维人员
**内容**：CLI命令、规则管理
**必读指数**：⭐⭐⭐⭐

### 📕 04-configuration (配置管理)
**目标读者**：系统管理员
**内容**：容量配置、性能调优
**必读指数**：⭐⭐⭐⭐

### 📔 05-advanced-features (高级功能)
**目标读者**：高级用户、架构师
**内容**：云环境支持、日志引擎、动态模块、健康检查、性能监控
**必读指数**：⭐⭐⭐

### 📓 06-plugin-development (插件开发)
**目标读者**：开发者
**内容**：插件开发指南、API文档
**必读指数**：⭐⭐⭐

### 📖 07-performance-tuning (性能调优)
**目标读者**：性能工程师
**内容**：性能测试数据、优化建议
**必读指数**：⭐⭐⭐

### 📒 08-troubleshooting (故障排查)
**目标读者**：运维人员
**内容**：常见问题、解决方案
**必读指数**：⭐⭐⭐⭐

### 📚 09-api-reference (API参考)
**目标读者**：开发者、集成人员
**内容**：REST API、配置管理、监控指标
**必读指数**：⭐⭐⭐

### 📑 10-appendix (附录)
**目标读者**：技术人员、研究人员
**内容**：架构设计、技术细节、测试报告
**必读指数**：⭐⭐

---

## 📝 使用建议

### 对于新用户
1. 先阅读 `01-getting-started/01-00_document_guide.md`
2. 按照导读建议的路径学习
3. 遇到问题查看 `08-troubleshooting`

### 对于运维人员
1. 重点阅读 `03-quick-start` 和 `04-configuration`
2. 收藏 `08-troubleshooting` 作为参考
3. 参考 `07-performance-tuning` 优化系统

### 对于开发者
1. 阅读 `06-plugin-development` 了解开发流程
2. 参考 `09-api-reference` 进行集成
3. 查看 `10-appendix` 了解技术细节

---

## 💡 目录命名规范

- 使用小写字母
- 单词间用连字符分隔（kebab-case）
- 前缀数字编号表示顺序（01-, 02-, ...）
- 名称简洁明了，体现功能定位

示例：
- ✅ `01-getting-started`
- ✅ `02-installation`
- ❌ `01_GettingStarted` (驼峰命名)
- ❌ `installation_docs` (下划线命名)

---

## 📅 更新日期
- **2026-03-02**: 完成文档结构重组（使用英文名称）
- **2026-03-07**: 新增动态模块顺序、健康检查系统、性能监控文档
