# 文档结构说明

## 📁 新的文档目录结构（英文名称）

```
docs/
├── README.md                           # 文档总索引（入口）
├── document-structure.md               # 文档结构说明（本文档）
├── 01-getting-started/                 # 新手入门
│   ├── 01-00_document_guide.md            # 🌟 从这里开始！
│   ├── 01-01_project_introduction.md      # NetXFW 是什么
│   ├── 01-02_project_introduction_en.md
│   ├── index.md                        # 快速导航
│   └── 01-01_document_index.md            # 详细索引
│
├── 02-installation/                    # 安装部署
│   ├── 02-01_security_best_practices.md    # 安全配置建议
│   └── 02-02_security_best_practices_en.md
│
├── 03-quick-start/                     # 快速开始
│   ├── 03-01_cli.md                    # CLI 命令手册
│   ├── 03-02_cli_en.md
│   ├── 03-03_rule_import_export.md     # 规则批量管理
│   └── 03-04_rule_import_export_en.md
│
├── 04-configuration/                   # 配置管理
│   ├── 04-01_performance_tuning.md     # 性能调优
│   ├── 04-02_performance_tuning_en.md
│   ├── 04-03_bpf_map_capacity.md       # 容量配置
│   └── 04-04_bpf_map_capacity_en.md
│
├── 05-advanced-features/               # 高级功能
│   ├── 05-01_realip.md                 # 云环境真实 IP
│   ├── 05-02_realip_en.md
│   ├── 05-03_interface_specific_agent.md   # 接口特定模式
│   ├── 05-04_interface_specific_agent_en.md
│   ├── 05-05_log_engine.md             # 日志引擎
│   ├── 05-06_log_engine_en.md
│   └── config_example.yaml             # 配置示例
│
├── 06-plugin-development/              # 插件开发
│   ├── 06-01_plugins.md                # 插件系统介绍
│   ├── 06-02_plugins_en.md
│   ├── 06-03_xdp_development_guide.md  # XDP 插件开发
│   └── 06-04_golang_development_guide.md   # Go 插件开发
│
├── 07-performance-tuning/              # 性能调优
│   ├── 07-01_benchmarks.md             # 性能测试
│   └── 07-02_benchmarks_en.md
│
├── 08-troubleshooting/                 # 故障排查
│   ├── 08-01_troubleshooting.md        # 问题诊断
│   └── 08-02_troubleshooting_en.md
│
├── 09-api-reference/                   # API 参考
│   ├── 09-01_config_management_unification.md  # 配置 API
│   ├── 09-01_config_management_unification_en.md
│   ├── 09-02_unified_web_api_metrics.md        # 监控 API
│   ├── 09-02_unified_web_api_metrics_en.md
│   ├── 09-05_api_reference.md          # REST API
│   ├── 09-05_api_reference_en.md
│   └── openapi.yaml                    # OpenAPI 规范
│
└── 10-appendix/                        # 附录
    ├── 10-01_architecture.md           # 系统架构
    ├── 10-02_architecture_en.md
    ├── 10-03_architecture_diagrams.md  # 架构图
    ├── 10-03_architecture_diagrams_en.md
    ├── 10-04_packet_filter_flow.md     # 数据包过滤流程
    ├── 10-05_summary_packet_filter.md
    ├── 10-06_testing.md                # 测试指南
    ├── 10-07_testing_en.md
    ├── 10-08_evaluation.md             # 项目评估
    └── 10-09_evaluation_en.md
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
**内容**：云环境支持、日志引擎
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

---

# Document Structure Documentation

## 📁 New Documentation Directory Structure (English Names)

```
docs/
├── README.md                           # Documentation Index (Entry)
├── document-structure.md               # Document Structure Documentation (This File)
├── 01-getting-started/                 # Getting Started
│   ├── 01-00_document_guide.md            # 🌟 Start Here!
│   ├── 01-01_project_introduction.md      # What is NetXFW
│   ├── 01-02_project_introduction_en.md
│   ├── index.md                        # Quick Navigation
│   └── 01-01_document_index.md            # Detailed Index
│
├── 02-installation/                    # Installation
│   ├── 02-01_security_best_practices.md    # Security Configuration
│   └── 02-02_security_best_practices_en.md
│
├── 03-quick-start/                     # Quick Start
│   ├── 03-01_cli.md                    # CLI Command Manual
│   ├── 03-02_cli_en.md
│   ├── 03-03_rule_import_export.md     # Batch Rule Management
│   └── 03-04_rule_import_export_en.md
│
├── 04-configuration/                   # Configuration Management
│   ├── 04-01_performance_tuning.md     # Performance Tuning
│   ├── 04-02_performance_tuning_en.md
│   ├── 04-03_bpf_map_capacity.md       # Capacity Configuration
│   └── 04-04_bpf_map_capacity_en.md
│
├── 05-advanced-features/               # Advanced Features
│   ├── 05-01_realip.md                 # Real IP in Cloud
│   ├── 05-02_realip_en.md
│   ├── 05-03_interface_specific_agent.md   # Interface Specific Mode
│   ├── 05-04_interface_specific_agent_en.md
│   ├── 05-05_log_engine.md             # Log Engine
│   ├── 05-06_log_engine_en.md
│   └── config_example.yaml             # Configuration Example
│
├── 06-plugin-development/              # Plugin Development
│   ├── 06-01_plugins.md                # Plugin System Overview
│   ├── 06-02_plugins_en.md
│   ├── 06-03_xdp_development_guide.md  # BPF/XDP Plugin Development
│   └── 06-04_golang_development_guide.md   # Go Plugin Development
│
├── 07-performance-tuning/              # Performance Tuning
│   ├── 07-01_benchmarks.md             # Performance Testing
│   └── 07-02_benchmarks_en.md
│
├── 08-troubleshooting/                 # Troubleshooting
│   ├── 08-01_troubleshooting.md        # Problem Diagnosis
│   └── 08-02_troubleshooting_en.md
│
├── 09-api-reference/                   # API Reference
│   ├── 09-01_config_management_unification.md  # Configuration API
│   ├── 09-01_config_management_unification_en.md
│   ├── 09-02_unified_web_api_metrics.md        # Monitoring API
│   ├── 09-02_unified_web_api_metrics_en.md
│   ├── 09-05_api_reference.md          # REST API
│   ├── 09-05_api_reference_en.md
│   └── openapi.yaml                    # OpenAPI Specification
│
└── 10-appendix/                        # Appendix
    ├── 10-01_architecture.md           # System Architecture
    ├── 10-02_architecture_en.md
    ├── 10-03_architecture_diagrams.md  # Architecture Diagrams
    ├── 10-03_architecture_diagrams_en.md
    ├── 10-04_packet_filter_flow.md     # Packet Filter Flow
    ├── 10-05_summary_packet_filter.md
    ├── 10-06_testing.md                # Testing Guide
    ├── 10-07_testing_en.md
    ├── 10-08_evaluation.md             # Project Evaluation
    └── 10-09_evaluation_en.md
```

---

## 🎯 Reorganization Principles

### 1. **Use English Directory Names**
- Directory names use English, following technical project conventions
- Consistent with code directory naming style
- Easy for command-line operations and script references

### 2. **Organize by Function Modules**
- No longer numbered by digits, but categorized by **functional purpose**
- Each directory has a clear functional definition

### 3. **Follow Logical Thinking**
- **Getting Started** → First understand the project
- **Installation** → Then install the system
- **Quick Start** → Learn basic operations
- **Configuration** → Deep dive into configuration optimization
- **Advanced Features** → Explore advanced features
- **Plugin Development** → Custom extensions
- **Performance Tuning** → Optimize performance
- **Troubleshooting** → Solve problems
- **API Reference** → Development integration
- **Appendix** → Technical details

### 4. **User-Oriented**
- Added "Documentation Guide" to help users quickly locate content
- Provides multiple learning paths (basic users, advanced users, developers)
- Each section has clear target audience descriptions

### 5. **File Naming Convention**
- File naming format: `Directory Number-File Number-Description.md`
- Example: `01-00_document_guide.md`
- Keep directory number aligned with file number

---

## 📊 Document Classification

### 📘 01-getting-started (Getting Started)
**Target Audience**: All users
**Content**: Project introduction, quick navigation, documentation index
**Must-Read Index**: ⭐⭐⭐⭐⭐

### 📗 02-installation (Installation)
**Target Audience**: First-time installation users
**Content**: Security configuration, initialization steps
**Must-Read Index**: ⭐⭐⭐⭐⭐

### 📙 03-quick-start (Quick Start)
**Target Audience**: Daily operation and maintenance personnel
**Content**: CLI commands, rule management
**Must-Read Index**: ⭐⭐⭐⭐

### 📕 04-configuration (Configuration Management)
**Target Audience**: System administrators
**Content**: Capacity configuration, performance tuning
**Must-Read Index**: ⭐⭐⭐⭐

### 📔 05-advanced-features (Advanced Features)
**Target Audience**: Advanced users, architects
**Content**: Cloud environment support, log engine
**Must-Read Index**: ⭐⭐⭐

### 📓 06-plugin-development (Plugin Development)
**Target Audience**: Developers
**Content**: Plugin development guide, API documentation
**Must-Read Index**: ⭐⭐⭐

### 📖 07-performance-tuning (Performance Tuning)
**Target Audience**: Performance engineers
**Content**: Performance test data, optimization suggestions
**Must-Read Index**: ⭐⭐⭐

### 📒 08-troubleshooting (Troubleshooting)
**Target Audience**: Operation and maintenance personnel
**Content**: Common problems, solutions
**Must-Read Index**: ⭐⭐⭐⭐

### 📚 09-api-reference (API Reference)
**Target Audience**: Developers, integration personnel
**Content**: REST API, configuration management, monitoring metrics
**Must-Read Index**: ⭐⭐⭐

### 📑 10-appendix (Appendix)
**Target Audience**: Technical personnel, researchers
**Content**: Architecture design, technical details, testing reports
**Must-Read Index**: ⭐⭐

---

## 📝 Usage Recommendations

### For New Users
1. First read `01-getting-started/01-00_document_guide.md`
2. Follow the learning path suggested in the guide
3. Check `08-troubleshooting` when encountering problems

### For Operation and Maintenance Personnel
1. Focus on reading `03-quick-start` and `04-configuration`
2. Keep `08-troubleshooting` as a reference
3. Refer to `07-performance-tuning` for system optimization

### For Developers
1. Read `06-plugin-development` to understand the development process
2. Refer to `09-api-reference` for integration
3. Check `10-appendix` for technical details

---

## 💡 Directory Naming Convention

- Use lowercase letters
- Separate words with hyphens (kebab-case)
- Prefix with numbers to indicate order (01-, 02-, ...)
- Names should be concise and clearly reflect functional positioning

Examples:
- ✅ `01-getting-started`
- ✅ `02-installation`
- ❌ `01_GettingStarted` (camelCase)
- ❌ `installation_docs` (underscore naming)

---

## 📅 Update Date
- **2026-03-02**: Documentation structure reorganization completed (using English names)
