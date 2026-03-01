# NetXFW Documentation

Welcome to the NetXFW documentation. This directory contains all documentation for the NetXFW project, organized by category.

---

## Document Navigation

### Quick Start
- [Standalone Installation & Configuration](./standalone/) - Quick deployment and basic configuration
- [CLI Manual](./cli/03-01_cli_en.md) - CLI command reference and usage examples

### Architecture & Design
- [Architecture Overview](./02-02_architecture_en.md) - System architecture design
- [Standalone Architecture](./standalone/02-03_architecture_diagrams_en.md) - Detailed standalone architecture
- [Packet Filter Flow](./standalone/02-04_PACKET_FILTER_FLOW.md) - Packet processing flow

### Development & Extension
- [Plugin Development Guide](./plugins/04-02_plugins_en.md) - Plugin development framework and interfaces
- [XDP Plugin Development](./plugins/xdp/04-03_xdp_development_guide.md) - XDP layer plugin development
- [Go Plugin Development](./plugins/golang/04-04_golang_development_guide.md) - Go language plugin development
- [API Reference](./api/04-05_api_reference_en.md) - API interface reference
- [Rule Import/Export](./03-04_rule_import_export_en.md) - Rule import/export feature

### Performance & Monitoring
- [Performance Benchmarks](./performance/06-02_benchmarks_en.md) - Performance test data and benchmarks
- [Web API Metrics Unification](./07-02_unified_web_api_metrics_en.md) - Unified Web API metrics design

### Cloud Environment & Special Scenarios
- [Real IP in Cloud](./cloud/05-02_realip_en.md) - Getting real client IP in cloud environments
- [Interface-specific Agent Mode](./features/05-04_interface_specific_agent_en.md) - Agent mode for specific interfaces

### System Management
- [Config Management Unification](./07-01_config_management_unification_en.md) - Unified configuration management
- [Testing Guide](./testing/07-04_TESTING_en.md) - Testing methods and procedures
- [Log Engine](./log-engine/07-03_log_engine_en.md) - Log processing engine

### Project Evaluation
- [Project Evaluation Report](./08-02_evaluation_en.md) - Detailed project evaluation report

---

## Directory Structure

| Directory | Description |
|-----------|-------------|
| [standalone/](./standalone/) | Standalone deployment and configuration |
| [cluster/](./cluster/) | Cluster documentation (in development) |
| [api/](./api/) | API reference documentation |
| [cli/](./cli/) | Command-line tool documentation |
| [plugins/](./plugins/) | Plugin development documentation |
| [testing/](./testing/) | Testing documentation |
| [performance/](./performance/) | Performance benchmarks and testing |
| [cloud/](./cloud/) | Cloud environment support |
| [features/](./features/) | Feature documentation |
| [log-engine/](./log-engine/) | Log engine documentation |

---

## Bilingual Documentation

We provide bilingual documentation for different user groups:

| Document Type | Chinese | English |
|---------------|---------|---------|
| Architecture | [02-01_architecture.md](./02-01_architecture.md) | [02-02_architecture_en.md](./02-02_architecture_en.md) |
| CLI Commands | [cli/03-01_cli.md](./cli/03-01_cli.md) | [cli/03-02_cli_en.md](./cli/03-02_cli_en.md) |
| Plugin Development | [plugins/04-01_plugins.md](./plugins/04-01_plugins.md) | [plugins/04-02_plugins_en.md](./plugins/04-02_plugins_en.md) |
| Rule Import/Export | [03-03_rule_import_export.md](./03-03_rule_import_export.md) | [03-04_rule_import_export_en.md](./03-04_rule_import_export_en.md) |
| Performance Benchmarks | [performance/06-01_benchmarks.md](./performance/06-01_benchmarks.md) | [performance/06-02_benchmarks_en.md](./performance/06-02_benchmarks_en.md) |
| Cloud Support | [cloud/05-01_realip.md](./cloud/05-01_realip.md) | [cloud/05-02_realip_en.md](./cloud/05-02_realip_en.md) |
| Project Evaluation | [08-01_evaluation.md](./08-01_evaluation.md) | [08-02_evaluation_en.md](./08-02_evaluation_en.md) |
| Feature Docs | [features/05-03_interface_specific_agent.md](./features/05-03_interface_specific_agent.md) | [features/05-04_interface_specific_agent_en.md](./features/05-04_interface_specific_agent_en.md) |
| BPF Map Capacity | [06-03_bpf_map_capacity.md](./06-03_bpf_map_capacity.md) | [06-04_bpf_map_capacity_en.md](./06-04_bpf_map_capacity_en.md) |

---

## Document Status

| Category | Chinese | English | Completeness |
|----------|---------|---------|--------------|
| Architecture | ✅ | ✅ | Complete |
| CLI Commands | ✅ | ✅ | Complete |
| Plugin Development | ✅ | ✅ | Complete |
| Rule Import/Export | ✅ | ✅ | Complete |
| API Reference | ✅ | ✅ | Complete |
| Performance Benchmarks | ✅ | ✅ | Complete |
| Cloud Support | ✅ | ✅ | Complete |
| Project Evaluation | ✅ | ✅ | Complete |
| Testing Guide | ✅ | ✅ | Complete |
| Log Engine | ✅ | ✅ | Complete |
| Config Management | ✅ | ✅ | Complete |

---

## Quick Start

1. **Getting Started**: Start with [Standalone Documentation](./standalone/) for basic concepts and deployment
2. **Daily Operations**: Refer to [CLI Manual](./cli/03-01_cli_en.md) for daily management
3. **Deep Customization**: Implement feature extensions via [Plugin Development Guide](./plugins/04-02_plugins_en.md)
4. **Performance Tuning**: Check [Performance Benchmarks](./performance/06-02_benchmarks_en.md) to optimize system performance
5. **Cloud Deployment**: Refer to [Cloud Documentation](./cloud/) for cloud environment configuration
