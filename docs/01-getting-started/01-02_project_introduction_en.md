# NetXFW Documentation

Welcome to the NetXFW documentation. This directory contains all documentation for the NetXFW project, organized by category.

---

## Document Navigation

### Quick Start
- [Standalone Installation & Configuration](../02-installation/02-02_security_best_practices_en.md) - Quick deployment and basic configuration
- [CLI Manual](../03-quick-start/03-02_cli_en.md) - CLI command reference and usage examples

### Architecture & Design
- [Architecture Overview](../10-appendix/10-02_architecture_en.md) - System architecture design
- [Standalone Architecture](../10-appendix/10-03_architecture_diagrams_en.md) - Detailed standalone architecture
- [Packet Filter Flow](../10-appendix/10-04_packet_filter_flow.md) - Packet processing flow

### Development & Extension
- [Plugin Development Guide](../06-plugin-development/06-02_plugins_en.md) - Plugin development framework and interfaces
- [XDP Plugin Development](../06-plugin-development/06-03_xdp_development_guide.md) - XDP layer plugin development
- [Go Plugin Development](../06-plugin-development/06-04_golang_development_guide.md) - Go language plugin development
- [API Reference](../09-api-reference/09-05_api_reference_en.md) - API interface reference
- [Rule Import/Export](../03-quick-start/03-04_rule_import_export_en.md) - Rule import/export feature

### Performance & Monitoring
- [Performance Benchmarks](../07-performance-tuning/07-02_benchmarks_en.md) - Performance test data and benchmarks
- [Web API Metrics Unification](../09-api-reference/09-02_unified_web_api_metrics_en.md) - Unified Web API metrics design

### Cloud Environment & Special Scenarios
- [Real IP in Cloud](../05-advanced-features/05-02_realip_en.md) - Getting real client IP in cloud environments
- [Interface-specific Agent Mode](../05-advanced-features/05-04_interface_specific_agent_en.md) - Agent mode for specific interfaces

### System Management
- [Config Management Unification](../09-api-reference/09-01_config_management_unification_en.md) - Unified configuration management
- [Testing Guide](../10-appendix/10-07_testing_en.md) - Testing methods and procedures
- [Log Engine](../05-advanced-features/05-06_log_engine_en.md) - Log processing engine

### Project Evaluation
- [Project Evaluation Report](../10-appendix/10-09_evaluation_en.md) - Detailed project evaluation report

---

## Directory Structure

| Directory | Description |
|-----------|-------------|
| [01-getting-started/](../) | Getting started documentation |
| [02-installation/](../02-installation/) | Installation documentation |
| [03-quick-start/](../03-quick-start/) | Quick start documentation |
| [04-configuration/](../04-configuration/) | Configuration documentation |
| [05-advanced-features/](../05-advanced-features/) | Advanced features documentation |
| [06-plugin-development/](../06-plugin-development/) | Plugin development documentation |
| [07-performance-tuning/](../07-performance-tuning/) | Performance tuning documentation |
| [08-troubleshooting/](../08-troubleshooting/) | Troubleshooting documentation |
| [09-api-reference/](../09-api-reference/) | API reference documentation |
| [10-appendix/](../10-appendix/) | Appendix documentation |

---

## Bilingual Documentation

We provide bilingual documentation for different user groups:

| Document Type | Chinese | English |
|---------------|---------|---------|
| Architecture | [10-01_architecture.md](../10-appendix/10-01_architecture.md) | [10-02_architecture_en.md](../10-appendix/10-02_architecture_en.md) |
| CLI Commands | [03-01_cli.md](../03-quick-start/03-01_cli.md) | [03-02_cli_en.md](../03-quick-start/03-02_cli_en.md) |
| Plugin Development | [06-01_plugins.md](../06-plugin-development/06-01_plugins.md) | [06-02_plugins_en.md](../06-plugin-development/06-02_plugins_en.md) |
| Rule Import/Export | [03-03_rule_import_export.md](../03-quick-start/03-03_rule_import_export.md) | [03-04_rule_import_export_en.md](../03-quick-start/03-04_rule_import_export_en.md) |
| Performance Benchmarks | [07-01_benchmarks.md](../07-performance-tuning/07-01_benchmarks.md) | [07-02_benchmarks_en.md](../07-performance-tuning/07-02_benchmarks_en.md) |
| Cloud Support | [05-01_realip.md](../05-advanced-features/05-01_realip.md) | [05-02_realip_en.md](../05-advanced-features/05-02_realip_en.md) |
| Project Evaluation | [10-08_evaluation.md](../10-appendix/10-08_evaluation.md) | [10-09_evaluation_en.md](../10-appendix/10-09_evaluation_en.md) |
| Feature Docs | [05-03_interface_specific_agent.md](../05-advanced-features/05-03_interface_specific_agent.md) | [05-04_interface_specific_agent_en.md](../05-advanced-features/05-04_interface_specific_agent_en.md) |
| BPF Map Capacity | [04-03_bpf_map_capacity.md](../04-configuration/04-03_bpf_map_capacity.md) | [04-04_bpf_map_capacity_en.md](../04-configuration/04-04_bpf_map_capacity_en.md) |
| Config Management | [09-01_config_management_unification.md](../09-api-reference/09-01_config_management_unification.md) | [09-01_config_management_unification_en.md](../09-api-reference/09-01_config_management_unification_en.md) |
| Testing Guide | [10-06_testing.md](../10-appendix/10-06_testing.md) | [10-07_testing_en.md](../10-appendix/10-07_testing_en.md) |
| Log Engine | [05-05_log_engine.md](../05-advanced-features/05-05_log_engine.md) | [05-06_log_engine_en.md](../05-advanced-features/05-06_log_engine_en.md) |
| Troubleshooting | [08-01_troubleshooting.md](../08-troubleshooting/08-01_troubleshooting.md) | [08-02_troubleshooting_en.md](../08-troubleshooting/08-02_troubleshooting_en.md) |
| Performance Tuning | [04-01_performance_tuning.md](../04-configuration/04-01_performance_tuning.md) | [04-02_performance_tuning_en.md](../04-configuration/04-02_performance_tuning_en.md) |
| Security Best Practices | [02-01_security_best_practices.md](../02-installation/02-01_security_best_practices.md) | [11-02_security_best_practices_en.md](../02-installation/02-02_security_best_practices_en.md) |

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
| Troubleshooting | ✅ | ✅ | Complete |
| Performance Tuning | ✅ | ✅ | Complete |
| Security Best Practices | ✅ | ✅ | Complete |

---

## Quick Start

1. **Getting Started**: Start with [Getting Started Documentation](../01-getting-started/) for basic concepts and deployment
2. **Daily Operations**: Refer to [CLI Manual](../03-quick-start/03-02_cli_en.md) for daily management
3. **Deep Customization**: Implement feature extensions via [Plugin Development Guide](../06-plugin-development/06-02_plugins_en.md)
4. **Performance Tuning**: Check [Performance Benchmarks](../07-performance-tuning/07-02_benchmarks_en.md) to optimize system performance
5. **Cloud Deployment**: Refer to [Cloud Documentation](../05-advanced-features/) for cloud environment configuration
