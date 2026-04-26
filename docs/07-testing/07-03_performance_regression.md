# 性能回归测试框架

## 概述

NetXFW 性能回归测试框架用于检测代码变更导致的性能退化。它通过比较基准性能数据和当前性能数据，自动识别性能回归。

## 快速开始

### 1. 创建性能基线

```bash
make bench-baseline
```

这将：
- 运行所有基准测试
- 保存结果到 `~/.netxfw/benchmarks/baseline.json`
- 创建性能基线供后续比较

### 2. 运行性能回归测试

```bash
make bench-regression
```

这将：
- 运行当前基准测试
- 与基线比较
- 生成回归报告

### 3. 运行快速基准测试

```bash
make bench
```

仅运行基准测试，不进行回归检测。

## 工作原理

### 架构

```
┌─────────────────────────────────────────────────────────────┐
│                  性能回归测试流程                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. 创建基线                                                │
│     ┌──────────────┐                                        │
│     │ 运行基准测试 │                                        │
│     └──────┬───────┘                                        │
│            │                                                │
│            ▼                                                │
│     ┌──────────────┐                                        │
│     │ 保存基线数据 │ baseline.json                          │
│     └──────────────┘                                        │
│                                                             │
│  2. 回归检测                                                │
│     ┌──────────────┐                                        │
│     │ 运行基准测试 │                                        │
│     └──────┬───────┘                                        │
│            │                                                │
│            ▼                                                │
│     ┌──────────────┐                                        │
│     │ 保存当前数据 │ results.json                           │
│     └──────┬───────┘                                        │
│            │                                                │
│            ▼                                                │
│     ┌──────────────┐                                        │
│     │  比较数据    │                                        │
│     └──────┬───────┘                                        │
│            │                                                │
│            ▼                                                │
│     ┌──────────────┐                                        │
│     │ 生成报告     │ regression_report.json                 │
│     └──────────────┘                                        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 回归阈值

- **警告阈值**: 20% 性能下降
- **严重阈值**: 50% 性能下降

### 文件结构

```
~/.netxfw/benchmarks/
├── baseline.json           # 性能基线数据
├── results.json            # 当前测试结果
├── regression_report.json  # 回归分析报告
└── bench_output.txt        # 原始基准测试输出
```

## 使用场景

### 1. CI/CD 集成

在 CI 流程中检测性能回归：

```yaml
# .github/workflows/performance.yml
name: Performance Tests

on: [push, pull_request]

jobs:
  performance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.24'
      
      - name: Load baseline
        run: |
          mkdir -p ~/.netxfw/benchmarks
          # 从缓存加载基线
          if [ -f baseline.json ]; then
            cp baseline.json ~/.netxfw/benchmarks/
          fi
      
      - name: Run regression tests
        run: make bench-regression
      
      - name: Save baseline
        run: |
          if [ -f ~/.netxfw/benchmarks/results.json ]; then
            cp ~/.netxfw/benchmarks/results.json baseline.json
          fi
      
      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: performance-results
          path: ~/.netxfw/benchmarks/
```

### 2. 发布前检查

在发布新版本前验证性能：

```bash
# 1. 创建发布分支的基线
git checkout release-v2.1
make bench-baseline

# 2. 合并开发分支
git merge develop

# 3. 检查性能回归
make bench-regression

# 4. 查看报告
cat ~/.netxfw/benchmarks/regression_report.json
```

### 3. 优化验证

验证性能优化效果：

```bash
# 1. 创建优化前的基线
make bench-baseline

# 2. 应用优化代码
git checkout optimize-map-operations

# 3. 运行回归测试（应该显示性能提升）
make bench-regression
```

## 编写基准测试

### 示例：添加新的基准测试

```go
// test/performance/my_benchmark_test.go
package performance

import (
    "testing"
    "github.com/netxfw/netxfw/internal/utils/iputil"
)

func BenchmarkIPValidation(b *testing.B) {
    testIPs := []string{
        "192.168.1.1",
        "10.0.0.1",
        "invalid",
    }
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        ip := testIPs[i%len(testIPs)]
        _ = iputil.IsValidIP(ip)
    }
    
    // 保存结果用于回归检测
    if b.N > 0 {
        nsPerOp := float64(b.Elapsed().Nanoseconds()) / float64(b.N)
        SaveBenchmarkResult("IPValidation", nsPerOp, 0, 0)
    }
}
```

### 最佳实践

1. **使用有意义的名称**
   ```go
   // ✅ 好
   SaveBenchmarkResult("MapLookup_10000Entries", nsPerOp, 0, 0)
   
   // ❌ 避免
   SaveBenchmarkResult("test1", nsPerOp, 0, 0)
   ```

2. **测试真实场景**
   ```go
   // ✅ 测试实际使用场景
   func BenchmarkRealWorldScenario(b *testing.B) {
       // 模拟真实负载
       manager := setupManager()
       ips := generateRealisticIPs(10000)
       
       b.ResetTimer()
       for i := 0; i < b.N; i++ {
           manager.BlockIP(ips[i%len(ips)], 0)
       }
   }
   ```

3. **避免微优化**
   ```go
   // ❌ 避免测试过于简单的操作
   func BenchmarkAddition(b *testing.B) {
       for i := 0; i < b.N; i++ {
           _ = i + 1
       }
   }
   ```

## 报告解读

### 回归报告示例

```json
{
  "timestamp": "2026-04-25T10:30:00Z",
  "results": {
    "IPParsing": {
      "name": "IPParsing",
      "ns_per_op": 125.5,
      "timestamp": "2026-04-25T10:30:00Z",
      "git_commit": "abc123"
    }
  },
  "baseline": {
    "IPParsing": {
      "name": "IPParsing",
      "ns_per_op": 100.0,
      "timestamp": "2026-04-24T10:00:00Z",
      "git_commit": "def456"
    }
  },
  "regressions": [
    {
      "name": "IPParsing",
      "baseline_ns": 100.0,
      "current_ns": 125.5,
      "regression_pct": 25.5,
      "severity": "warning"
    }
  ]
}
```

### 严重程度

- **warning**: 性能下降 20-50%
- **critical**: 性能下降 > 50%

## 故障排查

### 常见问题

1. **没有基线数据**
   ```
   Error: No baseline found
   ```
   **解决方案**: 运行 `make bench-baseline` 创建基线

2. **测试结果不稳定**
   ```
   Warning: High variance in results
   ```
   **解决方案**: 
   - 关闭其他进程
   - 使用专用测试机器
   - 增加测试迭代次数

3. **回归检测失败**
   ```
   Critical performance regression detected
   ```
   **解决方案**:
   - 检查最近的代码变更
   - 使用 `git bisect` 定位问题提交
   - 查看详细报告了解具体回归

## 高级用法

### 自定义阈值

```bash
# 设置自定义阈值
export REGRESSION_THRESHOLD=10.0
export CRITICAL_THRESHOLD=30.0
make bench-regression
```

### 指定测试目录

```bash
# 使用自定义目录
export NETXFW_BENCH_DIR=/path/to/benchmarks
make bench-regression
```

### 仅测试特定功能

```bash
# 仅测试 IP 相关基准
go test -bench=IP -run=^$ ./test/performance/...
```

## 相关文件

- [test/performance/regression.go](../../test/performance/regression.go) - 回归检测核心逻辑
- [test/performance/baseline_test.go](../../test/performance/baseline_test.go) - 基准测试示例
- [scripts/bench_regression.sh](../../scripts/bench_regression.sh) - 回归测试脚本
- [Makefile](../../Makefile) - 构建目标定义

## 参考资料

- [Go Testing Package](https://pkg.go.dev/testing)
- [Go Benchmark Guidelines](https://dave.cheney.net/2013/06/30/how-to-write-benchmarks-in-go)
- [Performance Testing Best Practices](https://github.com/golang/go/wiki/Performance)
