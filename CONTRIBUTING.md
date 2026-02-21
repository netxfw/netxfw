# 贡献指南

感谢您对 `netxfw` 感兴趣！我们欢迎任何形式的贡献，无论是提交 Bug 报告、功能建议、文档改进还是代码提交。

## 准备工作

在开始之前，请确保您的环境中安装了以下工具：

*   **Go**: 版本 1.22 或更高。
*   **Clang/LLVM**: 版本 11 或更高（编译 BPF 程序需要）。
*   **Make**: 标准构建工具。
*   **Linux Kernel Headers**: BPF 编译需要 (`linux-headers-$(uname -r)`)。

## 开发流程

1.  **Fork** 本仓库到您的 GitHub 账户。
2.  **Clone** 您的 Fork 到本地：
    ```bash
    git clone https://github.com/your-username/netxfw.git
    cd netxfw
    ```
3.  **创建分支** (Branch) 进行开发：
    ```bash
    git checkout -b feature/my-new-feature
    ```
4.  **修改代码**: 编写代码和测试。
5.  **构建**:
    ```bash
    make build
    ```
    如果您修改了 C 代码，请验证 BPF 编译：
    ```bash
    make generate
    ```

## 测试

集成测试需要 `root` 权限，因为它们需要与 BPF Map 进行交互。

运行 CLI 集成测试套件：
```bash
sudo test/integration/cli/run_tests.sh
```

在提交 Pull Request 之前，请确保所有测试通过。

## 代码风格

*   **Go**: 提交前请运行 `go fmt ./...`。
*   **C (BPF)**: 尽可能遵循标准的 Linux 内核代码风格。
