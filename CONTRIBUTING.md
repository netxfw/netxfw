# Contributing to netxfw

Thank you for your interest in contributing to `netxfw`! We welcome contributions from everyone, whether it's bug reports, feature requests, documentation improvements, or code contributions.

## Prerequisites

Before you start, ensure you have the following tools installed:

*   **Go**: Version 1.22 or later.
*   **Clang/LLVM**: Version 11 or later (required for compiling BPF programs).
*   **Make**: Standard build tool.
*   **Linux Kernel Headers**: Required for BPF compilation (`linux-headers-$(uname -r)`).

## Development Workflow

1.  **Fork** the repository on GitHub.
2.  **Clone** your fork locally:
    ```bash
    git clone https://github.com/your-username/netxfw.git
    cd netxfw
    ```
3.  **Create a Branch** for your changes:
    ```bash
    git checkout -b feature/my-new-feature
    ```
4.  **Make Changes**: Write your code and tests.
5.  **Build**:
    ```bash
    make build
    ```
    To verify BPF compilation (if modifying C code):
    ```bash
    make generate
    ```

## Testing

Integration tests require `root` privileges because they interact with BPF maps.

Run the CLI integration test suite:
```bash
sudo test/integration/cli/run_tests.sh
```

Ensure all tests pass before submitting a Pull Request.

## Code Style

*   **Go**: Run `go fmt ./...` before committing.
*   **C (BPF)**: Follow standard Linux kernel coding style where applicable.

## Commit Messages

We encourage the use of [Conventional Commits](https://www.conventionalcommits.org/):

*   `feat: add support for ...`
*   `fix: resolve issue with ...`
*   `docs: update README for ...`
*   `test: add integration test for ...`

## Submitting a Pull Request

1.  Push your changes to your fork.
2.  Open a Pull Request against the `main` branch of the original repository.
3.  Provide a clear description of the changes and link any related issues.

## Reporting Issues

If you find a bug or have a feature request, please open an issue on the repository issue tracker. Provide as much detail as possible, including:
*   Netxfw version (`netxfw version`)
*   Kernel version (`uname -r`)
*   Steps to reproduce
