//go:build linux
// +build linux

package xdp

// Generate Go bindings for the BPF program / 为 BPF 程序生成 Go 绑定
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang NetXfw ../../bpf/netxfw.bpf.c -- -I../../bpf

/**
 * xdp.go is the main entry point for the xdp package.
 * It contains the go:generate directives and acts as the package descriptor.
 * Most implementation details are split into xdp_*.go files for better maintainability.
 *
 * xdp.go 是 xdp 包的主入口。
 * 它包含 go:generate 指令并作为包描述符。
 * 大多数实现细节已拆分到 xdp_*.go 文件中，以提高可维护性。
 */
