//go:build linux
// +build linux

package xdp

// Generate Go bindings for the BPF program / 为 BPF 程序生成 Go 绑定
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang NetXfw ../../bpf/netxfw.bpf.c -- -I../../bpf

/*
 * NetXFW XDP Manager
 * NetXFW XDP 管理器
 *
 * This file contains the main entry point for the XDP manager.
 * Most implementation details are split into xdp_*.go files for maintainability.
 * 此文件包含 XDP 管理器的主要入口点。
 * 大多数实现细节已拆分到 xdp_*.go 文件中，以提高可维护性。
 */
