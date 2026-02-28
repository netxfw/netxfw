//go:build ignore

// Package main contains hybrid approval verification tests.
// Package main 包含混合审批验证测试。
//
// This file is excluded from normal builds and tests.
// Use: go run verify_hybrid_approval.go
// 此文件从正常构建和测试中排除。
// 使用方法: go run verify_hybrid_approval.go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"time"
)

// baseURL is the base URL for the API server.
// baseURL 是 API 服务器的基础 URL。
const baseURL = "http://localhost:11818/api"

func main() {
	fmt.Println("[TEST] Testing Hybrid Approval (Auto-Active) Workflow...")

	// 1. Test Manual Add with AutoActive = true
	// 1. 测试手动添加，且 AutoActive = true
	testManualAutoActive()

	// 2. Test External Alert with AutoActive = true (Simulating Falco/Analyzer)
	// 2. 测试外部告警，且 AutoActive = true（模拟 Falco/分析器）
	testExternalAutoActive()

	// 3. Test Manual Add with AutoActive = false (Pending)
	// 3. 测试手动添加，且 AutoActive = false（待审批）
	testManualPending()

	fmt.Println("\n✅ Hybrid Approval tests completed.")
}

// testManualAutoActive tests manual add with auto_active=true.
// testManualAutoActive 测试手动添加且 auto_active=true。
func testManualAutoActive() {
	fmt.Println("\n--- Scenario 1: Manual Add with AutoActive=true ---")
	// 场景 1：手动添加，AutoActive=true
	payload := map[string]any{
		"ip":          "1.1.1.1",
		"reason":      "Test manual auto-active",
		"auto_active": true,
	}
	resp := post("/rules/crisis", payload)
	fmt.Printf("Response: %s\n", resp)
}

// testExternalAutoActive tests external alert with auto_active=true.
// testExternalAutoActive 测试外部告警且 auto_active=true。
func testExternalAutoActive() {
	fmt.Println("\n--- Scenario 2: External Alert with AutoActive=true ---")
	// 场景 2：外部告警，AutoActive=true
	payload := map[string]any{
		"type":        "blacklist",
		"instance":    "2.2.2.2",
		"reason":      "Simulated attack from analyzer",
		"source":      "traffic-analyzer",
		"auto_active": true,
	}
	resp := post("/alerts/external", payload)
	fmt.Printf("Response: %s\n", resp)
}

// testManualPending tests manual add with auto_active=false (pending approval).
// testManualPending 测试手动添加且 auto_active=false（待审批）。
func testManualPending() {
	fmt.Println("\n--- Scenario 3: Manual Add with AutoActive=false (Pending) ---")
	// 场景 3：手动添加，AutoActive=false（待审批）
	payload := map[string]any{
		"ip":          "3.3.3.3",
		"reason":      "Test manual pending",
		"auto_active": false,
	}
	resp := post("/rules/crisis", payload)
	fmt.Printf("Response: %s\n", resp)
}

// post is a helper function to send POST requests to the API.
// post 是一个向 API 发送 POST 请求的辅助函数。
func post(path string, data any) string {
	b, err := json.Marshal(data)
	if err != nil {
		return fmt.Sprintf("JSON marshal error: %v", err)
	}

	req, err := http.NewRequest("POST", baseURL+path, bytes.NewBuffer(b))
	if err != nil {
		return fmt.Sprintf("Request creation error: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Note: In a real test we'd need a token if Auth is enabled.
	// 注意：在真实测试中，如果启用了认证，我们需要一个令牌。
	// For this local verification, we assume Auth might be disabled or we use a bypass if possible.
	// 对于此本地验证，我们假设认证可能已禁用，或者我们尽可能使用绕过方式。

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Sprintf("Error: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Sprintf("Read body error: %v", err)
	}
	return string(body)
}
