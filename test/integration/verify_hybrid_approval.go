package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

const baseURL = "http://localhost:11818/api"

func main() {
	fmt.Println("🧪 Testing Hybrid Approval (Auto-Active) Workflow...")

	// 1. Test Manual Add with AutoActive = true
	testManualAutoActive()

	// 2. Test External Alert with AutoActive = true (Simulating Falco/Analyzer)
	testExternalAutoActive()

	// 3. Test Manual Add with AutoActive = false (Pending)
	testManualPending()

	fmt.Println("\n✅ Hybrid Approval tests completed.")
}

func testManualAutoActive() {
	fmt.Println("\n--- Scenario 1: Manual Add with AutoActive=true ---")
	payload := map[string]interface{}{
		"ip":          "1.1.1.1",
		"reason":      "Test manual auto-active",
		"auto_active": true,
	}
	resp := post("/rules/crisis", payload)
	fmt.Printf("Response: %s\n", resp)
}

func testExternalAutoActive() {
	fmt.Println("\n--- Scenario 2: External Alert with AutoActive=true ---")
	payload := map[string]interface{}{
		"type":        "blacklist",
		"instance":    "2.2.2.2",
		"reason":      "Simulated attack from analyzer",
		"source":      "traffic-analyzer",
		"auto_active": true,
	}
	resp := post("/alerts/external", payload)
	fmt.Printf("Response: %s\n", resp)
}

func testManualPending() {
	fmt.Println("\n--- Scenario 3: Manual Add with AutoActive=false (Pending) ---")
	payload := map[string]interface{}{
		"ip":          "3.3.3.3",
		"reason":      "Test manual pending",
		"auto_active": false,
	}
	resp := post("/rules/crisis", payload)
	fmt.Printf("Response: %s\n", resp)
}

func post(path string, data interface{}) string {
	b, _ := json.Marshal(data)
	req, _ := http.NewRequest("POST", baseURL+path, bytes.NewBuffer(b))
	req.Header.Set("Content-Type", "application/json")

	// Note: In a real test we'd need a token if Auth is enabled.
	// For this local verification, we assume Auth might be disabled or we use a bypass if possible.
	// Since I'm running this, I'll check if auth is enabled in the default config.

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Sprintf("Error: %v", err)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	return string(body)
}
