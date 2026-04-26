package performance

import (
	"encoding/json"
	"os"
	"testing"
)

func TestPerformanceRegression(t *testing.T) {
	baseline, err := LoadBaseline()
	if err != nil {
		if os.IsNotExist(err) {
			t.Skip("No baseline found. Run 'make bench-baseline' to create one.")
		}
		t.Fatalf("Failed to load baseline: %v", err)
	}

	resultsFile := getResultsDir() + "/" + ResultsFile
	data, err := os.ReadFile(resultsFile)
	if err != nil {
		t.Skip("No results found. Run 'make bench' first.")
	}

	var current map[string]BenchmarkResult
	if err := json.Unmarshal(data, &current); err != nil {
		t.Fatalf("Failed to unmarshal results: %v", err)
	}

	AssertNoCriticalRegression(t, baseline, current)

	regressions := CheckRegression(baseline, current)
	if len(regressions) > 0 {
		if err := GenerateReport(baseline, current, regressions); err != nil {
			t.Logf("Warning: failed to generate regression report: %v", err)
		}
	}
}

func TestBaselineExists(t *testing.T) {
	_, err := LoadBaseline()
	if err != nil {
		if os.IsNotExist(err) {
			t.Log("ℹ️  No baseline found. This is expected for first-time runs.")
			t.Log("   Run 'make bench-baseline' to create a baseline.")
			t.Skip("Skipping test - no baseline available")
		} else {
			t.Errorf("Failed to load baseline: %v", err)
		}
	} else {
		t.Log("✅ Baseline found and loaded successfully")
	}
}
