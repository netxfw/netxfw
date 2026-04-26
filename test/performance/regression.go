package performance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type BenchmarkResult struct {
	Name        string  `json:"name"`
	NsPerOp     float64 `json:"ns_per_op"`
	AllocsPerOp uint64  `json:"allocs_per_op"`
	BytesPerOp  int64   `json:"bytes_per_op"`
	Timestamp   string  `json:"timestamp"`
	GitCommit   string  `json:"git_commit"`
}

type RegressionReport struct {
	Timestamp   string                     `json:"timestamp"`
	Results     map[string]BenchmarkResult `json:"results"`
	Baseline    map[string]BenchmarkResult `json:"baseline"`
	Regressions []RegressionDetail         `json:"regressions"`
}

type RegressionDetail struct {
	Name          string  `json:"name"`
	BaselineNs    float64 `json:"baseline_ns"`
	CurrentNs     float64 `json:"current_ns"`
	RegressionPct float64 `json:"regression_pct"`
	Severity      string  `json:"severity"`
}

const (
	RegressionThreshold = 20.0
	CriticalThreshold   = 50.0
	BaselineFile        = "baseline.json"
	ResultsFile         = "results.json"
	ReportFile          = "regression_report.json"
)

func SaveBenchmarkResult(name string, nsPerOp float64, allocsPerOp uint64, bytesPerOp int64) error {
	resultsDir := getResultsDir()
	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		return fmt.Errorf("failed to create results directory: %w", err)
	}

	gitCommit := getGitCommit()
	result := BenchmarkResult{
		Name:        name,
		NsPerOp:     nsPerOp,
		AllocsPerOp: allocsPerOp,
		BytesPerOp:  bytesPerOp,
		Timestamp:   time.Now().Format(time.RFC3339),
		GitCommit:   gitCommit,
	}

	resultsFile := filepath.Join(resultsDir, ResultsFile)
	var results map[string]BenchmarkResult
	if data, err := os.ReadFile(resultsFile); err == nil {
		json.Unmarshal(data, &results)
	} else {
		results = make(map[string]BenchmarkResult)
	}

	results[name] = result

	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results: %w", err)
	}

	return os.WriteFile(resultsFile, data, 0644)
}

func LoadBaseline() (map[string]BenchmarkResult, error) {
	baselineFile := filepath.Join(getResultsDir(), BaselineFile)
	data, err := os.ReadFile(baselineFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to read baseline file: %w", err)
	}

	var baseline map[string]BenchmarkResult
	if err := json.Unmarshal(data, &baseline); err != nil {
		return nil, fmt.Errorf("failed to unmarshal baseline: %w", err)
	}

	return baseline, nil
}

func SaveBaseline(results map[string]BenchmarkResult) error {
	resultsDir := getResultsDir()
	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		return fmt.Errorf("failed to create results directory: %w", err)
	}

	baselineFile := filepath.Join(resultsDir, BaselineFile)
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal baseline: %w", err)
	}

	return os.WriteFile(baselineFile, data, 0644)
}

func CheckRegression(baseline, current map[string]BenchmarkResult) []RegressionDetail {
	var regressions []RegressionDetail

	for name, currentResult := range current {
		baselineResult, exists := baseline[name]
		if !exists {
			continue
		}

		regressionPct := ((currentResult.NsPerOp - baselineResult.NsPerOp) / baselineResult.NsPerOp) * 100

		if regressionPct > RegressionThreshold {
			severity := "warning"
			if regressionPct > CriticalThreshold {
				severity = "critical"
			}

			regressions = append(regressions, RegressionDetail{
				Name:          name,
				BaselineNs:    baselineResult.NsPerOp,
				CurrentNs:     currentResult.NsPerOp,
				RegressionPct: regressionPct,
				Severity:      severity,
			})
		}
	}

	return regressions
}

func GenerateReport(baseline, current map[string]BenchmarkResult, regressions []RegressionDetail) error {
	report := RegressionReport{
		Timestamp:   time.Now().Format(time.RFC3339),
		Results:     current,
		Baseline:    baseline,
		Regressions: regressions,
	}

	reportFile := filepath.Join(getResultsDir(), ReportFile)
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}

	return os.WriteFile(reportFile, data, 0644)
}

func getResultsDir() string {
	if dir := os.Getenv("NETXFW_BENCH_DIR"); dir != "" {
		return dir
	}
	return filepath.Join(os.Getenv("HOME"), ".netxfw", "benchmarks")
}

func getGitCommit() string {
	if commit := os.Getenv("GIT_COMMIT"); commit != "" {
		return commit
	}
	return "unknown"
}

func AssertNoCriticalRegression(t *testing.T, baseline, current map[string]BenchmarkResult) {
	regressions := CheckRegression(baseline, current)

	for _, reg := range regressions {
		if reg.Severity == "critical" {
			t.Errorf("Critical performance regression detected in %s: %.2f%% slower (%.2f ns/op -> %.2f ns/op)",
				reg.Name, reg.RegressionPct, reg.BaselineNs, reg.CurrentNs)
		}
	}

	if len(regressions) > 0 {
		t.Logf("Performance regressions detected: %d", len(regressions))
		for _, reg := range regressions {
			t.Logf("  - %s: %.2f%% slower (severity: %s)", reg.Name, reg.RegressionPct, reg.Severity)
		}
	}
}
