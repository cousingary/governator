package spend

import "testing"

func TestEstimateCostUSDUsesBackendRate(t *testing.T) {
	got := EstimateCostUSD("glm", 1_000_000, nil)
	if got != 3.0 {
		t.Fatalf("glm estimate = %v, want 3.0", got)
	}
	got = EstimateCostUSD("claude-code", 500_000, nil)
	if got != 7.5 {
		t.Fatalf("claude-code estimate = %v, want 7.5", got)
	}
}

func TestEstimateCostUSDFallsBackForUnknownBackend(t *testing.T) {
	got := EstimateCostUSD("some-new-backend", 1_000_000, nil)
	if got != fallbackCostPerMTokUSD {
		t.Fatalf("unknown backend estimate = %v, want %v", got, fallbackCostPerMTokUSD)
	}
}

func TestEstimateCostUSDUnboundedJobUsesFlatEstimate(t *testing.T) {
	got := EstimateCostUSD("glm", 0, nil)
	if got != unboundedEstimateUSD {
		t.Fatalf("unbounded estimate = %v, want %v", got, unboundedEstimateUSD)
	}
}

func TestEstimateCostUSDHonorsCustomRates(t *testing.T) {
	rates := map[string]float64{"custom": 100.0}
	got := EstimateCostUSD("custom", 10_000, rates)
	if got != 1.0 {
		t.Fatalf("custom rate estimate = %v, want 1.0", got)
	}
}
