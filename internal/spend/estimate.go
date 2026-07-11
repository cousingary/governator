package spend

import "strings"

// DefaultCostPerMTokUSD are conservative, deliberately pessimistic $/1M-token
// estimates keyed by backend name. They exist only to size a batch worker's
// pre-launch reservation (EstimateCostUSD) — they are never written to the
// ledger as cost_usd and never substitute for a backend's own reported cost.
// gov cost / gov spend / TodaySpend always read the real, backend-reported
// figure.
var DefaultCostPerMTokUSD = map[string]float64{
	"claude": 15.0, "claude-code": 15.0,
	"codex": 15.0, "glm": 3.0, "opencode": 15.0, "pi": 15.0,
}

// fallbackCostPerMTokUSD prices an unrecognized backend at the highest known
// rate rather than guessing low — an unmetered backend should shrink the
// batch's effective budget, not silently bypass the cap.
const fallbackCostPerMTokUSD = 15.0

// unboundedEstimateUSD is the flat per-job estimate used when a contract
// sets no budget.max_tokens ceiling (the field is optional; zero is a valid,
// common value). A job with no declared token ceiling still needs to
// reserve *something*, or a batch of unbounded jobs would never be
// throttled by the cap at all.
const unboundedEstimateUSD = 0.25

// unboundedQuotaTokens is the conservative subscription-window reservation
// when a contract omits budget.max_tokens. It intentionally differs from the
// dollar estimate above: quota windows track provider-plan usage units, so the
// reservation needs a token-shaped floor.
const unboundedQuotaTokens = 50000

func UnboundedQuotaTokens() int { return unboundedQuotaTokens }

// EstimateCostUSD conservatively estimates a job's worst-case cost from its
// budget.max_tokens ceiling and a per-backend $/1M-token table, for sizing a
// batch reservation before the job runs. Pass nil for rates to use
// DefaultCostPerMTokUSD.
func EstimateCostUSD(backend string, maxTokens int, rates map[string]float64) float64 {
	if maxTokens <= 0 {
		return unboundedEstimateUSD
	}
	if rates == nil {
		rates = DefaultCostPerMTokUSD
	}
	rate, ok := rates[strings.ToLower(strings.TrimSpace(backend))]
	if !ok {
		rate = fallbackCostPerMTokUSD
	}
	return float64(maxTokens) / 1_000_000.0 * rate
}
