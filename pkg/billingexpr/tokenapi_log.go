package billingexpr

import "os"

// captureTokenAPIBillingLog preserves the exact successful settlement inputs.
// It must not rerun normalization or change any charge, tier, or snapshot.
func captureTokenAPIBillingLog(result *TieredResult, params TokenParams, snap *BillingSnapshot) {
	if os.Getenv("TOKENAPI_BILLING_LOG_ENABLED") == "true" && !snap.TaskUsageBilling {
		result.BillingTokens = &params
	}
}
