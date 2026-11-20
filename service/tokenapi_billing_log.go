package service

import (
	"os"

	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/pkg/billingexpr"
	"github.com/QuantumNous/new-api/relaykit/dto"
)

// BuildTieredTokenParams preserves retail normalization and optionally captures
// independent procurement components with the same upstream normalizer.
func BuildTieredTokenParams(usage *dto.Usage, isClaudeUsageSemantic bool, usedVars map[string]bool) billingexpr.TokenParams {
	params := buildTieredTokenParams(usage, isClaudeUsageSemantic, usedVars)
	return withTokenAPICostTokens(params, usage, isClaudeUsageSemantic)
}

func withTokenAPICostTokens(params billingexpr.TokenParams, usage *dto.Usage, isClaudeUsageSemantic bool) billingexpr.TokenParams {
	if os.Getenv("TOKENAPI_BILLING_LOG_ENABLED") == "true" {
		cost := buildTieredTokenParams(usage, isClaudeUsageSemantic, map[string]bool{
			"p": true, "c": true, "len": true,
			"cr": true, "cc": true, "cc1h": true, "cc12h": true,
			"img": true, "img_cr": true, "img_o": true, "ai": true, "ao": true,
		})
		params.CostTokens = &cost
	}
	return params
}

// Realtime retail settlement uses aggregate P/C inputs. Preserve that contract
// while retaining the separate upstream component details for procurement.
func tokenAPIRealtimeBillingParams(usage *dto.RealtimeUsage, params billingexpr.TokenParams) billingexpr.TokenParams {
	return withTokenAPICostTokens(params, &dto.Usage{
		PromptTokens: usage.InputTokens, CompletionTokens: usage.OutputTokens,
		PromptTokensDetails: usage.InputTokenDetails, CompletionTokenDetails: usage.OutputTokenDetails,
	}, false)
}

func injectTokenAPICostTokens(other *model.LogOther, result *billingexpr.TieredResult) {
	if os.Getenv("TOKENAPI_BILLING_LOG_ENABLED") != "true" || result == nil || result.BillingTokens == nil {
		return
	}
	tokens := result.BillingTokens.CostTokens
	if tokens == nil {
		return
	}
	other.SetPublic("cost_tokens", map[string]float64{
		"p": tokens.P, "c": tokens.C, "len": tokens.Len,
		"cr": tokens.CR, "cc": tokens.CC, "cc1h": tokens.CC1h, "cc12h": tokens.CC12h,
		"img": tokens.Img, "img_cr": tokens.ImgCR, "img_o": tokens.ImgO,
		"ai": tokens.AI, "ao": tokens.AO,
	})
}
