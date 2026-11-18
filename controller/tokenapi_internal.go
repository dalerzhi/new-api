package controller

import (
	"errors"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting/ratio_setting"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type tokenAPIFields struct {
	Name               *string `json:"name"`
	Group              *string `json:"group"`
	ModelLimitsEnabled *bool   `json:"model_limits_enabled"`
	ModelLimits        *string `json:"model_limits"`
	AllowIPs           *string `json:"allow_ips"`
	ExpiredTime        *int64  `json:"expired_time"`
	RemainQuota        *int    `json:"remain_quota"`
	UnlimitedQuota     *bool   `json:"unlimited_quota"`
	Status             *int    `json:"status"`
}

func tokenAPIError(c *gin.Context, err error) {
	status, message := http.StatusServiceUnavailable, "Internal operation unavailable"
	if errors.Is(err, model.ErrTokenAPIInvalid) || errors.Is(err, model.ErrWalletQuotaLimitExceeded) {
		status, message = http.StatusBadRequest, "Invalid internal request"
	} else if errors.Is(err, gorm.ErrRecordNotFound) {
		status, message = http.StatusNotFound, "Internal resource not found"
	}
	c.AbortWithStatusJSON(status, gin.H{"success": false, "message": message})
}

func tokenAPIBody(c *gin.Context, destination any, fields ...string) error {
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 1024*1024+1))
	if err != nil || len(body) > 1024*1024 {
		return model.ErrTokenAPIInvalid
	}
	var raw map[string]common.RawMessage
	if err := common.Unmarshal(body, &raw); err != nil || raw == nil {
		return model.ErrTokenAPIInvalid
	}
	for key, value := range raw {
		if !slices.Contains(fields, key) || string(value) == "null" {
			return model.ErrTokenAPIInvalid
		}
	}
	if err := common.Unmarshal(body, destination); err != nil {
		return model.ErrTokenAPIInvalid
	}
	return nil
}

func tokenAPIID(c *gin.Context, name string) (int, error) {
	value, err := strconv.Atoi(c.Param(name))
	if err != nil || value <= 0 {
		return 0, model.ErrTokenAPIInvalid
	}
	return value, nil
}

func (fields tokenAPIFields) apply(token *model.Token, create bool) error {
	if create && (fields.Name == nil || fields.Group == nil || fields.Status != nil) {
		return model.ErrTokenAPIInvalid
	}
	if fields.Name != nil {
		token.Name = *fields.Name
	}
	if fields.Group != nil {
		token.Group = *fields.Group
	}
	if fields.ModelLimitsEnabled != nil {
		token.ModelLimitsEnabled = *fields.ModelLimitsEnabled
	}
	if fields.ModelLimits != nil {
		token.ModelLimits = *fields.ModelLimits
	}
	if fields.AllowIPs != nil {
		token.AllowIps = fields.AllowIPs
	}
	if fields.ExpiredTime != nil {
		token.ExpiredTime = *fields.ExpiredTime
	}
	if fields.RemainQuota != nil {
		token.RemainQuota = *fields.RemainQuota
	}
	if fields.UnlimitedQuota != nil {
		token.UnlimitedQuota = *fields.UnlimitedQuota
	}
	if fields.Status != nil {
		token.Status = *fields.Status
	}
	if (create || fields.Name != nil) && (strings.TrimSpace(token.Name) == "" || len(token.Name) > 50) {
		return model.ErrTokenAPIInvalid
	}
	if (create || fields.Group != nil) && (token.Group == "auto" || !ratio_setting.ContainsGroupRatio(token.Group)) {
		return model.ErrTokenAPIInvalid
	}
	if fields.ModelLimits != nil && len(token.ModelLimits) > 4096 {
		return model.ErrTokenAPIInvalid
	}
	if fields.RemainQuota != nil && (token.RemainQuota < 0 || token.RemainQuota > maxTokenQuota()) {
		return model.ErrTokenAPIInvalid
	}
	if fields.ExpiredTime != nil && token.ExpiredTime != -1 && token.ExpiredTime <= common.GetTimestamp() {
		return model.ErrTokenAPIInvalid
	}
	if fields.Status != nil && token.Status != common.TokenStatusEnabled && token.Status != common.TokenStatusDisabled {
		return model.ErrTokenAPIInvalid
	}
	if fields.Status != nil && token.Status == common.TokenStatusEnabled && ((token.ExpiredTime != -1 && token.ExpiredTime <= common.GetTimestamp()) || (!token.UnlimitedQuota && token.RemainQuota <= 0)) {
		return model.ErrTokenAPIInvalid
	}
	if fields.ModelLimitsEnabled != nil && token.ModelLimitsEnabled && strings.TrimSpace(token.ModelLimits) == "" {
		return model.ErrTokenAPIInvalid
	}
	if fields.AllowIPs != nil && token.AllowIps != nil {
		if len(*token.AllowIps) > 4096 {
			return model.ErrTokenAPIInvalid
		}
		for line := range strings.SplitSeq(*token.AllowIps, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if _, err := netip.ParseAddr(line); err != nil {
				if _, err := netip.ParsePrefix(line); err != nil {
					return model.ErrTokenAPIInvalid
				}
			}
		}
	}
	return nil
}

func (fields tokenAPIFields) columns() []string {
	columns := make([]string, 0, 9)
	for _, field := range []struct {
		name     string
		provided bool
	}{
		{"name", fields.Name != nil}, {"group", fields.Group != nil},
		{"model_limits_enabled", fields.ModelLimitsEnabled != nil}, {"model_limits", fields.ModelLimits != nil},
		{"allow_ips", fields.AllowIPs != nil}, {"expired_time", fields.ExpiredTime != nil},
		{"remain_quota", fields.RemainQuota != nil}, {"unlimited_quota", fields.UnlimitedQuota != nil},
		{"status", fields.Status != nil},
	} {
		if field.provided {
			columns = append(columns, field.name)
		}
	}
	return columns
}

func TokenAPITokens(c *gin.Context) {
	uid, err := tokenAPIID(c, "uid")
	if err != nil {
		tokenAPIError(c, err)
		return
	}
	if _, err := model.GetUserById(uid, false); err != nil {
		tokenAPIError(c, err)
		return
	}
	if c.Request.Method == http.MethodGet {
		page, size := 1, 100
		if value := c.Query("page"); value != "" {
			page, err = strconv.Atoi(value)
		}
		if err != nil || page < 1 || page > 100000 {
			tokenAPIError(c, model.ErrTokenAPIInvalid)
			return
		}
		if value := c.Query("size"); value != "" {
			size, err = strconv.Atoi(value)
		}
		if err != nil || size < 1 || size > 500 {
			tokenAPIError(c, model.ErrTokenAPIInvalid)
			return
		}
		tokens, err := model.GetAllUserTokens(uid, (page-1)*size, size)
		if err != nil {
			tokenAPIError(c, err)
			return
		}
		total, err := model.CountUserTokens(uid)
		if err != nil {
			tokenAPIError(c, err)
			return
		}
		common.ApiSuccess(c, gin.H{"items": buildMaskedTokenResponses(tokens), "total": total, "page": page, "size": size})
		return
	}
	var fields tokenAPIFields
	if err := tokenAPIBody(c, &fields, "name", "group", "model_limits_enabled", "model_limits", "allow_ips", "expired_time", "remain_quota", "unlimited_quota", "status"); err != nil {
		tokenAPIError(c, err)
		return
	}
	key, err := common.GenerateKey()
	if err != nil {
		tokenAPIError(c, err)
		return
	}
	token := model.Token{UserId: uid, Key: key, Status: common.TokenStatusEnabled, ExpiredTime: -1, CreatedTime: common.GetTimestamp(), AccessedTime: common.GetTimestamp()}
	if err := fields.apply(&token, true); err != nil {
		tokenAPIError(c, err)
		return
	}
	err = model.CreateTokenAPIToken(c.Request.Context(), &token)
	if err != nil {
		tokenAPIError(c, err)
		return
	}
	common.ApiSuccess(c, gin.H{"id": token.Id, "key": token.GetFullKey()})
}

func TokenAPIToken(c *gin.Context) {
	uid, err := tokenAPIID(c, "uid")
	if err != nil {
		tokenAPIError(c, err)
		return
	}
	tid, err := tokenAPIID(c, "tid")
	if err != nil {
		tokenAPIError(c, err)
		return
	}
	token, err := model.GetTokenByIds(tid, uid)
	if err != nil {
		tokenAPIError(c, err)
		return
	}
	if c.Request.Method == http.MethodDelete {
		if err := token.Delete(); err != nil {
			tokenAPIError(c, err)
			return
		}
		common.ApiSuccess(c, nil)
		return
	}
	var fields tokenAPIFields
	if err := tokenAPIBody(c, &fields, "name", "group", "model_limits_enabled", "model_limits", "allow_ips", "expired_time", "remain_quota", "unlimited_quota", "status"); err != nil {
		tokenAPIError(c, err)
		return
	}
	if err := fields.apply(token, false); err != nil {
		tokenAPIError(c, err)
		return
	}
	if err := model.UpdateTokenAPIToken(c.Request.Context(), token, fields.columns()); err != nil {
		tokenAPIError(c, err)
		return
	}
	common.ApiSuccess(c, buildMaskedTokenResponse(token))
}

func TokenAPIQuota(c *gin.Context) {
	if strings.HasSuffix(c.FullPath(), "/batch-get") {
		var request struct {
			UserIDs []int `json:"user_ids"`
		}
		if err := tokenAPIBody(c, &request, "user_ids"); err != nil {
			tokenAPIError(c, err)
			return
		}
		if len(request.UserIDs) == 0 || len(request.UserIDs) > 500 {
			tokenAPIError(c, model.ErrTokenAPIInvalid)
			return
		}
		items := make([]*model.TokenAPIQuotaSnapshot, 0, len(request.UserIDs))
		seen := make(map[int]bool, len(request.UserIDs))
		for _, uid := range request.UserIDs {
			if uid <= 0 || seen[uid] {
				tokenAPIError(c, model.ErrTokenAPIInvalid)
				return
			}
			seen[uid] = true
		}
		for _, uid := range request.UserIDs {
			snapshot, err := model.GetTokenAPIQuota(c.Request.Context(), uid)
			if err != nil {
				tokenAPIError(c, err)
				return
			}
			items = append(items, snapshot)
		}
		common.ApiSuccess(c, gin.H{"items": items})
		return
	}
	var request struct {
		Items []struct {
			UserID               int    `json:"user_id"`
			GrantedTotal         *int64 `json:"granted_total"`
			ExpectedGrantedTotal *int64 `json:"expected_granted_total"`
		} `json:"items"`
	}
	if err := tokenAPIBody(c, &request, "items"); err != nil {
		tokenAPIError(c, err)
		return
	}
	if len(request.Items) == 0 || len(request.Items) > 500 {
		tokenAPIError(c, model.ErrTokenAPIInvalid)
		return
	}
	seen := make(map[int]bool, len(request.Items))
	for _, item := range request.Items {
		if item.UserID <= 0 || seen[item.UserID] || item.GrantedTotal == nil || item.ExpectedGrantedTotal == nil || *item.GrantedTotal > common.MaxWalletQuota || *item.GrantedTotal < -common.MaxWalletQuota || *item.ExpectedGrantedTotal > common.MaxWalletQuota || *item.ExpectedGrantedTotal < -common.MaxWalletQuota {
			tokenAPIError(c, model.ErrTokenAPIInvalid)
			return
		}
		seen[item.UserID] = true
	}
	// Items commit independently. A later failure can leave earlier items applied;
	// callers may retry the entire batch using the original expected totals.
	items := make([]*model.TokenAPIQuotaSnapshot, 0, len(request.Items))
	for _, item := range request.Items {
		snapshot, err := model.GrantTokenAPIQuota(c.Request.Context(), item.UserID, *item.GrantedTotal, *item.ExpectedGrantedTotal)
		if err != nil {
			tokenAPIError(c, err)
			return
		}
		items = append(items, snapshot)
	}
	common.ApiSuccess(c, gin.H{"items": items})
}
