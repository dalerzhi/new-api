package controller

import (
	"net/http"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/gin-gonic/gin"
)

func TokenAPIManagedUsers(c *gin.Context) {
	var snapshot *model.TokenAPIManagedSnapshot
	var err error
	if c.Request.Method == http.MethodPost {
		defer func() { tokenAPIManagedAudit(c, "create", snapshot, err) }()
	}
	if c.Request.Method == http.MethodGet {
		snapshot, err = model.GetTokenAPIManagedUser(c.Request.Context(), c.Param("account_id"))
	} else {
		var input model.TokenAPIManagedUserInput
		if err = tokenAPIBody(c, &input, "account_id", "username", "display_name", "group"); err == nil {
			snapshot, err = model.CreateTokenAPIManagedUser(c.Request.Context(), input)
		}
	}
	if err != nil {
		tokenAPIError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": snapshot})
}

func TokenAPIManagedUserLifecycle(c *gin.Context) {
	var input struct {
		UserID           *int   `json:"user_id"`
		Action           string `json:"action"`
		ExpectedRevision *int64 `json:"expected_revision"`
	}
	if err := tokenAPIBody(c, &input, "user_id", "action", "expected_revision"); err != nil || input.UserID == nil || input.ExpectedRevision == nil {
		tokenAPIError(c, model.ErrTokenAPIInvalid)
		tokenAPIManagedAudit(c, "lifecycle", nil, model.ErrTokenAPIInvalid)
		return
	}
	snapshot, err := model.ChangeTokenAPIManagedUser(c.Request.Context(), c.Param("account_id"), *input.UserID, input.Action, *input.ExpectedRevision)
	if err != nil {
		tokenAPIError(c, err)
		tokenAPIManagedAudit(c, "lifecycle", nil, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": snapshot})
	tokenAPIManagedAudit(c, input.Action, snapshot, nil)
}

// HMAC is a machine principal, not an administrator's interactive identity.
// Unknown actor role keeps these entries root-only under upstream projections.
func tokenAPIManagedAudit(c *gin.Context, action string, snapshot *model.TokenAPIManagedSnapshot, err error) {
	fields := model.AuditFields{}
	if snapshot != nil {
		fields["account_id"] = snapshot.AccountID
		fields["user_id"] = snapshot.UserID
		fields["revision"] = snapshot.Revision
	}
	// Pass explicit safe metadata instead of recording caller-controlled agent,
	// URL, headers, body, errors or credentials. Audit persists after cancellation.
	model.RecordAuditLog(nil, model.AuditLog{Username: "tokenapi-internal", AuthMethod: "hmac",
		Category: model.AuditCategorySecurity, Action: "tokenapi.managed_user." + action,
		Method: c.Request.Method, Route: c.FullPath(), Ip: c.ClientIP(), RequestId: c.GetString(common.RequestIdKey),
		Status: c.Writer.Status(), Success: err == nil, Content: "Managed customer operation acknowledgement",
		Other: model.AuditOther{RootInfo: fields}})
}
