package middleware

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/logger"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// TokenAPIInternalAuth authenticates each complete request independently of
// dashboard sessions and PATs. Nonces are shared by every gateway node.
func TokenAPIInternalAuth(secret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		deny := func(status int) {
			logger.LogWarn(c, common.LogText("TokenAPI internal request rejected with HTTP %d", status))
			c.AbortWithStatusJSON(status, gin.H{"success": false, "message": "Internal request rejected"})
		}
		for _, header := range []string{"X-TokenAPI-Timestamp", "X-TokenAPI-Nonce", "X-TokenAPI-Signature"} {
			if len(c.Request.Header.Values(header)) != 1 {
				deny(http.StatusUnauthorized)
				return
			}
		}
		ts, nonce, signature := c.GetHeader("X-TokenAPI-Timestamp"), c.GetHeader("X-TokenAPI-Nonce"), c.GetHeader("X-TokenAPI-Signature")
		timestamp, err := strconv.ParseInt(ts, 10, 64)
		now := time.Now().Unix()
		if err != nil || ts != strconv.FormatInt(timestamp, 10) || timestamp < now-300 || timestamp > now+300 {
			deny(http.StatusUnauthorized)
			return
		}
		id, err := uuid.Parse(nonce)
		if err != nil || nonce != id.String() || id == uuid.Nil || len(signature) != 64 {
			deny(http.StatusUnauthorized)
			return
		}
		provided, err := hex.DecodeString(signature)
		if err != nil || signature != strings.ToLower(signature) {
			deny(http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(io.LimitReader(c.Request.Body, 1024*1024+1))
		if err != nil || len(body) > 1024*1024 {
			deny(http.StatusRequestEntityTooLarge)
			return
		}
		digest := sha256.Sum256(body)
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write([]byte(ts + "\n" + nonce + "\n" + c.Request.Method + "\n" + c.Request.URL.RequestURI() + "\n" + hex.EncodeToString(digest[:])))
		if !hmac.Equal(provided, mac.Sum(nil)) {
			deny(http.StatusUnauthorized)
			return
		}
		if !common.RedisEnabled || common.RDB == nil {
			deny(http.StatusServiceUnavailable)
			return
		}
		accepted, err := common.RDB.SetNX(c.Request.Context(), "tokenapi:internal:nonce:"+nonce, "1", 601*time.Second).Result()
		if err != nil {
			deny(http.StatusServiceUnavailable)
			return
		}
		if !accepted {
			deny(http.StatusUnauthorized)
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(body))
		c.Next()
	}
}
