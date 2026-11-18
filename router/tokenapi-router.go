package router

import (
	"os"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/controller"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/gin-gonic/gin"
)

// SetTokenAPIRouter is the only upstream hook. An unset secret leaves both the
// route table and database schema unchanged.
func SetTokenAPIRouter(router *gin.Engine) {
	secret := os.Getenv("TOKENAPI_INTERNAL_SECRET")
	if secret == "" {
		return
	}
	if len(secret) < 32 {
		panic("TOKENAPI_INTERNAL_SECRET must contain at least 32 bytes")
	}
	if !common.RedisEnabled || common.RDB == nil {
		panic("TokenAPI internal routes require Redis")
	}
	if common.IsMasterNode {
		if err := model.MigrateTokenAPI(); err != nil {
			panic("TokenAPI internal migration failed")
		}
	} else if !model.DB.Migrator().HasTable(&model.TokenAPIQuotaGrant{}) {
		panic("TokenAPI internal migration must run on the master first")
	}
	group := router.Group("/internal/tokenapi/v1", middleware.TokenAPIInternalAuth(secret))
	group.POST("/users/:uid/tokens", controller.TokenAPITokens)
	group.GET("/users/:uid/tokens", controller.TokenAPITokens)
	group.PATCH("/users/:uid/tokens/:tid", controller.TokenAPIToken)
	group.DELETE("/users/:uid/tokens/:tid", controller.TokenAPIToken)
	group.POST("/quota/batch-get", controller.TokenAPIQuota)
	group.POST("/quota/batch-grant", controller.TokenAPIQuota)
}
