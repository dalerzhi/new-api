package router

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/QuantumNous/new-api/setting/ratio_setting"
	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

const internalTestSecret = "internal-test-secret-with-at-least-32-bytes"

func tokenAPITestEngine(t *testing.T, beforeMigration ...func()) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	t.Setenv("TOKENAPI_INTERNAL_SECRET", internalTestSecret)
	oldDB, oldLogDB := model.DB, model.LOG_DB
	oldRedis, oldRDB, oldMaster := common.RedisEnabled, common.RDB, common.IsMasterNode
	oldMainType, oldLogType := common.MainDatabaseType(), common.LogDatabaseType()
	oldSQLitePath := common.SQLitePath
	common.SQLitePath = t.TempDir() + "/internal.db"
	dsn := os.Getenv("TOKENAPI_TEST_SQL_DSN")
	if dsn == "" {
		dsn = "local"
	}
	t.Setenv("SQL_DSN", dsn)
	t.Setenv("LOG_SQL_DSN", os.Getenv("TOKENAPI_TEST_LOG_SQL_DSN"))
	common.IsMasterNode = true
	require.NoError(t, model.InitDB())
	require.NoError(t, model.InitLogDB())
	db := model.DB
	common.RedisEnabled = true
	if url := os.Getenv("TOKENAPI_TEST_REDIS_URL"); url != "" {
		options, err := redis.ParseURL(url)
		require.NoError(t, err)
		common.RDB = redis.NewClient(options)
		// This opt-in URL must point at a disposable test-only Redis database.
		require.NoError(t, common.RDB.FlushDB(t.Context()).Err())
	} else {
		server := miniredis.RunT(t)
		common.RDB = redis.NewClient(&redis.Options{Addr: server.Addr()})
	}
	t.Cleanup(func() {
		_ = common.RDB.Close()
		sqlDB, closeErr := db.DB()
		require.NoError(t, closeErr)
		require.NoError(t, sqlDB.Close())
		model.DB, model.LOG_DB = oldDB, oldLogDB
		common.RedisEnabled, common.RDB, common.IsMasterNode = oldRedis, oldRDB, oldMaster
		common.SetDatabaseTypes(oldMainType, oldLogType)
		common.SQLitePath = oldSQLitePath
	})
	for _, setup := range beforeMigration {
		setup()
	}
	engine := gin.New()
	SetTokenAPIRouter(engine)
	require.NoError(t, model.MigrateTokenAPI())
	return engine
}

func signedInternalRequest(method, path, body, timestamp, nonce string) *http.Request {
	digest := sha256.Sum256([]byte(body))
	mac := hmac.New(sha256.New, []byte(internalTestSecret))
	_, _ = mac.Write([]byte(timestamp + "\n" + nonce + "\n" + method + "\n" + path + "\n" + hex.EncodeToString(digest[:])))
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-TokenAPI-Timestamp", timestamp)
	req.Header.Set("X-TokenAPI-Nonce", nonce)
	req.Header.Set("X-TokenAPI-Signature", hex.EncodeToString(mac.Sum(nil)))
	return req
}

func TestTokenAPIDisabledWithoutSecret(t *testing.T) {
	t.Setenv("TOKENAPI_INTERNAL_SECRET", "")
	engine := gin.New()
	SetTokenAPIRouter(engine)
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/internal/tokenapi/v1/quota/batch-get", nil))
	assert.Equal(t, http.StatusNotFound, recorder.Code)
}

func TestTokenAPIAuthenticationRejectsTamperingExpiryAndReplay(t *testing.T) {
	engine := tokenAPITestEngine(t)
	path, body := "/internal/tokenapi/v1/quota/batch-get", `{"user_ids":[1]}`
	now := time.Now().Unix()
	for _, tc := range []struct {
		name   string
		ts     int64
		mutate func(*http.Request)
	}{
		{"wrong signature", now, func(req *http.Request) { req.Header.Set("X-TokenAPI-Signature", strings.Repeat("0", 64)) }},
		{"expired", now - 301, nil},
		{"future", now + 301, nil},
		{"invalid nonce", now, func(req *http.Request) { req.Header.Set("X-TokenAPI-Nonce", "not-a-uuid") }},
		{"different body", now, func(req *http.Request) { req.Body = http.NoBody }},
		{"duplicate timestamp", now, func(req *http.Request) { req.Header.Add("X-TokenAPI-Timestamp", strconv.FormatInt(now, 10)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := signedInternalRequest(http.MethodPost, path, body, strconv.FormatInt(tc.ts, 10), uuid.NewString())
			if tc.mutate != nil {
				tc.mutate(req)
			}
			recorder := httptest.NewRecorder()
			engine.ServeHTTP(recorder, req)
			assert.Equal(t, http.StatusUnauthorized, recorder.Code)
			assert.NotContains(t, recorder.Body.String(), internalTestSecret)
		})
	}
	// A valid signature consumes the nonce even when business validation fails.
	nonce, timestamp := uuid.NewString(), strconv.FormatInt(now, 10)
	first := httptest.NewRecorder()
	engine.ServeHTTP(first, signedInternalRequest(http.MethodPost, path, body, timestamp, nonce))
	assert.NotEqual(t, http.StatusUnauthorized, first.Code)
	replayed := httptest.NewRecorder()
	engine.ServeHTTP(replayed, signedInternalRequest(http.MethodPost, path, body, timestamp, nonce))
	assert.Equal(t, http.StatusUnauthorized, replayed.Code)
}

type internalRedisFault struct {
	after bool
	fired bool
	evict bool
}

func (fault *internalRedisFault) BeforeProcess(ctx context.Context, cmd redis.Cmder) (context.Context, error) {
	if !fault.after && !fault.fired && cmd.Name() == "eval" && strings.Contains(fmt.Sprint(cmd.Args()[1]), "HINCRBY") && strings.Contains(fmt.Sprint(cmd.Args()[1]), "TokenAPIQuotaRevision") {
		fault.fired = true
		if fault.evict {
			return ctx, common.RDB.Del(ctx, fmt.Sprint(cmd.Args()[3])).Err()
		}
		return ctx, errors.New("injected cache synchronization failure")
	}
	return ctx, nil
}
func (fault *internalRedisFault) AfterProcess(_ context.Context, cmd redis.Cmder) error {
	if fault.after && !fault.fired && cmd.Name() == "eval" && strings.Contains(fmt.Sprint(cmd.Args()[1]), "HINCRBY") && strings.Contains(fmt.Sprint(cmd.Args()[1]), "TokenAPIQuotaRevision") {
		fault.fired = true
		return errors.New("injected lost Redis reply")
	}
	return nil
}
func (*internalRedisFault) BeforeProcessPipeline(ctx context.Context, _ []redis.Cmder) (context.Context, error) {
	return ctx, nil
}
func (*internalRedisFault) AfterProcessPipeline(context.Context, []redis.Cmder) error { return nil }

func TestTokenAPIQuotaRecoversAmbiguousCacheSynchronization(t *testing.T) {
	for _, mode := range []string{"before cache apply", "lost cache reply", "evicted cache"} {
		t.Run(mode, func(t *testing.T) {
			engine := tokenAPITestEngine(t)
			user := internalTestUser(t, "internal-recovery")
			fault := &internalRedisFault{after: mode == "lost cache reply", evict: mode == "evicted cache"}
			common.RDB.AddHook(fault)
			first := grantInternal(engine, user.Id, 1000000, 0)
			require.True(t, fault.fired)
			if mode == "evicted cache" {
				assert.Equal(t, http.StatusOK, first.Code)
			} else {
				assert.Equal(t, http.StatusServiceUnavailable, first.Code)
			}
			retried := quotaResult(t, grantInternal(engine, user.Id, 1000000, 0))
			assert.False(t, retried.Applied)
			assert.Zero(t, retried.AppliedDelta)
			assert.Equal(t, 1000000, retried.Quota)
			var persisted model.User
			require.NoError(t, model.DB.First(&persisted, user.Id).Error)
			assert.Equal(t, retried.Quota, persisted.Quota)
			var grant model.TokenAPIQuotaGrant
			require.NoError(t, model.DB.First(&grant, "user_id = ?", user.Id).Error)
			assert.Empty(t, grant.PendingNonce)
			assert.Zero(t, grant.PendingDelta)
		})
	}
}

func internalCall(engine *gin.Engine, method, path string, body any) *httptest.ResponseRecorder {
	encoded := ""
	if body != nil {
		bytes, err := common.Marshal(body)
		if err != nil {
			panic(err)
		}
		encoded = string(bytes)
	}
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, signedInternalRequest(method, path, encoded, strconv.FormatInt(time.Now().Unix(), 10), uuid.NewString()))
	return recorder
}

func internalTestUser(t *testing.T, username string) model.User {
	t.Helper()
	username = username[:min(len(username), 8)] + "-" + uuid.NewString()[:8]
	user := model.User{Username: username, Password: "unused-test-hash", Role: common.RoleCommonUser, Status: common.UserStatusEnabled, Group: "default", AuthVersion: 1, AffCode: username}
	require.NoError(t, model.DB.Create(&user).Error)
	return user
}

func TestTokenAPITokenOwnershipMaskingAndLifecycle(t *testing.T) {
	engine := tokenAPITestEngine(t)
	user := internalTestUser(t, "internal-owner")
	other := internalTestUser(t, "internal-other")
	path := fmt.Sprintf("/internal/tokenapi/v1/users/%d/tokens", user.Id)
	created := internalCall(engine, http.MethodPost, path, map[string]any{"name": "test", "group": "default", "unlimited_quota": true})
	require.Equal(t, http.StatusOK, created.Code, created.Body.String())
	var result struct {
		Data struct {
			ID  int    `json:"id"`
			Key string `json:"key"`
		} `json:"data"`
	}
	require.NoError(t, common.Unmarshal(created.Body.Bytes(), &result))
	require.NotEmpty(t, result.Data.Key)
	token, err := model.ValidateUserToken(result.Data.Key)
	require.NoError(t, err)
	assert.Equal(t, user.Id, token.UserId)
	assert.False(t, token.AllowUserQuotaQuery)
	listed := internalCall(engine, http.MethodGet, path+"?page=1&size=10", nil)
	require.Equal(t, http.StatusOK, listed.Code)
	assert.NotContains(t, listed.Body.String(), result.Data.Key)
	assert.Contains(t, listed.Body.String(), "**********")
	// Unlimited tokens still accumulate a negative remain_quota during relay.
	// That accounting value must not prevent disabling or renaming the key.
	require.NoError(t, model.DecreaseTokenQuota(token.Id, token.Key, 100))
	foreign := fmt.Sprintf("/internal/tokenapi/v1/users/%d/tokens/%d", other.Id, result.Data.ID)
	assert.Equal(t, http.StatusNotFound, internalCall(engine, http.MethodPatch, foreign, map[string]any{"status": 2}).Code)
	assert.Equal(t, http.StatusNotFound, internalCall(engine, http.MethodDelete, foreign, nil).Code)
	item := fmt.Sprintf("%s/%d", path, result.Data.ID)
	updated := internalCall(engine, http.MethodPatch, item, map[string]any{"status": 2, "name": "disabled"})
	require.Equal(t, http.StatusOK, updated.Code, updated.Body.String())
	assert.NotContains(t, updated.Body.String(), result.Data.Key)
	_, err = model.ValidateUserToken(result.Data.Key)
	assert.Error(t, err)
	require.Equal(t, http.StatusOK, internalCall(engine, http.MethodPatch, item, map[string]any{"status": 1}).Code)
	_, err = model.ValidateUserToken(result.Data.Key)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, internalCall(engine, http.MethodDelete, item, nil).Code)
	_, err = model.ValidateUserToken(result.Data.Key)
	assert.Error(t, err)
}

func grantInternal(engine *gin.Engine, uid int, target, expected int64) *httptest.ResponseRecorder {
	return internalCall(engine, http.MethodPost, "/internal/tokenapi/v1/quota/batch-grant", map[string]any{"items": []any{map[string]any{"user_id": uid, "granted_total": target, "expected_granted_total": expected}}})
}

func quotaResult(t *testing.T, response *httptest.ResponseRecorder) model.TokenAPIQuotaSnapshot {
	t.Helper()
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var result struct {
		Data struct {
			Items []model.TokenAPIQuotaSnapshot `json:"items"`
		} `json:"data"`
	}
	require.NoError(t, common.Unmarshal(response.Body.Bytes(), &result))
	require.Len(t, result.Data.Items, 1)
	return result.Data.Items[0]
}

func TestTokenAPIQuotaGoldenG23G24AndRevocation(t *testing.T) {
	engine := tokenAPITestEngine(t)
	user := internalTestUser(t, "internal-quota")
	initial := quotaResult(t, grantInternal(engine, user.Id, 10000000, 0))
	assert.Equal(t, 10000000, initial.Quota)
	reserved, err := model.TryReserveUserQuota(user.Id, 9600000)
	require.NoError(t, err)
	require.True(t, reserved)
	before := quotaResult(t, internalCall(engine, http.MethodPost, "/internal/tokenapi/v1/quota/batch-get", map[string]any{"user_ids": []int{user.Id}}))
	assert.Equal(t, 400000, before.Quota)
	// G24: this spend happens after batch-get and before the additive grant.
	reserved, err = model.TryReserveUserQuota(user.Id, 50000)
	require.NoError(t, err)
	require.True(t, reserved)
	applied := quotaResult(t, grantInternal(engine, user.Id, 10200000, 10000000))
	assert.True(t, applied.Applied)
	assert.Equal(t, int64(200000), applied.AppliedDelta)
	assert.Equal(t, 550000, applied.Quota)
	// G23: retrying the original expected total cannot grant again.
	replayed := quotaResult(t, grantInternal(engine, user.Id, 10200000, 10000000))
	assert.False(t, replayed.Applied)
	assert.Zero(t, replayed.AppliedDelta)
	assert.Equal(t, applied.Quota, replayed.Quota)
	assert.Equal(t, int64(9650000), replayed.GrantedTotal-int64(replayed.Quota))
	revoked := quotaResult(t, grantInternal(engine, user.Id, 9600000, 10200000))
	assert.Equal(t, -50000, revoked.Quota)
	reserved, err = model.TryReserveUserQuota(user.Id, 1)
	require.NoError(t, err)
	assert.False(t, reserved)
}

func TestTokenAPIConcurrentGrantOnlyAppliesOnce(t *testing.T) {
	engine := tokenAPITestEngine(t)
	user := internalTestUser(t, "internal-race")
	var wg sync.WaitGroup
	responses := make(chan *httptest.ResponseRecorder, 2)
	for range 2 {
		wg.Go(func() { responses <- grantInternal(engine, user.Id, 1000000, 0) })
	}
	wg.Wait()
	close(responses)
	applied := 0
	for response := range responses {
		if response.Code == http.StatusServiceUnavailable {
			response = grantInternal(engine, user.Id, 1000000, 0)
		}
		result := quotaResult(t, response)
		if result.Applied {
			applied++
		}
	}
	assert.Equal(t, 1, applied)
	result := quotaResult(t, internalCall(engine, http.MethodPost, "/internal/tokenapi/v1/quota/batch-get", map[string]any{"user_ids": []int{user.Id}}))
	assert.Equal(t, 1000000, result.Quota)
	assert.Equal(t, int64(1000000), result.GrantedTotal)
}

func TestTokenAPIMigrationPreservesReleasedSchemaAndData(t *testing.T) {
	var original model.User
	var token model.Token
	tokenAPITestEngine(t, func() {
		// InitDB above is the unchanged rc.49 migration path. These rows exist
		// before the new router hook migrates CP-02, as on an upgraded instance.
		// Only the disposable test database is used; restore the pre-patch schema.
		require.NoError(t, model.DB.Migrator().DropTable(&model.TokenAPIQuotaGrant{}))
		require.False(t, model.DB.Migrator().HasTable(&model.TokenAPIQuotaGrant{}))
		original = internalTestUser(t, "upgrade")
		require.NoError(t, model.DB.Model(&original).Update("quota", 123456).Error)
		token = model.Token{UserId: original.Id, Key: uuid.NewString(), Name: "existing", Status: common.TokenStatusEnabled, ExpiredTime: -1, UnlimitedQuota: true}
		require.NoError(t, token.Insert())
	})
	// Repeat the complete released startup migrations and the patch migration.
	require.NoError(t, model.InitDB())
	secondDB := model.DB
	t.Cleanup(func() {
		connection, err := secondDB.DB()
		require.NoError(t, err)
		require.NoError(t, connection.Close())
	})
	require.NoError(t, model.MigrateTokenAPI())
	var preserved model.User
	require.NoError(t, model.DB.First(&preserved, original.Id).Error)
	assert.Equal(t, 123456, preserved.Quota)
	preservedToken, err := model.GetTokenByIds(token.Id, original.Id)
	require.NoError(t, err)
	assert.Equal(t, token.Key, preservedToken.Key)
	assert.Equal(t, token.Name, preservedToken.Name)
	assert.True(t, model.DB.Migrator().HasIndex(&model.Token{}, "Key"))
	grant := model.TokenAPIQuotaGrant{UserID: original.Id}
	require.NoError(t, model.DB.Create(&grant).Error)
	assert.Error(t, model.DB.Create(&model.TokenAPIQuotaGrant{UserID: original.Id}).Error, "grant primary key must remain unique")
	var version string
	query := "SELECT version()"
	if common.UsingMainDatabase(common.DatabaseTypeSQLite) {
		query = "SELECT sqlite_version()"
	}
	require.NoError(t, model.DB.Raw(query).Scan(&version).Error)
	t.Logf("Database migration verified twice: %s %s", common.MainDatabaseType(), version)
}

func TestTokenAPIInputLimitsAndRedisFailureAreFailClosed(t *testing.T) {
	engine := tokenAPITestEngine(t)
	user := internalTestUser(t, "invalid")
	path := fmt.Sprintf("/internal/tokenapi/v1/users/%d/tokens", user.Id)
	for _, body := range []map[string]any{
		{"name": "test", "group": "unknown"},
		{"name": "test", "group": "auto"},
		{"name": "test", "group": "default", "remain_quota": -1},
		{"name": "test", "group": "default", "expired_time": 0},
		{"name": "test", "group": "default", "allow_ips": "not-an-ip"},
		{"name": "test", "group": "default", "key": "must-not-be-accepted"},
	} {
		assert.Equal(t, http.StatusBadRequest, internalCall(engine, http.MethodPost, path, body).Code)
	}
	count, err := model.CountUserTokens(user.Id)
	require.NoError(t, err)
	assert.Zero(t, count)
	assert.Equal(t, http.StatusBadRequest, grantInternal(engine, user.Id, common.MaxWalletQuota+1, 0).Code)
	assert.Equal(t, http.StatusBadRequest, internalCall(engine, http.MethodPost, "/internal/tokenapi/v1/quota/batch-get", map[string]any{"user_ids": []int{user.Id, user.Id}}).Code)
	assert.Equal(t, http.StatusBadRequest, internalCall(engine, http.MethodPost, "/internal/tokenapi/v1/quota/batch-get", map[string]any{"user_ids": make([]int, 501)}).Code)
	common.RedisEnabled = false
	assert.Equal(t, http.StatusServiceUnavailable, grantInternal(engine, user.Id, 100, 0).Code)
	var persisted model.User
	require.NoError(t, model.DB.First(&persisted, user.Id).Error)
	assert.Zero(t, persisted.Quota)
}

func TestTokenAPIQuotaColdCacheDuringGrantPreservesRevocation(t *testing.T) {
	engine := tokenAPITestEngine(t)
	user := internalTestUser(t, "cold-grant")
	quotaResult(t, grantInternal(engine, user.Id, 1000000, 0))
	hydrated := false
	const hook = "tokenapi_test_cold_cache_during_grant"
	require.NoError(t, model.DB.Callback().Update().After("gorm:update").Register(hook, func(tx *gorm.DB) {
		if hydrated || tx.Statement.Table != "users" {
			return
		}
		hydrated = true
		// A cache expires while the wallet transaction is uncommitted. A relay
		// reader can only see the old committed wallet and recreates the hash.
		require.NoError(t, common.RDB.Del(t.Context(), fmt.Sprintf("user:%d", user.Id)).Err())
		_, err := model.GetUserCache(user.Id)
		require.NoError(t, err)
	}))
	t.Cleanup(func() { require.NoError(t, model.DB.Callback().Update().Remove(hook)) })
	result := quotaResult(t, grantInternal(engine, user.Id, 500000, 1000000))
	require.True(t, hydrated)
	assert.Equal(t, 500000, result.Quota, "a pre-commit cache refill must still receive the negative grant delta")
	assert.Equal(t, int64(500000), result.GrantedTotal)
}

func TestTokenAPIQuotaRejectsDelayedPreGrantCacheSnapshot(t *testing.T) {
	engine := tokenAPITestEngine(t)
	user := internalTestUser(t, "late-fill")
	quotaResult(t, grantInternal(engine, user.Id, 1000000, 0))
	key := fmt.Sprintf("user:%d", user.Id)
	require.NoError(t, common.RDB.Del(t.Context(), key).Err())
	ready, release := make(chan struct{}), make(chan struct{})
	completed := make(chan error, 1)
	var blocked atomic.Bool
	var unblock sync.Once
	const hook = "tokenapi_test_delayed_quota_snapshot"
	require.NoError(t, model.DB.Callback().Query().After("gorm:query").Register(hook, func(tx *gorm.DB) {
		if !strings.Contains(tx.Statement.SQL.String(), "COALESCE(tokenapi_quota_grants.revision") || blocked.Swap(true) {
			return
		}
		close(ready)
		<-release
	}))
	t.Cleanup(func() {
		unblock.Do(func() { close(release) })
		require.NoError(t, model.DB.Callback().Query().Remove(hook))
	})
	go func() { _, err := model.GetUserCache(user.Id); completed <- err }()
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("quota snapshot did not reach the read barrier")
	}
	quotaResult(t, grantInternal(engine, user.Id, 500000, 1000000))
	// The old reader resumes after the new grant is fully acknowledged and the
	// current hash has expired. Its old quota must not resurrect spendable funds.
	require.NoError(t, common.RDB.Del(t.Context(), key).Err())
	unblock.Do(func() { close(release) })
	select {
	case err := <-completed:
		assert.ErrorIs(t, err, model.ErrUserAuthCachePending)
	case <-time.After(3 * time.Second):
		t.Fatal("delayed quota snapshot did not finish")
	}
	exists, err := common.RDB.Exists(t.Context(), key).Result()
	require.NoError(t, err)
	assert.Zero(t, exists, "rejected cache fills must not leave a partial user hash")
	quota, err := model.GetUserQuota(user.Id, false)
	require.NoError(t, err)
	assert.Equal(t, 500000, quota)
}

func TestTokenAPIMetadataPatchPreservesConcurrentTokenSpend(t *testing.T) {
	engine := tokenAPITestEngine(t)
	user := internalTestUser(t, "token-spend")
	path := fmt.Sprintf("/internal/tokenapi/v1/users/%d/tokens", user.Id)
	created := internalCall(engine, http.MethodPost, path, map[string]any{"name": "before", "group": "default", "unlimited_quota": true})
	var result struct {
		Data struct {
			ID int `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, common.Unmarshal(created.Body.Bytes(), &result))
	var spent atomic.Bool
	const hook = "tokenapi_test_spend_before_metadata_patch"
	require.NoError(t, model.DB.Callback().Update().Before("gorm:update").Register(hook, func(tx *gorm.DB) {
		if tx.Statement.Table != "tokens" || spent.Swap(true) {
			return
		}
		// The spend lands after the controller read, before its metadata write.
		require.NoError(t, model.DB.Model(&model.Token{}).Where("id = ?", result.Data.ID).Updates(map[string]any{"remain_quota": -100, "used_quota": 100}).Error)
	}))
	t.Cleanup(func() { require.NoError(t, model.DB.Callback().Update().Remove(hook)) })
	updated := internalCall(engine, http.MethodPatch, fmt.Sprintf("%s/%d", path, result.Data.ID), map[string]any{"name": "after"})
	require.Equal(t, http.StatusOK, updated.Code, updated.Body.String())
	token, err := model.GetTokenByIds(result.Data.ID, user.Id)
	require.NoError(t, err)
	assert.Equal(t, "after", token.Name)
	assert.Equal(t, -100, token.RemainQuota)
	assert.Equal(t, 100, token.UsedQuota)
}

func TestTokenAPIQuotaReadsLiveCacheAndRetainsPendingDeductions(t *testing.T) {
	engine := tokenAPITestEngine(t)
	user := internalTestUser(t, "live-quota")
	quotaResult(t, grantInternal(engine, user.Id, 1000000, 0))
	// Model a reservation that reached Redis before its database delta flush.
	require.NoError(t, common.RDB.HIncrBy(t.Context(), fmt.Sprintf("user:%d", user.Id), "Quota", -10000).Err())
	var stored model.User
	require.NoError(t, model.DB.First(&stored, user.Id).Error)
	assert.Equal(t, 1000000, stored.Quota)
	live := quotaResult(t, internalCall(engine, http.MethodPost, "/internal/tokenapi/v1/quota/batch-get", map[string]any{"user_ids": []int{user.Id}}))
	assert.Equal(t, 990000, live.Quota)
	granted := quotaResult(t, grantInternal(engine, user.Id, 1200000, 1000000))
	assert.Equal(t, 1190000, granted.Quota)
	assert.Equal(t, int64(10000), granted.GrantedTotal-int64(granted.Quota))
}

func TestTokenAPIProvisioningGroupAndTokenCap(t *testing.T) {
	engine := tokenAPITestEngine(t)
	user := internalTestUser(t, "group-cap")
	original := ratio_setting.GroupRatio2JSONString()
	require.NoError(t, ratio_setting.UpdateGroupRatioByJSONString(`{"default":1,"internal_only":1}`))
	t.Cleanup(func() { require.NoError(t, ratio_setting.UpdateGroupRatioByJSONString(original)) })
	oldCap := operation_setting.GetTokenSetting().MaxUserTokens
	operation_setting.GetTokenSetting().MaxUserTokens = 1
	t.Cleanup(func() { operation_setting.GetTokenSetting().MaxUserTokens = oldCap })
	path := fmt.Sprintf("/internal/tokenapi/v1/users/%d/tokens", user.Id)
	// Internal provisioning checks existence, not dashboard-selectable groups.
	created := internalCall(engine, http.MethodPost, path, map[string]any{"name": "private", "group": "internal_only", "unlimited_quota": true})
	require.Equal(t, http.StatusOK, created.Code, created.Body.String())
	capped := internalCall(engine, http.MethodPost, path, map[string]any{"name": "extra", "group": "default", "unlimited_quota": true})
	assert.Equal(t, http.StatusBadRequest, capped.Code)
	count, err := model.CountUserTokens(user.Id)
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)
}
