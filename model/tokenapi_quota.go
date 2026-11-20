package model

import (
	"context"
	"errors"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var ErrTokenAPIInvalid = errors.New("invalid internal request")
var ErrTokenAPICache = errors.New("internal quota synchronization unavailable")

// TokenAPIQuotaGrant keeps the absolute grant and a recoverable cache delta in
// the same transaction as the wallet update. It never contains credentials.
type TokenAPIQuotaGrant struct {
	UserID       int    `gorm:"primaryKey;autoIncrement:false"`
	GrantedTotal int64  `gorm:"type:bigint;not null"`
	UpdatedAt    int64  `gorm:"type:bigint;not null"`
	PendingNonce string `gorm:"type:varchar(36);not null"`
	PendingDelta int64  `gorm:"type:bigint;not null"`
	Revision     int64  `gorm:"type:bigint;not null"`
}

func (TokenAPIQuotaGrant) TableName() string { return "tokenapi_quota_grants" }

type TokenAPIQuotaSnapshot struct {
	UserID       int   `json:"user_id"`
	Quota        int   `json:"quota"`
	GrantedTotal int64 `json:"granted_total"`
	Status       int   `json:"status"`
	AppliedDelta int64 `json:"applied_delta"`
	Applied      bool  `json:"applied"`
}

func MigrateTokenAPI() error {
	return DB.AutoMigrate(&TokenAPIQuotaGrant{}, &TokenAPIManagedUser{})
}

// syncTokenAPIGrant is retryable across process exits and ambiguous Redis
// replies. The cache's quota revision distinguishes a pre-commit cache fill
// from one that already includes the committed grant. A durable Redis floor
// rejects delayed fills after this synchronization completes.
func syncTokenAPIGrant(ctx context.Context, userID int) error {
	return DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var grant TokenAPIQuotaGrant
		if err := lockForUpdate(tx).First(&grant, "user_id = ?", userID).Error; err != nil {
			return err
		}
		if grant.PendingNonce == "" {
			return nil
		}
		const script = `
local target = tonumber(ARGV[1])
if redis.call('HEXISTS', KEYS[1], 'Quota') == 1 then
  local cached = tonumber(redis.call('HGET', KEYS[1], 'TokenAPIQuotaRevision') or '0')
  if cached == target - 1 then
    redis.call('HINCRBY', KEYS[1], 'Quota', ARGV[2])
    redis.call('HSET', KEYS[1], 'TokenAPIQuotaRevision', ARGV[1])
  elseif cached ~= target then return 0 end
end
if tonumber(redis.call('GET', KEYS[2]) or '0') < target then redis.call('SET', KEYS[2], ARGV[1]) end
return 1`
		if !common.RedisEnabled || common.RDB == nil {
			return ErrTokenAPICache
		}
		result, err := common.RDB.Eval(ctx, script, []string{getUserCacheKey(userID), tokenAPIQuotaVersionKey(userID)}, grant.Revision, grant.PendingDelta).Int()
		if err != nil || result != 1 {
			return ErrTokenAPICache
		}
		return tx.Model(&grant).Updates(map[string]any{"pending_nonce": "", "pending_delta": 0}).Error
	})
}

// GetTokenAPIQuota uses the relay's cache-first quota function. Reading the
// grant on both sides rejects a snapshot spanning a concurrent grant commit.
func GetTokenAPIQuota(ctx context.Context, userID int) (*TokenAPIQuotaSnapshot, error) {
	if userID <= 0 {
		return nil, ErrTokenAPIInvalid
	}
	for range 5 {
		var before TokenAPIQuotaGrant
		err := DB.WithContext(ctx).First(&before, "user_id = ?", userID).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		if before.PendingNonce != "" {
			if err := syncTokenAPIGrant(ctx, userID); err != nil {
				return nil, err
			}
			continue
		}
		quota, err := GetUserQuota(userID, false)
		if err != nil {
			return nil, err
		}
		user, err := GetUserCache(userID)
		if err != nil {
			return nil, err
		}
		var after TokenAPIQuotaGrant
		err = DB.WithContext(ctx).First(&after, "user_id = ?", userID).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		if before.Revision == after.Revision && before.GrantedTotal == after.GrantedTotal && after.PendingNonce == "" {
			return &TokenAPIQuotaSnapshot{UserID: userID, Quota: quota, GrantedTotal: after.GrantedTotal, Status: user.Status}, nil
		}
	}
	return nil, ErrTokenAPICache
}

// GrantTokenAPIQuota applies a compare-and-set absolute grant using an additive
// wallet mutation. Concurrent relay reservations therefore remain intact.
func GrantTokenAPIQuota(ctx context.Context, userID int, target, expected int64) (*TokenAPIQuotaSnapshot, error) {
	if userID <= 0 || target > common.MaxWalletQuota || target < -common.MaxWalletQuota || expected > common.MaxWalletQuota || expected < -common.MaxWalletQuota {
		return nil, ErrTokenAPIInvalid
	}
	if _, err := GetUserCache(userID); err != nil {
		return nil, err
	}
	var delta int64
	var applied bool
	for range 5 {
		pending := false
		err := DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			grant := TokenAPIQuotaGrant{UserID: userID}
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&grant).Error; err != nil {
				return err
			}
			if err := lockForUpdate(tx).First(&grant, "user_id = ?", userID).Error; err != nil {
				return err
			}
			if grant.PendingNonce != "" {
				pending = true
				return nil
			}
			if grant.GrantedTotal != expected {
				return nil
			}
			var user User
			if err := lockForUpdate(tx).First(&user, userID).Error; err != nil {
				return err
			}
			delta = target - grant.GrantedTotal
			if _, err := common.WalletQuotaFromDecimalStrict(decimal.NewFromInt(int64(user.Quota)).Add(decimal.NewFromInt(delta))); err != nil {
				return ErrWalletQuotaLimitExceeded
			}
			if delta == 0 {
				applied = true
				return nil
			}
			nonce := uuid.NewString()
			if !common.RedisEnabled || common.RDB == nil {
				return ErrTokenAPICache
			}
			if err := tx.Model(&user).Update("quota", gorm.Expr("quota + ?", delta)).Error; err != nil {
				return err
			}
			if grant.Revision >= common.MaxWalletQuota {
				return ErrTokenAPIInvalid
			}
			if err := tx.Model(&grant).Updates(map[string]any{"granted_total": target, "updated_at": time.Now().Unix(), "pending_nonce": nonce, "pending_delta": delta, "revision": grant.Revision + 1}).Error; err != nil {
				return err
			}
			applied = true
			return nil
		})
		if err != nil {
			return nil, err
		}
		if pending {
			if err := syncTokenAPIGrant(ctx, userID); err != nil {
				return nil, err
			}
			continue
		}
		if err := syncTokenAPIGrant(ctx, userID); err != nil {
			return nil, err
		}
		snapshot, err := GetTokenAPIQuota(ctx, userID)
		if err != nil {
			return nil, err
		}
		snapshot.Applied = applied
		if applied {
			snapshot.AppliedDelta = delta
		}
		return snapshot, nil
	}
	return nil, ErrTokenAPICache
}
