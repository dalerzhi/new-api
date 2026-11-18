package model

import (
	"context"

	"github.com/QuantumNous/new-api/setting/operation_setting"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// CreateTokenAPIToken keeps the upstream token insertion semantics while
// serializing the per-user token cap with other internal creators.
func CreateTokenAPIToken(ctx context.Context, token *Token) error {
	return DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var user User
		if err := lockForUpdate(tx).First(&user, token.UserId).Error; err != nil {
			return err
		}
		var count int64
		if err := tx.Model(&Token{}).Where("user_id = ?", token.UserId).Count(&count).Error; err != nil {
			return err
		}
		if count >= int64(operation_setting.GetMaxUserTokens()) {
			return ErrTokenAPIInvalid
		}
		// A driver error must never print an INSERT containing the usable key.
		return tx.Session(&gorm.Session{Logger: logger.Default.LogMode(logger.Silent)}).Create(token).Error
	})
}

// UpdateTokenAPIToken only writes fields present in the PATCH. Metadata-only
// updates must not replace quota counters changed by a concurrent relay.
func UpdateTokenAPIToken(ctx context.Context, token *Token, columns []string) error {
	if len(columns) == 0 {
		return ErrTokenAPIInvalid
	}
	if err := invalidateTokenCacheForMutation(token.Key); err != nil {
		return ErrTokenAPICache
	}
	return DB.WithContext(ctx).Model(token).Where("user_id = ?", token.UserId).Select(columns).Updates(token).Error
}
