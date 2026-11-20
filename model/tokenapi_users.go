package model

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/setting/ratio_setting"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var ErrTokenAPIConflict = errors.New("internal resource conflict")
var ErrTokenAPIForbidden = errors.New("internal resource outside managed scope")
var tokenAPIUsername = regexp.MustCompile(`^u_[A-Za-z0-9_]{1,18}$`)

// TokenAPIManagedUser is an immutable ownership binding, including tombstones.
// Quota grants alone do not establish ownership of a gateway user.
type TokenAPIManagedUser struct {
	AccountID          string `gorm:"type:varchar(36);primaryKey"`
	UserID             int    `gorm:"not null;uniqueIndex"`
	CreationHash       string `gorm:"type:char(64);not null"`
	Revision           int64  `gorm:"type:bigint;not null"`
	PendingAuthVersion int64  `gorm:"type:bigint;not null"`
}

func (TokenAPIManagedUser) TableName() string { return "tokenapi_managed_users" }

type TokenAPIManagedUserInput struct {
	AccountID   string `json:"account_id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Group       string `json:"group"`
}

type TokenAPIManagedSnapshot struct {
	AccountID string `json:"account_id"`
	UserID    int    `json:"user_id"`
	Revision  int64  `json:"revision"`
	Status    int    `json:"status"`
	Deleted   bool   `json:"deleted"`
}

func ValidTokenAPIAccountID(id string) bool {
	parsed, err := uuid.Parse(id)
	return err == nil && parsed != uuid.Nil && parsed.String() == id
}

func CreateTokenAPIManagedUser(ctx context.Context, input TokenAPIManagedUserInput) (*TokenAPIManagedSnapshot, error) {
	if !ValidTokenAPIAccountID(input.AccountID) || !tokenAPIUsername.MatchString(input.Username) ||
		strings.TrimSpace(input.DisplayName) == "" || len(input.DisplayName) > 20 ||
		input.Group == "" || input.Group == "auto" {
		return nil, ErrTokenAPIInvalid
	}
	encoded, err := common.Marshal(input)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	hash := hex.EncodeToString(digest[:])
	var binding TokenAPIManagedUser
	err = DB.WithContext(ctx).First(&binding, "account_id = ?", input.AccountID).Error
	if err == nil {
		if binding.CreationHash != hash {
			return nil, ErrTokenAPIConflict
		}
		return GetTokenAPIManagedUser(ctx, input.AccountID)
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	if !ratio_setting.ContainsGroupRatio(input.Group) {
		return nil, ErrTokenAPIInvalid
	}
	if common.QuotaForNewUser != 0 {
		return nil, ErrTokenAPICache
	}
	// A cryptographically random, discarded password prevents an interactive
	// login credential from becoming part of this machine-only API contract.
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	user := User{Username: input.Username, Password: hex.EncodeToString(secret), DisplayName: input.DisplayName,
		Group: input.Group, Role: common.RoleCommonUser, Status: common.UserStatusEnabled, AuthVersion: 1}
	// User insertion includes a password hash. Never let a driver print it.
	err = DB.WithContext(ctx).Session(&gorm.Session{Logger: logger.Default.LogMode(logger.Silent)}).Transaction(func(tx *gorm.DB) error {
		if err := user.InsertWithTx(tx, 0); err != nil {
			return err
		}
		if user.Quota != 0 {
			return ErrTokenAPICache
		}
		return tx.Create(&TokenAPIManagedUser{AccountID: input.AccountID, UserID: user.Id, CreationHash: hash}).Error
	})
	if err != nil {
		// A competing creator or a lost commit reply may already have made the
		// exact binding. Never adopt a username merely because it exists.
		if lookup := DB.WithContext(ctx).First(&binding, "account_id = ?", input.AccountID).Error; lookup == nil {
			if binding.CreationHash == hash {
				return GetTokenAPIManagedUser(ctx, input.AccountID)
			}
			return nil, ErrTokenAPIConflict
		}
		var count int64
		if lookup := DB.WithContext(ctx).Unscoped().Model(&User{}).Where("username = ?", input.Username).Count(&count).Error; lookup == nil && count > 0 {
			return nil, ErrTokenAPIConflict
		}
		return nil, err
	}
	common.SysLog(fmt.Sprintf("TokenAPI managed user created (account_id=%s, user_id=%d)", input.AccountID, user.Id))
	return GetTokenAPIManagedUser(ctx, input.AccountID)
}

// GetTokenAPIManagedUser repairs committed authentication changes before
// acknowledging them. Cleanup is bounded by the captured authentication version
// so a delayed repair cannot terminate a newer enabled user's sessions.
func GetTokenAPIManagedUser(ctx context.Context, accountID string) (*TokenAPIManagedSnapshot, error) {
	if !ValidTokenAPIAccountID(accountID) {
		return nil, ErrTokenAPIInvalid
	}
	for range 5 {
		var state struct {
			TokenAPIManagedUser
			Role      int
			Status    int
			DeletedAt gorm.DeletedAt
		}
		err := DB.WithContext(ctx).Unscoped().Table("tokenapi_managed_users AS managed").
			Select("managed.*, users.role, users.status, users.deleted_at").
			Joins("JOIN users ON users.id = managed.user_id").Where("managed.account_id = ?", accountID).Take(&state).Error
		if err != nil {
			return nil, err
		}
		if state.Role != common.RoleCommonUser {
			return nil, ErrTokenAPIForbidden
		}
		if state.PendingAuthVersion == 0 {
			return &TokenAPIManagedSnapshot{AccountID: accountID, UserID: state.UserID, Revision: state.Revision,
				Status: state.Status, Deleted: state.DeletedAt.Valid}, nil
		}
		if !common.RedisEnabled || common.RDB == nil {
			return nil, ErrTokenAPICache
		}
		if state.DeletedAt.Valid {
			if err := publishCommittedUserAuthVersion(state.UserID, state.PendingAuthVersion); err != nil {
				return nil, err
			}
			if err := invalidateUserCache(state.UserID); err != nil {
				return nil, err
			}
		} else if err := PublishUserAuthCache(state.UserID); err != nil {
			return nil, err
		}
		if _, err := revokeUserSessions(state.UserID, "", "user_security_changed", state.PendingAuthVersion); err != nil {
			return nil, err
		}
		if err := InvalidateUserTokensCache(state.UserID); err != nil {
			return nil, err
		}
		if err := DB.WithContext(ctx).Model(&TokenAPIManagedUser{}).
			Where("account_id = ? AND revision = ? AND pending_auth_version = ?", accountID, state.Revision, state.PendingAuthVersion).
			UpdateColumn("pending_auth_version", 0).Error; err != nil {
			return nil, err
		}
	}
	return nil, ErrTokenAPICache
}

func ChangeTokenAPIManagedUser(ctx context.Context, accountID string, userID int, action string, expected int64) (*TokenAPIManagedSnapshot, error) {
	if !ValidTokenAPIAccountID(accountID) || userID <= 0 || expected < 0 || expected == math.MaxInt64 ||
		(action != "enable" && action != "disable" && action != "delete") {
		return nil, ErrTokenAPIInvalid
	}
	var ack TokenAPIManagedSnapshot
	err := DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if common.UsingMainDatabase(common.DatabaseTypeSQLite) {
			// SQLite has no SELECT FOR UPDATE. Acquire its write lock before
			// reading the revision or publishing an authentication deny fence.
			if err := tx.Model(&TokenAPIManagedUser{}).Where("account_id = ?", accountID).
				UpdateColumn("revision", gorm.Expr("revision")).Error; err != nil {
				return err
			}
		}
		var binding TokenAPIManagedUser
		if err := lockForUpdate(tx).First(&binding, "account_id = ?", accountID).Error; err != nil {
			return err
		}
		if binding.UserID != userID {
			return ErrTokenAPIForbidden
		}
		var user User
		if err := lockForUpdate(tx.Unscoped()).First(&user, userID).Error; err != nil {
			return err
		}
		if user.Role != common.RoleCommonUser {
			return ErrTokenAPIForbidden
		}
		if binding.Revision != expected || user.DeletedAt.Valid {
			return ErrTokenAPIConflict
		}
		target := common.UserStatusDisabled
		if action == "enable" {
			target = common.UserStatusEnabled
		}
		version := max(user.AuthVersion, 1)
		if user.Status != target || action == "delete" {
			var err error
			version, err = IncrementUserAuthVersionWithTx(tx, userID)
			if err != nil {
				return err
			}
			if err := tx.Model(&user).UpdateColumn("status", target).Error; err != nil {
				return err
			}
		}
		if action == "delete" {
			if _, err := DeleteUserAccessTokensWithTx(tx, userID); err != nil {
				return err
			}
			if err := tx.Delete(&user).Error; err != nil {
				return err
			}
		}
		result := tx.Model(&TokenAPIManagedUser{}).Where("account_id = ? AND revision = ?", accountID, expected).
			Updates(map[string]any{"revision": expected + 1, "pending_auth_version": version})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrTokenAPIConflict
		}
		ack = TokenAPIManagedSnapshot{AccountID: accountID, UserID: userID, Revision: expected + 1, Status: target, Deleted: action == "delete"}
		return nil
	})
	if err != nil {
		return nil, err
	}
	common.SysLog(fmt.Sprintf("TokenAPI managed user lifecycle committed (account_id=%s, user_id=%d, action=%s, revision=%d)", accountID, userID, action, ack.Revision))
	if _, err := GetTokenAPIManagedUser(ctx, accountID); err != nil {
		return nil, err
	}
	return &ack, nil
}
