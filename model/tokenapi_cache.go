package model

import (
	"fmt"
	"os"
)

func tokenAPIQuotaVersionKey(userID int) string {
	return fmt.Sprintf("tokenapi:quota:revision:{%s}", getUserCacheKey(userID))
}

// tokenAPIQuotaCacheSnapshot binds a cold wallet cache to the grant revision
// visible in the same SQL statement. A separately read revision could label an
// old wallet with a newer grant and silently discard a negative delta.
func tokenAPIQuotaCacheSnapshot(user *UserBase, includeQuota bool) (int64, string, error) {
	if !includeQuota || os.Getenv("TOKENAPI_INTERNAL_SECRET") == "" {
		return 0, "0", nil
	}
	var snapshot struct {
		Quota    int
		Revision int64
	}
	err := DB.Table("users").
		Select("users.quota, COALESCE(tokenapi_quota_grants.revision, 0) AS revision").
		Joins("LEFT JOIN tokenapi_quota_grants ON tokenapi_quota_grants.user_id = users.id").
		Where("users.id = ? AND users.deleted_at IS NULL", user.Id).Take(&snapshot).Error
	if err != nil {
		return 0, "1", err
	}
	user.Quota = snapshot.Quota
	return snapshot.Revision, "1", nil
}
