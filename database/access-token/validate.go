package accesstoken

import (
	"sso-oauth2/common"
	"time"
)

func Validate(accessToken, scopes, username string) (*ValidateResult, error) {
	tokenInfo, err := ReadToken(accessToken)
	if err != nil {
		if err.Error() == "Token not found" {
			return nil, &ErrorTokenNotFound
		}
		return nil, err
	}
	if tokenInfo == nil {
		return nil, &ErrorTokenNotFound
	}
	if tokenInfo.ExpireTime.Before(time.Now()) {
		return nil, &ErrorTokenExpired
	}
	requestScopes := common.StringToSet(scopes)
	if requestScopes != nil {
		for scope, _ := range requestScopes {
			if !tokenInfo.Scopes[scope] {
				return nil, &ErrorInvalidScope
			}
		}
	}
	return &ValidateResult{
		Token:    accessToken,
		Scopes:   scopes,
		ClientID: tokenInfo.Client,
	}, nil
}
