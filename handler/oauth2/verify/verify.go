package verify

import (
	"reflect"
	"strings"

	"dev.corp.extreme.co.th/exeoauth2/database"
	"dev.corp.extreme.co.th/exeoauth2/encrypt"
	"dev.corp.extreme.co.th/exeoauth2/handler/oauth2"
)

func Init() {
}

func VerifyClientPassword(clientInfo *database.ClientInfo, password string) bool {
	enteredEncryptPassword := encrypt.EncryptText1Way([]byte(password), []byte(string(clientInfo.Salt)))
	if !reflect.DeepEqual(clientInfo.EncryptedPassword, enteredEncryptPassword) {
		return false
	}
	return true
}

func VerifyUserPassword(userInfo *database.UserInfo, password string) bool {
	enteredEncryptPassword := encrypt.EncryptText1Way([]byte(password), []byte(string(userInfo.Salt)))
	if !reflect.DeepEqual(userInfo.EncryptedPassword, enteredEncryptPassword) {
		return false
	}
	return true
}

func VerifyGrantScopes(clientInfo *database.ClientInfo, grantType string, scopes string) bool {
	var clientScope map[string]bool
	switch grantType {
	case oauth2.ResourceOwnerCredentialsGrant:
		clientScope = clientInfo.GrantResourceOwner
	case oauth2.ClientCredentialsGrant:
		clientScope = clientInfo.GrantClientCredentials
	}

	scopeSlice := strings.Split(scopes, ",")
	for _, scope := range scopeSlice {
		if !clientScope[scope] {
			return false
		}
	}
	return true
}
