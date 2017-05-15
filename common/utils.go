package common

import (
	"strings"
)

func SetToString(scopeMap map[string]bool) string {
	var scopes string
	for key, value := range scopeMap {
		if value {
			scopes += key + ","
		}
	}
	if len(scopes) == 0 {
		return ""
	}
	return scopes[:len(scopes)-1]
}

func StringToSet(scopesString string) map[string]bool {
	if scopesString == "" {
		return nil
	}
	scopes := strings.Split(scopesString, ",")
	scopeMap := make(map[string]bool)
	for _, scope := range scopes {
		scopeMap[scope] = true
	}
	return scopeMap
}
