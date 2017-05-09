package database

import (
	"strings"

	"gopkg.in/redis.v3"

	"exeoauth2/config"
)

const ()

var ()

func init() {
}

type Client struct {
	client *redis.Client
}

func NewClient() (*Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     config.Default.Database.Redis.Address,
		Password: config.Default.Database.Redis.Password,
		DB:       int64(config.Default.Database.Redis.DB),
	})

	_, err := client.Ping().Result()
	if err != nil {
		return nil, err
	}
	return &Client{client}, nil
}

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
