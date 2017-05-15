package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gopkg.in/redis.v5"

	"exeoauth2/common"
	"exeoauth2/common/encrypt"
	"exeoauth2/config"
	"exeoauth2/handler/oauth2"
)

const ()

var (
	conf        = config.Config.Database.Redis
	RedisClient *redis.Client
)

func init() {
	RedisClient = redis.NewClient(&redis.Options{
		Addr:     conf.Address,
		Password: conf.Password,
		DB:       conf.ClientDB,
	})

	_, err := RedisClient.Ping().Result()

	if err != nil {
		panic(fmt.Sprintf("Cannot initialize redis client (package client): %v", err.Error()))
	}
}

// ClientInfo store all info about client in one struct which.
type ClientInfo struct {
	ClientID               string          `json:"client_id"`
	EncryptedClientSecret  []byte          `json:"client_secret"`
	GrantClientCredentials map[string]bool `json:"client_credentials_scope"`
	Description            string          `json:"description"`
	Salt                   []byte          `json:"salt"`
	CreateDate             time.Time       `json:"create_date"`
	UpdateDate             time.Time       `json:"update_date"`
	CurrentRefreshToken    string          `json:"current_refresh_token,omitempty"`
}

func (c *ClientInfo) VerifySecret(secret string) bool {
	return bytes.Equal(encrypt.EncryptText1Way([]byte(secret), c.Salt), c.EncryptedClientSecret)
}

func (c *ClientInfo) VerifyGrantScopes(grantType, scopes string) bool {
	var clientScopes map[string]bool
	switch grantType {
	case oauth2.ClientCredentialsGrant:
		clientScopes = c.GrantClientCredentials
	}

	reqScopes := common.StringToSet(scopes)
	for scope, val := range reqScopes {
		if val && !clientScopes[scope] {
			return false
		}
	}
	return true
}

// ReadClient get all client data from database and return as an object.
func ReadClient(clientID string) (*ClientInfo, error) {
	key := clientKey(clientID)

	clientJson, err := RedisClient.Get(key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}

	clientInfo := &ClientInfo{}
	if err := json.Unmarshal(clientJson, clientInfo); err != nil {
		return nil, err
	}
	return clientInfo, nil
}

// CreateClient encode client object and store it in database
func CreateClient(clientInfo *ClientInfo) error {
	key := clientKey(clientInfo.ClientID)
	exist, err := RedisClient.Exists(key).Result()
	if err != nil {
		return err
	}
	if exist {
		return errors.New("duplicate client id")
	}

	clientJson, err := json.Marshal(clientInfo)
	if err != nil {
		return err
	}

	val, err := RedisClient.Set(key, clientJson, 0).Result()
	if err != nil {
		return err
	}
	if val != "OK" {
		return errors.New("Set command result's not OK")
	}
	return nil
}

// UpdateClient update the existed client with the new client object.
func UpdateClient(clientInfo *ClientInfo) error {
	key := clientKey(clientInfo.ClientID)
	exist, err := RedisClient.Exists(key).Result()
	if err != nil {
		return err
	}
	if !exist {
		return errors.New("client not found")
	}

	clientJson, err := json.Marshal(clientInfo)
	if err != nil {
		return err
	}

	val, err := RedisClient.Set(key, clientJson, 0).Result()
	if err != nil {
		return err
	}
	if val != "OK" {
		return errors.New("Set command result is not OK")
	}
	return nil
}

// DeleteClient update the existed client with the new client object.
func DeleteClient(clientID string) error {
	key := clientKey(clientID)
	exist, err := RedisClient.Exists(key).Result()
	if err != nil {
		return err
	}
	if !exist {
		return errors.New("client not found")
	}

	val, err := RedisClient.Del(key).Result()
	if err != nil {
		return err
	}
	if val == 0 {
		return errors.New("client not found")
	}

	return nil
}

// clientKey receive clientname and return key to access that client
func clientKey(clientUsername string) string {
	return fmt.Sprintf("client:%v", clientUsername)
}

func ValidateScope(scopes map[string]bool) bool {
	return true
}
