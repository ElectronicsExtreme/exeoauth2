package accesstoken

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gopkg.in/redis.v5"

	"exeoauth2/config"
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
		DB:       conf.AccessTokenDB,
	})

	_, err := RedisClient.Ping().Result()

	if err != nil {
		panic(fmt.Sprintf("Cannot initialize redis client (package client): %v", err.Error()))
	}
}

type AccessTokenInfo struct {
	Token      string          `json:"token"`
	Client     string          `json:"client"`
	Scopes     map[string]bool `json:"scopes"`
	ExpireTime time.Time       `json:"expire-time"`
}

func accessTokenKey(token string) string {
	return "accesstoken:" + token
}

func ReadToken(token string) (*AccessTokenInfo, error) {
	key := accessTokenKey(token)

	tokenJson, err := RedisClient.Get(key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}

	tokenInfo := &AccessTokenInfo{}
	if err := json.Unmarshal(tokenJson, tokenInfo); err != nil {
		return nil, err
	}
	return tokenInfo, nil
}

// CreateClient encode client object and store it in database
func CreateToken(tokenInfo *AccessTokenInfo) error {
	if tokenInfo.Token == "" {
		return errors.New("token is empty")
	}
	key := accessTokenKey(tokenInfo.Token)
	exist, err := RedisClient.Exists(key).Result()
	if err != nil {
		return err
	}
	if exist {
		return errors.New("duplicate access-token")
	}

	tokenJson, err := json.Marshal(tokenInfo)
	if err != nil {
		return err
	}

	ttl := time.Duration(config.Config.AccessToken.TTLExpired) * time.Second
	val, err := RedisClient.Set(key, tokenJson, tokenInfo.ExpireTime.Add(ttl).Sub(time.Now())).Result()
	if err != nil {
		return err
	}
	if val != "OK" {
		return errors.New("Set command result's not OK")
	}
	return nil
}
