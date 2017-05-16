package user

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gopkg.in/redis.v5"

	"exeoauth2/common/encrypt"
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
		DB:       conf.UserDB,
	})

	_, err := RedisClient.Ping().Result()

	if err != nil {
		panic(fmt.Sprintf("Cannot initialize redis client (package client): %v", err.Error()))
	}
}

// UserInfo store all info about user in one struct.
type UserInfo struct {
	Username          string    `json:"username"`
	EncryptedPassword []byte    `json:"encrypted_password"`
	Salt              []byte    `json:"salt"`
	Password          string    `json:"-"`
	Email             string    `json:"email"`
	CreateDate        time.Time `json:"create_date"`
	UpdateDate        time.Time `json:"update_date"`
}

func (u *UserInfo) VerifyPassword(password string) bool {
	return bytes.Equal(encrypt.EncryptText1Way([]byte(password), u.Salt), u.EncryptedPassword)
}

// ReadUser get all user data from database and return as an object.
func ReadUser(username string) (*UserInfo, error) {
	key := userKey(username)
	userJson, err := RedisClient.Get(key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}

	userInfo := &UserInfo{}
	if err := json.Unmarshal(userJson, userInfo); err != nil {
		return nil, err
	}
	return userInfo, nil
}

// CreateUser encode user object and store it in database
func CreateUser(userInfo *UserInfo) error {
	key := userKey(userInfo.Username)
	exist, err := RedisClient.Exists(key).Result()
	if err != nil {
		return err
	}
	if exist {
		return errors.New("duplicate user id")
	}

	userJson, err := json.Marshal(userInfo)
	if err != nil {
		return err
	}

	val, err := RedisClient.Set(key, userJson, 0).Result()
	if err != nil {
		return err
	}
	if val != "OK" {
		return errors.New("Set command result's not OK")
	}
	return nil
}

// UpdateUser update the existed user with the new user object.
func UpdateUser(userInfo *UserInfo) error {
	key := userKey(userInfo.Username)
	exist, err := RedisClient.Exists(key).Result()
	if err != nil {
		return err
	}
	if !exist {
		return errors.New("user not found")
	}

	userJson, err := json.Marshal(userInfo)
	if err != nil {
		return err
	}

	val, err := RedisClient.Set(key, userJson, 0).Result()
	if err != nil {
		return err
	}
	if val != "OK" {
		return errors.New("Set command result is not OK")
	}
	return nil
}

// DeleteUser the specified user..
func DeleteUser(userID string) error {
	key := userKey(userID)
	exist, err := RedisClient.Exists(key).Result()
	if err != nil {
		return err
	}
	if !exist {
		return errors.New("user not found")
	}

	val, err := RedisClient.Del(key).Result()
	if err != nil {
		return err
	}
	if val == 0 {
		return errors.New("user not found")
	}

	return nil
}

// userKey receive username and return key to access that user
func userKey(username string) string {
	return fmt.Sprintf("user:%v", username)
}
