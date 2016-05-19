package user

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/boltdb/bolt"
	"github.com/dgrijalva/jwt-go"

	"dev.corp.extreme.co.th/exeoauth2/config"
	"dev.corp.extreme.co.th/exeoauth2/database"
)

const (
	userBucketName = "user"
	uidBucketName  = "uid"
)

const (
	ErrorUserMissMatch = iota
	ErrorJWTValidation
	ErrorInternal
)

var (
	db *bolt.DB
)

func init() {
	var err error
	db, err = bolt.Open(config.Default.Database.BoltDB.UserDB, 0600, nil)
	if err != nil {
		panic("fail to open database for access-token")
	}
	db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(userBucketName))
		if err != nil {
			return err
		}
		_, err = tx.CreateBucketIfNotExists([]byte(uidBucketName))
		return err
	})
	if err != nil {
		panic(err)
	}
}

type UserInfo struct {
	UID               string          `json:"uid"`
	Username          string          `json:"username"`
	EncryptedPassword []byte          `json:"password"`
	Salt              []byte          `json:"salt"`
	ActivatedClient   map[string]bool `json:"activated_client"`
	EmailActivated    bool            `json:"email-activated"`
}

func GetUserInfo(username string) (*UserInfo, error) {
	username = strings.ToLower(username)
	var userInfo *UserInfo
	err := db.View(func(tx *bolt.Tx) error {
		usersBucket := tx.Bucket([]byte(userBucketName))
		if usersBucket == nil {
			return errors.New("user bucket is missing")
		}
		userEncoded := usersBucket.Get([]byte(username))
		if userEncoded == nil {
			return nil
		}
		userInfo = &UserInfo{}

		err := json.Unmarshal(userEncoded, userInfo)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if userInfo != nil {
		if userInfo.ActivatedClient == nil {
			userInfo.ActivatedClient = make(map[string]bool)
		}
	}

	return userInfo, nil
}

func PutUserInfo(userInfo *UserInfo) error {
	oldUserInfo, err := GetUserInfo(userInfo.Username)
	if err != nil {
		return err
	}
	if oldUserInfo != nil {
		return errors.New("duplicate user")
	}
	err = db.Update(func(tx *bolt.Tx) error {
		usersBucket := tx.Bucket([]byte(userBucketName))
		uidBucket := tx.Bucket([]byte(uidBucketName))
		if usersBucket == nil {
			return errors.New("user bucket is missing")
		}
		if uidBucket == nil {
			return errors.New("uid bucket is missing")
		}

		userJson, err := json.Marshal(userInfo)
		if err != nil {
			return err
		}

		err = database.AddKeyValue(usersBucket, strings.ToLower(userInfo.Username), userJson)
		if err != nil {
			return err
		}

		err = database.AddKeyValue(uidBucket, userInfo.UID, strings.ToLower(userInfo.Username))
		if err != nil {
			return err
		}
		return nil
	})
	return err
}

func UpdateUserInfo(userInfo *UserInfo) error {
	oldUserInfo, err := GetUserInfo(userInfo.Username)
	if err != nil {
		return err
	}
	if oldUserInfo == nil {
		return errors.New("requested user not found")
	}
	err = db.Update(func(tx *bolt.Tx) error {
		usersBucket := tx.Bucket([]byte(userBucketName))
		if usersBucket == nil {
			return errors.New("user bucket is missing")
		}

		userJson, err := json.Marshal(userInfo)
		if err != nil {
			return err
		}

		err = database.AddKeyValue(usersBucket, strings.ToLower(userInfo.Username), userJson)
		if err != nil {
			return err
		}
		return nil
	})
	return err
}

func DeleteUserInfo(username string) error {
	username = strings.ToLower(username)
	err := db.Update(func(tx *bolt.Tx) error {
		usersBucket := tx.Bucket([]byte(userBucketName))
		if usersBucket == nil {
			return errors.New("user bucket is missing")
		}
		userInfo, err := GetUserInfo(username)
		if err != nil {
			return err
		}
		err = usersBucket.Delete([]byte(userInfo.UID))
		if err != nil {
			return err
		}
		err = usersBucket.Delete([]byte(username))
		if err != nil {
			return err
		}
		return nil
	})
	return err
}

func ChangeUserPassword(username string, encryptedPassword []byte) error {
	userInfo, err := GetUserInfo(username)
	if err != nil {
		return err
	}
	userInfo.EncryptedPassword = encryptedPassword
	err = UpdateUserInfo(userInfo)
	if err != nil {
		return err
	}
	return nil
}

func ActivateClient(username string, client string) error {
	userInfo, err := GetUserInfo(username)
	if err != nil {
		return err
	}
	userInfo.ActivatedClient[client] = true
	err = UpdateUserInfo(userInfo)
	if err != nil {
		return err
	}
	return nil
}

func GetEmailActivationString(userInfo *UserInfo) (string, error) {
	token := jwt.New(jwt.SigningMethodHS512)
	token.Claims["username"] = userInfo.Username
	return token.SignedString(userInfo.Salt)
}

func ValidateEmailActivationString(tokenString string, userInfo *UserInfo) (bool, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		tokenUsername, ok := token.Claims["username"].(string)
		if !ok {
			return nil, &ValidateEmailActivationError{
				ErrorCode:    ErrorJWTValidation,
				ErrorMessage: "jwt token store wrong variable type",
			}
		}
		if userInfo.Username != tokenUsername {
			return nil, &ValidateEmailActivationError{
				ErrorCode:    ErrorUserMissMatch,
				ErrorMessage: "the requsted username is not match with token",
			}
		}
		return userInfo.Salt, nil
	})
	if err != nil {
		switch err := err.(type) {
		case *ValidateEmailActivationError:
			return false, err
		case *jwt.ValidationError:
			return false, &ValidateEmailActivationError{
				ErrorCode:    ErrorJWTValidation,
				ErrorMessage: err.Error(),
			}
		default:
			return false, &ValidateEmailActivationError{
				ErrorCode:    ErrorInternal,
				ErrorMessage: err.Error(),
			}
		}
	}
	return token.Valid, nil
}

type ValidateEmailActivationError struct {
	ErrorCode    uint
	ErrorMessage string
}

func (self *ValidateEmailActivationError) Error() string {
	return self.ErrorMessage
}
