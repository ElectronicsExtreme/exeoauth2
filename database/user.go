package database

import (
	//"encoding/json"
	//"errors"
	"fmt"
	"reflect"
	"strings"

	"gopkg.in/redis.v3"
	//"github.com/boltdb/bolt"
	//"github.com/dgrijalva/jwt-go"
)

const (
	ErrorUserMissMatch = iota
	ErrorJWTValidation
	ErrorInternal
)

var ()

func init() {
}

type UserInfo struct {
	UID               string `json:"uid" redis:"UID"`
	Username          string `json:"username" redis:"Username"`
	EncryptedPassword []byte `json:"password" redis:"EncryptedPassword"`
	Salt              []byte `json:"salt" redis:"Salt"`
}

func (self *Client) GetUserInfo(username string) (*UserInfo, error) {
	username = strings.ToLower(username)
	userInfo := &UserInfo{}

	typ := reflect.TypeOf(userInfo).Elem()
	val := reflect.ValueOf(userInfo).Elem()

	key := "Users:" + username + ":"
	exist, err := self.isUserExist(username)
	if err != nil {
		return nil, err
	}
	if !exist {
		return nil, nil
	}

	for i := 0; i < typ.NumField(); i++ {
		tfield := typ.Field(i)
		vfield := val.Field(i)
		res := self.client.Get(key + tfield.Tag.Get("redis"))
		if err := res.Err(); err != nil {
			if err == redis.Nil {
				continue
			} else {
				return nil, err
			}
		}
		switch vfield.Type() {
		case reflect.TypeOf(""): // string type
			vfield.SetString(res.Val())
		case reflect.TypeOf([]byte("")): // []byte type
			b, err := res.Bytes()
			if err != nil {
				return nil, err
			}
			vfield.SetBytes(b)
		default:
			return nil, fmt.Errorf("Unknown struct field type %v in struct %v", vfield.Type(), val.Type())
		}
	}

	return userInfo, nil
}

func (self *Client) isUserExist(username string) (bool, error) {
	username = strings.ToLower(username)

	key := "Users:" + username + ":"
	tfield, _ := reflect.TypeOf(&UserInfo{}).Elem().FieldByName("Username")
	res := self.client.Get(key + tfield.Tag.Get("redis"))
	err := res.Err()
	if err == nil {
		return true, nil
	} else {
		if err == redis.Nil {
			return false, nil
		} else {
			return false, err
		}
	}

}

func (self *Client) PutUserInfo(userInfo *UserInfo) error {
	exist, err := self.isUserExist(userInfo.Username)
	if err != nil {
		return err
	}
	if exist {
		return fmt.Errorf("duplicate user")
	}
	return self.setUserInfo(userInfo)
}

func (self *Client) UpdateUserInfo(userInfo *UserInfo) error {
	exist, err := self.isUserExist(userInfo.Username)
	if err != nil {
		return err
	}
	if !exist {
		return fmt.Errorf("requested user not found")
	}
	return self.setUserInfo(userInfo)
}

func (self *Client) setUserInfo(userInfo *UserInfo) error {
	username := strings.ToLower(userInfo.Username)

	typ := reflect.TypeOf(userInfo).Elem()
	val := reflect.ValueOf(userInfo).Elem()
	key := "Users:" + username + ":"
	for i := 0; i < typ.NumField(); i++ {
		tfield := typ.Field(i)
		vfield := val.Field(i)
		switch vfield.Type() {
		case reflect.TypeOf(""): // string type
			if vfield.String() == "" {
				self.client.Del(key + tfield.Tag.Get("redis"))
			} else {
				self.client.Set(key+tfield.Tag.Get("redis"), vfield.String(), 0)
			}
		case reflect.TypeOf([]byte("")): // []byte type
			if vfield.Bytes() == nil {
				self.client.Del(key + tfield.Tag.Get("redis"))
				continue
			} else {
				self.client.Set(key+tfield.Tag.Get("redis"), vfield.Bytes(), 0)
			}
		default:
			return fmt.Errorf("Unknown struct field type %v in struct %v", vfield.Type(), val.Type())
		}
	}
	return nil
}

func (self *Client) DeleteUserInfo(username string) error {
	username = strings.ToLower(username)

	exist, err := self.isUserExist(username)
	if err != nil {
		return err
	}
	if !exist {
		return fmt.Errorf("user is not exist")
	}

	typ := reflect.TypeOf(&UserInfo{}).Elem()
	key := "Users:" + username + ":"
	for i := 0; i < typ.NumField(); i++ {
		tfield := typ.Field(i)
		self.client.Del(key + tfield.Tag.Get("redis"))
	}
	return nil
}

/*func ChangeUserPassword(username string, encryptedPassword []byte) error {
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
}*/
