package database

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"gopkg.in/redis.v3"
)

const ()

var ()

func init() {
}

type AccessTokenInfo struct {
	Token      string          `json:"token" redis:"-"`
	Client     string          `json:"client" redis:"Client"`
	User       string          `json:"user" redis:"User"`
	UID        string          `json:"uid" redis:"UID"`
	Scopes     map[string]bool `json:"scopes" redis:"Scopes"`
	ExpireTime time.Time       `json:"expire-time" redis:"ExpireTime"`
}

func accessTokenKey(token string) string {
	return "AccessTokens:" + token
}

func (self *Client) GetAccessTokenInfo(token string) (*AccessTokenInfo, error) {
	tokenInfo := &AccessTokenInfo{}
	tokenInfo.Token = token

	typ := reflect.TypeOf(tokenInfo).Elem()
	val := reflect.ValueOf(tokenInfo).Elem()

	key := accessTokenKey(token)
	exist, err := self.isAccessTokenExist(token)
	if err != nil {
		return nil, err
	}
	if !exist {
		return nil, nil
	}

	for i := 0; i < typ.NumField(); i++ {
		tfield := typ.Field(i)
		vfield := val.Field(i)
		if tfield.Tag.Get("redis") == "-" {
			continue
		}
		switch vfield.Type() {
		case reflect.TypeOf(""): // string type
			res := self.client.HGet(key, tfield.Tag.Get("redis"))
			if err := res.Err(); err != nil {
				if err == redis.Nil {
					continue
				} else {
					return nil, err
				}
			}
			vfield.SetString(res.Val())
		case reflect.TypeOf(make(map[string]bool)): // map[string]bool type
			res := self.client.HGet(key, tfield.Tag.Get("redis"))
			if err := res.Err(); err != nil {
				if err == redis.Nil {
					continue
				} else {
					return nil, err
				}
			}
			scopeSlice := strings.Split(res.Val(), ",")
			vfield.Set(reflect.MakeMap(reflect.TypeOf(make(map[string]bool))))
			for _, scope := range scopeSlice {
				vfield.SetMapIndex(reflect.ValueOf(scope), reflect.ValueOf(true))
			}
		case reflect.TypeOf(time.Time{}): // Time type
			res := self.client.HGet(key, tfield.Tag.Get("redis"))
			if err := res.Err(); err != nil {
				if err == redis.Nil {
					continue
				} else {
					return nil, err
				}
			}
			exp, err := time.Parse(time.RFC3339Nano, res.Val())
			if err != nil {
				return nil, err
			}
			vfield.Set(reflect.ValueOf(exp))
		default:
			return nil, fmt.Errorf("Unknown struct field type %v in struct %v", vfield.Type(), val.Type())
		}
	}
	return tokenInfo, nil
}

func (self *Client) isAccessTokenExist(token string) (bool, error) {
	//username = strings.ToLower(username)
	//self.client.Set("isClientExist", "1", 0)
	res := self.client.HKeys(accessTokenKey(token))
	err := res.Err()
	if err == nil {
		if len(res.Val()) == 0 {
			return false, nil
		}
		return true, nil
	} else {
		if err == redis.Nil {
			return false, nil
		} else {
			return false, err
		}
	}

}

func (self *Client) PutAccessTokenInfo(tokenInfo *AccessTokenInfo) error {
	oldTokenInfo, err := self.GetAccessTokenInfo(tokenInfo.Token)
	if err != nil {
		return err
	}
	if oldTokenInfo != nil {
		return fmt.Errorf("duplicate token")
	}
	return self.setAccessTokenInfo(tokenInfo)
}

func (self *Client) setAccessTokenInfo(accessTokenInfo *AccessTokenInfo) error {
	typ := reflect.TypeOf(accessTokenInfo).Elem()
	val := reflect.ValueOf(accessTokenInfo).Elem()

	key := accessTokenKey(accessTokenInfo.Token)
	for i := 0; i < typ.NumField(); i++ {
		tfield := typ.Field(i)
		vfield := val.Field(i)
		if tfield.Tag.Get("redis") == "-" {
			continue
		}
		switch vfield.Type() {
		case reflect.TypeOf(""): // string type
			if vfield.String() == "" {
				self.client.HDel(key, tfield.Tag.Get("redis"))
			} else {
				self.client.HSet(key, tfield.Tag.Get("redis"), vfield.String())
			}
		case reflect.TypeOf(make(map[string]bool)): // map[string]bool type
			if vfield.IsNil() {
				self.client.HDel(key, tfield.Tag.Get("redis"))
				continue
			} else if vfield.Len() == 0 {
				self.client.HDel(key, tfield.Tag.Get("redis"))
			} else {
				scopes := ""
				for _, k := range vfield.MapKeys() {
					if vfield.MapIndex(k).Bool() {
						scopes = scopes + k.String() + ","
					}
				}
				self.client.HSet(key, tfield.Tag.Get("redis"), scopes[:len(scopes)-1])
			}
		case reflect.TypeOf(time.Time{}): // time.Time type
			if vfield.MethodByName("IsZero").Call(nil)[0].Bool() {
				self.client.HDel(key, tfield.Tag.Get("redis"))
				continue
			} else {
				method := vfield.MethodByName("Format")
				arg := append(make([]reflect.Value, 0), reflect.ValueOf(time.RFC3339Nano))
				vtime := method.Call(arg)[0].String()
				self.client.HSet(key, tfield.Tag.Get("redis"), vtime)
			}
		default:
			return fmt.Errorf("Unknown struct field type %v in struct %v", vfield.Type(), val.Type())
		}
	}
	if !accessTokenInfo.ExpireTime.IsZero() {
		self.client.ExpireAt(key, accessTokenInfo.ExpireTime.Add(time.Hour))
	}
	return nil
}

/*func queryString(bucket *bolt.Bucket, key string) string {
	value := bucket.Get([]byte(key))
	if value == nil {
		return ""
	} else {
		return string(value)
	}
}*/
