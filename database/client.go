package database

import (
	"fmt"
	"reflect"

	"gopkg.in/redis.v3"
)

const ()

var ()

func init() {
}

type ClientInfo struct {
	ClientUsername         string          `redis:"ClientUsername"`
	EncryptedPassword      []byte          `redis:"EncryptedPassword"`
	Salt                   []byte          `redis:"Salt"`
	OwnerUsername          string          `redis:"OwnerUsername"`
	OwnerUID               string          `redis:"OwnerUID"`
	ClientName             string          `redis:"ClientName"`
	Description            string          `redis:"Description"`
	GrantAuthorizationCode map[string]bool `redis:"GrantAuthorizationCode"`
	GrantImplicit          map[string]bool `redis:"GrantImplicit"`
	GrantResourceOwner     map[string]bool `redis:"GrantResourceOwner"`
	GrantClientCredentials map[string]bool `redis:"GrantClientCredentials"`
	RedirectURIAuthorCode  string          `redis:"RedirectURIAuthorCode"`
	RedirectURIImplicit    string          `redis:"RedirectURIImplicit"`
}

func clientKey(username string) string {
	return "Clients:" + username + ":"
}

func (self *Client) GetClientInfo(username string) (*ClientInfo, error) {
	clientInfo := &ClientInfo{}

	typ := reflect.TypeOf(clientInfo).Elem()
	val := reflect.ValueOf(clientInfo).Elem()

	key := clientKey(username)
	exist, err := self.IsClientExist(username)
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
			res := self.client.Get(key + tfield.Tag.Get("redis"))
			if err := res.Err(); err != nil {
				if err == redis.Nil {
					continue
				} else {
					return nil, err
				}
			}
			vfield.SetString(res.Val())
		case reflect.TypeOf([]byte("")): // []byte type
			res := self.client.Get(key + tfield.Tag.Get("redis"))
			if err := res.Err(); err != nil {
				if err == redis.Nil {
					continue
				} else {
					return nil, err
				}
			}
			b, err := res.Bytes()
			if err != nil {
				return nil, err
			}
			vfield.SetBytes(b)
		case reflect.TypeOf(make(map[string]bool)): // map[string]bool type
			res := self.client.SMembers(key + tfield.Tag.Get("redis"))
			if err := res.Err(); err != nil {
				if err == redis.Nil {
					continue
				} else {
					return nil, err
				}
			}
			if len(res.Val()) == 0 {
				continue
			}
			vfield.Set(reflect.MakeMap(reflect.TypeOf(make(map[string]bool))))
			for _, k := range res.Val() {
				vfield.SetMapIndex(reflect.ValueOf(k), reflect.ValueOf(true))
			}

		default:
			return nil, fmt.Errorf("Unknown struct field type %v in struct %v", vfield.Type(), val.Type())
		}
	}
	return clientInfo, nil
}

func (self *Client) IsClientExist(username string) (bool, error) {
	//username = strings.ToLower(username)
	//self.client.Set("isClientExist", "1", 0)
	key := clientKey(username)
	tfield, _ := reflect.TypeOf(&ClientInfo{}).Elem().FieldByName("ClientUsername")
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

func (self *Client) PutClientInfo(clientInfo *ClientInfo) error {
	exist, err := self.IsClientExist(clientInfo.ClientUsername)
	if err != nil {
		return err
	}
	if exist {
		return fmt.Errorf("duplicate client username")
	}
	return self.setClientInfo(clientInfo)
}

func (self *Client) setClientInfo(clientInfo *ClientInfo) error {
	typ := reflect.TypeOf(clientInfo).Elem()
	val := reflect.ValueOf(clientInfo).Elem()

	key := clientKey(clientInfo.ClientUsername)
	for i := 0; i < typ.NumField(); i++ {
		tfield := typ.Field(i)
		vfield := val.Field(i)
		if tfield.Tag.Get("redis") == "-" {
			continue
		}
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
		case reflect.TypeOf(make(map[string]bool)): // map[string]bool type
			if vfield.IsNil() {
				self.client.Del(key + tfield.Tag.Get("redis"))
				continue
			} else if vfield.Len() == 0 {
				self.client.Del(key + tfield.Tag.Get("redis"))
			} else {
				for _, k := range vfield.MapKeys() {
					if vfield.MapIndex(k).Bool() {
						self.client.SAdd(key+tfield.Tag.Get("redis"), k.String())
					}
				}
			}
		default:
			return fmt.Errorf("Unknown struct field type %v in struct %v", vfield.Type(), val.Type())
		}
	}
	return nil
}

/*func getGrantScopes(bucket *bolt.Bucket, grant string) map[string]bool {
	scopesByte := bucket.Get([]byte(grant))
	if scopesByte == nil {
		return nil
	}
	return database.StringToSet(string(scopesByte))
}*/
