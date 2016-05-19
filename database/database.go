package database

import (
	"github.com/boltdb/bolt"
	"strings"
	"time"
)

const ()

var ()

func init() {
}

func AddKeyValue(bucket *bolt.Bucket, key string, value interface{}) error {
	switch value := value.(type) {
	case string:
		if value != "" {
			return bucket.Put([]byte(key), []byte(value))
		}
	case []byte:
		if value != nil {
			return bucket.Put([]byte(key), value)
		}
	case map[string]bool:
		if value != nil {
			return bucket.Put([]byte(key), []byte(SetToString(value)))
		}
	case *time.Time:
		if value != nil {
			timeByte, err := value.MarshalBinary()
			if err != nil {
				return err
			}
			return bucket.Put([]byte(key), timeByte)
		}
	case time.Time:
		if !value.IsZero() {
			timeByte, err := value.MarshalBinary()
			if err != nil {
				return err
			}
			return bucket.Put([]byte(key), timeByte)
		}
	case bool:
		if value {
			return bucket.Put([]byte(key), []byte("true"))
		} else {
			return bucket.Put([]byte(key), []byte("false"))
		}
	}
	return nil
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
