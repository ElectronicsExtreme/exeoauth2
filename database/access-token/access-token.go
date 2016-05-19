package accesstoken

import (
	"encoding/json"
	"errors"
	"log"
	//"os"
	//"strconv"
	"time"

	"github.com/boltdb/bolt"

	"dev.corp.extreme.co.th/exeoauth2/config"
	"dev.corp.extreme.co.th/exeoauth2/database"
)

const ()

var (
	db *bolt.DB
)

func init() {
	var err error
	db, err = bolt.Open(config.Default.Database.BoltDB.AccessTokenDB, 0600, nil)
	if err != nil {
		panic("fail to open database for access-token")
	}
	go deleteExpiredTokenTicker()
}

type TokenInfo struct {
	Token      string     `json:"token"`
	Client     string     `json:"client"`
	User       string     `json:"user"`
	UID        string     `json:"uid"`
	Scopes     string     `json:"scopes"`
	ExpireTime *time.Time `json:"expire-time"`
}

func GetTokenInfo(token string, client string) (*TokenInfo, error) {
	var tokenInfo *TokenInfo = nil

	err := db.View(func(tx *bolt.Tx) error {
		clientBucket := tx.Bucket([]byte(client))
		if clientBucket == nil {
			return nil
		}
		tokenJson := clientBucket.Get([]byte(token))
		if tokenJson == nil {
			return nil
		}
		tokenInfo = &TokenInfo{}
		err := json.Unmarshal(tokenJson, tokenInfo)
		return err
	})
	if err != nil {
		return nil, err
	}
	return tokenInfo, nil
}

func PutTokenInfo(tokenInfo *TokenInfo) error {
	oldTokenInfo, err := GetTokenInfo(tokenInfo.Token, tokenInfo.Client)
	if err != nil {
		return err
	}
	if oldTokenInfo != nil {
		return errors.New("duplicate token")
	}
	err = db.Update(func(tx *bolt.Tx) error {
		var clientBucket *bolt.Bucket
		clientBucket, err = tx.CreateBucketIfNotExists([]byte(tokenInfo.Client))
		if err != nil {
			return err
		}

		tokenJson, err := json.Marshal(tokenInfo)
		if err != nil {
			return err
		}

		err = database.AddKeyValue(clientBucket, tokenInfo.Token, tokenJson)
		return err
	})
	return err
}

func queryString(bucket *bolt.Bucket, key string) string {
	value := bucket.Get([]byte(key))
	if value == nil {
		return ""
	} else {
		return string(value)
	}
}

func deleteExpiredTokenTicker() {
	ticker := time.NewTicker(1 * time.Hour)
	for {
		<-ticker.C
		deleteExpiredToken()
	}
}

func deleteExpiredToken() {
	currentTime := time.Now()
	deleteTime := currentTime.Add(-1 * time.Hour)

	// get all token to be delete
	deleteToken := make(map[string][]string)
	err := db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(client []byte, bucket *bolt.Bucket) error {
			numberToken := 0
			deleteToken[string(client)] = make([]string, 0)
			err := bucket.ForEach(func(token []byte, tokenJson []byte) error {
				numberToken++
				tokenInfo := &TokenInfo{}
				err := json.Unmarshal(tokenJson, tokenInfo)
				if err != nil {
					deleteToken[string(client)] = append(deleteToken[string(client)], string(token))
					return nil
				}
				if tokenInfo.ExpireTime.Before(deleteTime) {
					deleteToken[string(client)] = append(deleteToken[string(client)], string(token))
				}
				return nil
			})
			if err != nil {
				return errors.New(string(client) + ": " + err.Error())
			}

			/*if config.Default.LogInfo.Request.Enable {
				logger, err := requestLogger()
				if err != nil {
					logger, errr := errorLogger()
					if errr != nil {
						log.Println("accesstoken :", errr)
					} else {
						logger.Println(err)
					}
					log.Println("accesstoken :", err)
				} else {
					logger.Println(string(client), "number of token", numberToken)
					logger.Println(string(client), "number of deleted token", len(deleteToken[string(client)]))
				}
			}*/
			return nil
		})
	})
	if err != nil {
		/*logger, errr := errorLogger()
		if errr != nil {
			log.Println("accesstoken :", errr)
		} else {
			logger.Println(err)
		}*/
		log.Println("accesstoken :", err)
	}

	// delete token
	for client, tokens := range deleteToken {
		err := db.Update(func(tx *bolt.Tx) error {
			clientBucket := tx.Bucket([]byte(client))
			if clientBucket == nil {
				return errors.New(string(client) + " bucket not found")
			}
			for _, token := range tokens {
				clientBucket.Delete([]byte(token))
			}
			return nil
		})
		if err != nil {
			/*logger, errr := errorLogger()
			if errr != nil {
				log.Println("accesstoken :", errr)
			} else {
				logger.Println(err)
			}*/
			log.Println("accesstoken :", err)
		}
	}

}

/*func requestLogger() (*log.Logger, error) {
	filename := RequestLog.Path + "/" + strconv.FormatInt(int64(time.Now().Year()), 10) + "-" + strconv.FormatInt(int64(time.Now().Month()), 10) + ".log"
	outfile, err := os.OpenFile(filename, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}
	return log.New(outfile, "accesstoken : ", log.Lshortfile|log.LstdFlags), nil
}

func errorLogger() (*log.Logger, error) {
	filename := ErrorLog.Path + "/" + strconv.FormatInt(int64(time.Now().Year()), 10) + "-" + strconv.FormatInt(int64(time.Now().Month()), 10) + ".log"
	outfile, err := os.OpenFile(filename, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}
	return log.New(outfile, "accesstoken : ", log.Lshortfile|log.LstdFlags), nil
}*/
