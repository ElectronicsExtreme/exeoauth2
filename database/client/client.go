package client

import (
	"errors"
	"github.com/boltdb/bolt"
	"time"

	"dev.corp.extreme.co.th/exeoauth2/config"
	"dev.corp.extreme.co.th/exeoauth2/database"
)

const ()

var (
	db *bolt.DB
)

func init() {
	var err error
	db, err = bolt.Open(config.Default.Database.BoltDB.ClientDB, 0600, nil)
	if err != nil {
		panic("fail to open database for access-token")
	}
}

type ClientInfo struct {
	ClientUsername         string
	EncryptedPassword      []byte
	OwnerUsername          string
	OwnerUID               string
	GrantAuthorizationCode map[string]bool
	GrantImplicit          map[string]bool
	GrantResourceOwner     map[string]bool
	GrantClientCredentials map[string]bool
	RedirectURIAuthorCode  string
	RedirectURIImplicit    string
	ClientName             string
	Description            string
	Salt                   []byte
	CreateDate             time.Time
	UpdateDate             time.Time
	CreateUser             string
	UpdateUser             string
	CreateIP               string
	UpdateIP               string
	RequireActivate        bool
}

func GetClientInfo(username string) (*ClientInfo, error) {
	var clientInfo *ClientInfo
	err := db.View(func(tx *bolt.Tx) error {
		clientBucket := tx.Bucket([]byte(username))
		if clientBucket == nil {
			return nil
		}
		clientInfo = &ClientInfo{}
		clientInfo.ClientUsername = string(clientBucket.Get([]byte("client_username")))
		clientInfo.EncryptedPassword = clientBucket.Get([]byte("client_password"))
		clientInfo.OwnerUsername = string(clientBucket.Get([]byte("owner_username")))
		clientInfo.GrantAuthorizationCode = getGrantScopes(clientBucket, "authorization_code")
		clientInfo.GrantImplicit = getGrantScopes(clientBucket, "implicit")
		clientInfo.GrantResourceOwner = getGrantScopes(clientBucket, "resource_owner_credential")
		clientInfo.GrantClientCredentials = getGrantScopes(clientBucket, "client_credential")
		clientInfo.RedirectURIAuthorCode = string(clientBucket.Get([]byte("redirect_uri_author_code")))
		clientInfo.RedirectURIImplicit = string(clientBucket.Get([]byte("redirect_uri_implicit")))
		clientInfo.ClientName = string(clientBucket.Get([]byte("client_name")))
		clientInfo.Description = string(clientBucket.Get([]byte("description")))
		clientInfo.Salt = clientBucket.Get([]byte("salt"))
		if dataBinary := clientBucket.Get([]byte("create_date")); dataBinary != nil {
			createDate := time.Time{}
			err := createDate.UnmarshalBinary(dataBinary)
			if err != nil {
				return err
			}
			clientInfo.CreateDate = createDate
		}
		if dataBinary := clientBucket.Get([]byte("update_date")); dataBinary != nil {
			updateDate := time.Time{}
			err := updateDate.UnmarshalBinary(dataBinary)
			if err != nil {
				return err
			}
			clientInfo.UpdateDate = updateDate
		}
		clientInfo.CreateUser = string(clientBucket.Get([]byte("create_user")))
		clientInfo.UpdateUser = string(clientBucket.Get([]byte("update_user")))
		clientInfo.CreateIP = string(clientBucket.Get([]byte("create_ip")))
		clientInfo.UpdateIP = string(clientBucket.Get([]byte("update_ip")))
		requireActivate := string(clientBucket.Get([]byte("require_activate")))
		if requireActivate == "true" {
			clientInfo.RequireActivate = true
		} else {
			clientInfo.RequireActivate = false
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return clientInfo, nil
}

func PutClientInfo(clientInfo *ClientInfo) error {
	oldClientInfo, err := GetClientInfo(clientInfo.ClientUsername)
	if err != nil && err.Error() != "client not exist" {
		return err
	}
	if oldClientInfo != nil {
		return errors.New("duplicate client username")
	}
	err = db.Update(func(tx *bolt.Tx) error {
		clientBucket, err := tx.CreateBucket([]byte(clientInfo.ClientUsername))
		if err != nil {
			return err
		}
		err = database.AddKeyValue(clientBucket, "client_username", clientInfo.ClientUsername)
		if err != nil {
			return err
		}
		err = database.AddKeyValue(clientBucket, "client_password", clientInfo.EncryptedPassword)
		if err != nil {
			return err
		}
		err = database.AddKeyValue(clientBucket, "owner_username", clientInfo.OwnerUsername)
		if err != nil {
			return err
		}
		err = database.AddKeyValue(clientBucket, "authorization_code", clientInfo.GrantAuthorizationCode)
		if err != nil {
			return err
		}
		err = database.AddKeyValue(clientBucket, "implicit", clientInfo.GrantImplicit)
		if err != nil {
			return err
		}
		err = database.AddKeyValue(clientBucket, "resource_owner_credential", clientInfo.GrantResourceOwner)
		if err != nil {
			return err
		}
		err = database.AddKeyValue(clientBucket, "client_credential", clientInfo.GrantClientCredentials)
		if err != nil {
			return err
		}
		err = database.AddKeyValue(clientBucket, "redirect_uri_author_code", clientInfo.RedirectURIAuthorCode)
		if err != nil {
			return err
		}
		err = database.AddKeyValue(clientBucket, "redirect_uri_implicit", clientInfo.RedirectURIImplicit)
		if err != nil {
			return err
		}
		err = database.AddKeyValue(clientBucket, "client_name", clientInfo.ClientName)
		if err != nil {
			return err
		}
		err = database.AddKeyValue(clientBucket, "description", clientInfo.Description)
		if err != nil {
			return err
		}
		err = database.AddKeyValue(clientBucket, "salt", clientInfo.Salt)
		if err != nil {
			return err
		}
		err = database.AddKeyValue(clientBucket, "create_date", clientInfo.CreateDate)
		if err != nil {
			return err
		}
		err = database.AddKeyValue(clientBucket, "update_date", clientInfo.UpdateDate)
		if err != nil {
			return err
		}
		err = database.AddKeyValue(clientBucket, "create_user", clientInfo.CreateUser)
		if err != nil {
			return err
		}
		err = database.AddKeyValue(clientBucket, "update_user", clientInfo.UpdateUser)
		if err != nil {
			return err
		}
		err = database.AddKeyValue(clientBucket, "create_ip", clientInfo.CreateIP)
		if err != nil {
			return err
		}
		err = database.AddKeyValue(clientBucket, "update_ip", clientInfo.UpdateIP)
		if err != nil {
			return err
		}
		err = database.AddKeyValue(clientBucket, "require_activate", clientInfo.RequireActivate)
		if err != nil {
			return err
		}
		return nil
	})
	return err
}
func getGrantScopes(bucket *bolt.Bucket, grant string) map[string]bool {
	scopesByte := bucket.Get([]byte(grant))
	if scopesByte == nil {
		return nil
	}
	return database.StringToSet(string(scopesByte))
}
