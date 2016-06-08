package database

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"dev.corp.extreme.co.th/exeoauth2/config"
)

var (
	testAccessTokenInfo *AccessTokenInfo = &AccessTokenInfo{}
)

func init() {
	config.Default.Database.Redis = config.Redis{
		Address:  "localhost:6379",
		Password: "0tPpm9F5aFfXAitVaF2F",
		DB:       10,
	}

	testAccessTokenInfo.Client = "TestCli"
	testAccessTokenInfo.ExpireTime = time.Now()
	testAccessTokenInfo.Token = "AAABBBCCC1234zz"
	testAccessTokenInfo.UID = "10"
	testAccessTokenInfo.User = "Test"
	testAccessTokenInfo.Scopes = make(map[string]bool)
	testAccessTokenInfo.Scopes["scope1"] = true
	testAccessTokenInfo.Scopes["scope2"] = true
	testAccessTokenInfo.Scopes["scope4"] = true
}

func TestGetAccessTokenInfo(t *testing.T) {

	client, _ := NewClient()
	defer client.client.FlushDb()
	client.client.HSet("AccessTokens:AAABBBCCC1234zz", "Client", testAccessTokenInfo.Client)
	client.client.HSet("AccessTokens:AAABBBCCC1234zz", "ExpireTime", testAccessTokenInfo.ExpireTime.Format(time.RFC3339Nano))
	client.client.HSet("AccessTokens:AAABBBCCC1234zz", "UID", testAccessTokenInfo.UID)
	client.client.HSet("AccessTokens:AAABBBCCC1234zz", "User", testAccessTokenInfo.User)
	client.client.HSet("AccessTokens:AAABBBCCC1234zz", "Scopes", "scope1,scope2,scope4")
	accessTokenInfo, err := client.GetAccessTokenInfo(testAccessTokenInfo.Token)
	if err != nil {
		t.Fatal("get client error:", err)
	}
	if accessTokenInfo == nil {
		t.Fatal("can not find clientinfo")
	}
	if accessTokenInfo.Token != testAccessTokenInfo.Token {
		t.Fatal("Username invalid")
	}
	if accessTokenInfo.Client != testAccessTokenInfo.Client {
		t.Fatal("client invalid")
	}
	if accessTokenInfo.User != testAccessTokenInfo.User {
		t.Fatal("user invalid")
	}
	if !accessTokenInfo.ExpireTime.Equal(testAccessTokenInfo.ExpireTime) {
		t.Fatal("expire time invalid")
	}
	if !reflect.DeepEqual(accessTokenInfo.Scopes, testAccessTokenInfo.Scopes) {
		t.Fatal("scope invalid")
	}
	accessTokenInfo3, err := client.GetAccessTokenInfo("aaa")
	if err != nil {
		t.Fatal("get not exist token  error:", err)
	}
	if accessTokenInfo3 != nil {
		t.Fatal("token not exist return tokeninfo")
	}
}

func TestSetAccessTokenInfo(t *testing.T) {
	client, _ := NewClient()
	defer client.client.FlushDb()

	accessTokenInfo := testAccessTokenInfo
	err := client.setAccessTokenInfo(accessTokenInfo)
	if err != nil {
		t.Fatal("error set accesstokeninfo:", err)
	}
	accessTokenInfo2, _ := client.GetAccessTokenInfo(accessTokenInfo.Token)
	if !reflect.DeepEqual(accessTokenInfo, accessTokenInfo2) {
		fmt.Println(accessTokenInfo)
		fmt.Println(accessTokenInfo2)
		t.Fatal("accesstoken fail to deepequal")
	}
}

func TestPutAccessTokenInfo(t *testing.T) {
	client, _ := NewClient()
	defer client.client.FlushDb()
	accessTokenInfo := testAccessTokenInfo
	client.PutAccessTokenInfo(accessTokenInfo)
	err := client.PutAccessTokenInfo(accessTokenInfo)
	if err == nil {
		t.Fatal("duplicate token does not return error")
	} else {
		if err.Error() != "duplicate token" {
			t.Fatal("duplicate token return wrong error:", err)
		}
	}
}
