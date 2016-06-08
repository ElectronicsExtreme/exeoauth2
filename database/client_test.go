package database

import (
	"bytes"
	"reflect"
	"testing"

	"dev.corp.extreme.co.th/exeoauth2/config"
)

var (
	testClientInfo *ClientInfo = &ClientInfo{}
)

func init() {
	config.Default.Database.Redis = config.Redis{
		Address:  "localhost:6379",
		Password: "0tPpm9F5aFfXAitVaF2F",
		DB:       10,
	}

	testClientInfo.ClientUsername = "TestCli"
	testClientInfo.EncryptedPassword = []byte("adx,skw")
	testClientInfo.Salt = []byte("wdixaox")
	testClientInfo.GrantImplicit = make(map[string]bool)
	testClientInfo.GrantImplicit["Grant1"] = true
	testClientInfo.GrantImplicit["Grant2"] = true
	testClientInfo.GrantImplicit["Grant3"] = true
}

func TestGetClientInfo(t *testing.T) {

	client, _ := NewClient()
	defer client.client.FlushDb()
	client.client.Set("Clients:TestCli:ClientUsername", testClientInfo.ClientUsername, 0)
	client.client.Set("Clients:TestCli:EncryptedPassword", testClientInfo.EncryptedPassword, 0)
	client.client.Set("Clients:TestCli:Salt", testClientInfo.Salt, 0)
	client.client.SAdd("Clients:TestCli:GrantImplicit", "Grant1", "Grant2", "Grant3")
	clientInfo, err := client.GetClientInfo("TestCli")
	if err != nil {
		t.Fatal("get client error:", err)
	}
	if clientInfo == nil {
		t.Fatal("can not find clientinfo")
	}
	if clientInfo.ClientUsername != testClientInfo.ClientUsername {
		t.Fatal("Username invalid")
	}
	if !bytes.Equal(clientInfo.EncryptedPassword, testClientInfo.EncryptedPassword) {
		t.Fatal("Password invalid")
	}
	if !bytes.Equal(clientInfo.Salt, testClientInfo.Salt) {
		t.Fatal("Salt invalid")
	}

	if !reflect.DeepEqual(clientInfo.GrantImplicit, testClientInfo.GrantImplicit) {
		t.Fatal("implicit grant invalid")
	}
	clientInfo3, err := client.GetClientInfo("aaa")
	if err != nil {
		t.Fatal("get not exist client error:", err)
	}
	if clientInfo3 != nil {
		t.Fatal("client not exist return clientinfo")
	}
}

func TestSetClientInfo(t *testing.T) {
	client, _ := NewClient()
	defer client.client.FlushDb()

	clientInfo := testClientInfo
	err := client.PutClientInfo(clientInfo)
	if err != nil {
		t.Fatal("error set clientinfo:", err)
	}
	clientInfo2, _ := client.GetClientInfo(clientInfo.ClientUsername)
	if !reflect.DeepEqual(clientInfo, clientInfo2) {
		t.Fatal("user fail to deepequal")
	}
}

func TestPutClientInfo(t *testing.T) {
	client, _ := NewClient()
	defer client.client.FlushDb()
	clientInfo := testClientInfo
	client.PutClientInfo(clientInfo)
	err := client.PutClientInfo(clientInfo)
	if err == nil {
		t.Fatal("duplicate client does not return error")
	} else {
		if err.Error() != "duplicate client username" {
			t.Fatal("duplicate client return wrong error:", err)
		}
	}
}
