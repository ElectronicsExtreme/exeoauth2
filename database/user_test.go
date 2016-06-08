package database

import (
	"bytes"
	"dev.corp.extreme.co.th/exeoauth2/config"
	"reflect"
	"testing"
)

func init() {
	config.Default.Database.Redis = config.Redis{
		Address:  "localhost:6379",
		Password: "0tPpm9F5aFfXAitVaF2F",
		DB:       10,
	}
}

func TestGetUserInfo(t *testing.T) {

	client, _ := NewClient()
	defer client.client.FlushDb()
	client.client.Set("Users:test:UID", "10", 0)
	client.client.Set("Users:test:Username", "TeSt", 0)
	client.client.Set("Users:test:EncryptedPassword", []byte("adx,skw"), 0)
	client.client.Set("Users:test:Salt", []byte("wdixaox"), 0)
	userInfo, err := client.GetUserInfo("test")
	if err != nil {
		t.Fatal("get user error:", err)
	}
	if userInfo == nil {
		t.Fatal("can not find userinfo")
	}
	if userInfo.UID != "10" {
		t.Fatal("UID invalid")
	}
	if userInfo.Username != "TeSt" {
		t.Fatal("Username invalid")
	}
	if !bytes.Equal([]byte("adx,skw"), userInfo.EncryptedPassword) {
		t.Fatal("Password invalid")
	}
	if !bytes.Equal([]byte("wdixaox"), userInfo.Salt) {
		t.Fatal("Salt invalid")
	}
	userInfo2, err := client.GetUserInfo("TeSt")
	if err != nil {
		t.Fatal("get user case error:", err)
	}
	if !reflect.DeepEqual(userInfo, userInfo2) {
		t.Fatal("get user case invalid")
	}
	userInfo3, err := client.GetUserInfo("aaa")
	if err != nil {
		t.Fatal("get not exist user error:", err)
	}
	if userInfo3 != nil {
		t.Fatal("user not exist return userinfo")
	}
	client.client.Set("Users:test2:Username", "TeSt2", 0)
	client.client.Set("Users:test2:EncryptedPassword", []byte("adx,skw"), 0)
	client.client.Set("Users:test2:Salt", []byte("wdixaox"), 0)
	userInfo4, err := client.GetUserInfo("test2")
	if err != nil {
		t.Fatal("get user empty uid error:", err)
	}
	if userInfo4 == nil {
		t.Fatal("can not find userinfo with no uid")
	}
	if userInfo4.UID != "" {
		t.Fatal("UID invalid")
	}
	if userInfo4.Username != "TeSt2" {
		t.Fatal("Username invalid")
	}
	if !bytes.Equal([]byte("adx,skw"), userInfo4.EncryptedPassword) {
		t.Fatal("Password invalid")
	}
	if !bytes.Equal([]byte("wdixaox"), userInfo4.Salt) {
		t.Fatal("Salt invalid")
	}
}

func TestSetUserInfo(t *testing.T) {
	client, _ := NewClient()
	defer client.client.FlushDb()

	userInfo := &UserInfo{
		Username:          "TestPut",
		UID:               "15",
		EncryptedPassword: []byte("adfisxl"),
		Salt:              []byte("sszcsl"),
	}
	err := client.PutUserInfo(userInfo)
	if err != nil {
		t.Fatal("error set userinfo:", err)
	}
	userInfo2, _ := client.GetUserInfo(userInfo.Username)
	if !reflect.DeepEqual(userInfo, userInfo2) {
		t.Fatal("user fail to deepequal")
	}
}

func TestPutUserInfo(t *testing.T) {
	client, _ := NewClient()
	defer client.client.FlushDb()
	userInfo := &UserInfo{
		Username:          "TestPut",
		UID:               "15",
		EncryptedPassword: []byte("adfisxl"),
		Salt:              []byte("sszcsl"),
	}
	client.PutUserInfo(userInfo)
	err := client.PutUserInfo(userInfo)
	if err == nil {
		t.Fatal("duplicate user does not return error")
	} else {
		if err.Error() != "duplicate user" {
			t.Fatal("duplicate user return wrong error:", err)
		}
	}
}

func TestUpdateUserInfo(t *testing.T) {
	client, _ := NewClient()
	defer client.client.FlushDb()
	userInfo := &UserInfo{
		Username:          "TestUpdate",
		UID:               "20",
		EncryptedPassword: []byte("adfisxl"),
		Salt:              []byte("sszcsl"),
	}
	client.PutUserInfo(userInfo)
	userInfo.UID = ""
	err := client.UpdateUserInfo(userInfo)
	if err != nil {
		t.Fatal("error update userinfo:", err)
	}
	userInfo2, _ := client.GetUserInfo(userInfo.Username)
	if !reflect.DeepEqual(userInfo, userInfo2) {
		t.Fatal("user fail to deepequal")
	}
}

func TestDeleteUserInfo(t *testing.T) {
	client, _ := NewClient()
	defer client.client.FlushDb()
	userInfo := &UserInfo{
		Username:          "TestDelete",
		UID:               "25",
		EncryptedPassword: []byte("adfisxl"),
		Salt:              []byte("sszcsl"),
	}
	client.PutUserInfo(userInfo)
	userInfo2, _ := client.GetUserInfo(userInfo.Username)
	if !reflect.DeepEqual(userInfo, userInfo2) {
		t.Fatal("user fail to deepequal")
	}
	err := client.DeleteUserInfo(userInfo.Username)
	if err != nil {
		t.Fatal("fail to delete:", err)
	}
	userInfo3, _ := client.GetUserInfo(userInfo.Username)
	if userInfo3 != nil {
		t.Fatal("fail to delete user")
	}
}
