package user

import (
	"fmt"
	"time"

	"exeoauth2/database/user"
)

const (
	PrefixPath = "/user"

	UsernameLenMin = 3
	UsernameLenMax = 20
	PasswordLenMin = 6
	PasswordLenMax = 50
)

var (
	ErrorUserNotFound = "the specified user is not exist"

	ErrorUsernameLengthInvalid = fmt.Sprintf("username must have length between %v and %v", UsernameLenMin, UsernameLenMax)
	ErrorUsernameInvalid       = "username contain invalid character"
	ErrorUsernameDuplicate     = "username already exist"
	ErrorUsernameMissing       = "username is missing"

	ErrorPasswordLengthInvalid = fmt.Sprintf("password must have length between %v and %v", PasswordLenMin, PasswordLenMax)
	ErrorPasswordInvalid       = "password contain invalid character"

	ErrorEmailInvalid = "email is invalid"
)

type UserResult struct {
	Username   string    `json:"username"`
	Email      string    `json:"email"`
	CreateDate time.Time `json:"create_date"`
	UpdateDate time.Time `json:"update_date"`
}

func (self *UserResult) Success() bool {
	return true
}

func NewUserResult(usr *user.UserInfo) *UserResult {
	return &UserResult{
		Username:   usr.Username,
		Email:      usr.Email,
		CreateDate: usr.CreateDate,
		UpdateDate: usr.UpdateDate,
	}
}
