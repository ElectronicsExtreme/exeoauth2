package client

import (
	"fmt"
	"time"

	"exeoauth2/common"
	"exeoauth2/database/client"
)

const (
	PrefixPath = "/client"

	ClientIDLenMin     = 3
	ClientIDLenMax     = 20
	ClientSecretLenMin = 6
	ClientSecretLenMax = 50
	DescriptionLenMax  = 255
)

var (
	ErrorClientNotFound = "the specified client is not exist"

	ErrorClientIDLengthInvalid = fmt.Sprintf("client_id must have length between %v and %v", ClientIDLenMin, ClientIDLenMax)
	ErrorClientIDInvalid       = "client_id contain invalid character"
	ErrorClientIDDuplicate     = "client_id already exist"
	ErrorClientIDMissing       = "client_id is missing"

	ErrorClientSecretLengthInvalid = fmt.Sprintf("client_secret must have length between %v and %v", ClientSecretLenMin, ClientSecretLenMax)
	ErrorClientSecretInvalid       = "client_secret contain invalid character"

	ErrorCliCreScopeMissing = "client_credentials_scope is missing"
	ErrorCliCreScopeInvalid = "client_credentials_scope is invalid"

	ErrorDescriptionLengthInvalid = fmt.Sprintf("description maximum lenght is %v", DescriptionLenMax)
)

type ClientResult struct {
	ClientID               string    `json:"client_id"`
	GrantClientCredentials string    `json:"client_credentials_scope"`
	Description            string    `json:"description"`
	CreateDate             time.Time `json:"create_date"`
	UpdateDate             time.Time `json:"update_date"`
}

func (self *ClientResult) Success() bool {
	return true
}

func NewClientResult(cli *client.ClientInfo) *ClientResult {
	return &ClientResult{
		ClientID:               cli.ClientID,
		GrantClientCredentials: common.SetToString(cli.GrantClientCredentials),
		Description:            cli.Description,
		CreateDate:             cli.CreateDate,
		UpdateDate:             cli.UpdateDate,
	}
}
