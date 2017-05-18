package clients

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/asaskevich/govalidator"

	"exeoauth2/common"
	"exeoauth2/common/bearer"
	"exeoauth2/common/encrypt"
	"exeoauth2/database/access-token"
	clientdb "exeoauth2/database/client"
	"exeoauth2/logger"
)

const (
	RequiredScope = "admin"
	SaltLength    = 64
)

var ()

type postInput struct {
	ClientID                     string          `json:"client_id"`
	ClientSecret                 string          `json:"client_secret"`
	GrantClientCredentialsString string          `json:"client_credentials_scope"`
	GrantClientCredentials       map[string]bool `json:"-"`
	Description                  string          `json:"description"`
}

func Handler(httpResp http.ResponseWriter, req *http.Request) {
	reqLogger, respLogger, errLogger, transLogger := logger.NewLoggers(req.URL.Path)
	resp := common.NewResponseWriter(httpResp, respLogger)

	err := reqLogger.WriteLog(req)
	if err != nil {
		errLogger.WriteLog(err)
		resp.WriteResults(common.ErrorStatusInternalServerError)
		return
	}

	// Basic request validation
	switch req.Method {
	case http.MethodPost:
		postHandler(resp, req, respLogger, errLogger, transLogger)
	default:
		resp.WriteResults(common.ErrorStatusMethodNotAllowed)
	}
}

func postHandler(resp *common.ResponseWriter, req *http.Request, respLogger *logger.ResponseLogger, errLogger *logger.ErrorLogger, transLogger *logger.TransactionLogger) {
	// Validate Token
	token, err := bearer.ReadToken(req)
	if err != nil {
		resp.WriteResults(&bearer.ErrorTokenMissingMalform)
		return
	}

	_, err = accesstoken.Validate(token, RequiredScope, "")
	if err != nil {
		switch err := err.(type) {
		case *bearer.ErrorMessage:
			// copy error to a new variable to prevent modifying predefined variable
			temp := *err
			resp.WriteResults(&temp)
			return
		default:
			errLogger.WriteLog(err)
			resp.WriteResults(common.ErrorStatusInternalServerError)
			return
		}
	}

	// Validate input
	raw, err := ioutil.ReadAll(req.Body)
	if err != nil {
		resp.WriteResults(&common.ErrorStatusInternalServerError)
		return
	}

	input := &postInput{}
	err = json.Unmarshal(raw, input)
	if err != nil {
		resp.WriteResults(&common.ErrorStatusInternalServerError)
		return
	}
	input.GrantClientCredentials = common.StringToSet(input.GrantClientCredentialsString)

	valErr := common.ValidateErrorResponse{}

	if len(input.ClientID) < ClientIDLenMin || len(input.ClientID) > ClientIDLenMax {
		valErr.Add(ErrorClientIDLengthInvalid)
	} else if !govalidator.IsAlphanumeric(input.ClientID) {
		valErr.Add(ErrorClientIDInvalid)
	} else if c, _ := clientdb.ReadClient(input.ClientID); c != nil {
		valErr.Add(ErrorClientIDDuplicate)
	}

	if len(input.ClientSecret) < ClientSecretLenMin || len(input.ClientSecret) > ClientSecretLenMax {
		valErr.Add(ErrorClientSecretLengthInvalid)
	} else if !govalidator.IsPrintableASCII(input.ClientSecret) {
		valErr.Add(ErrorClientSecretInvalid)
	}

	if input.GrantClientCredentials == nil {
		valErr.Add(ErrorCliCreScopeMissing)
	} else if !clientdb.ValidateScope(input.GrantClientCredentials) {
		valErr.Add(ErrorCliCreScopeInvalid)
	}

	if len(input.Description) > DescriptionLenMax {
		valErr.Add(ErrorDescriptionLengthInvalid)
	}

	if len(valErr.ErrorDescriptions) > 0 {
		resp.WriteResults(&valErr)
		return
	}

	// Encrypt secret
	salt, err := encrypt.GenerateSalt(SaltLength)
	if err != nil {
		resp.WriteResults(&common.ErrorStatusInternalServerError)
		return
	}
	encSecret := encrypt.EncryptText1Way([]byte(input.ClientSecret), salt)

	now := time.Now()

	newCli := &clientdb.ClientInfo{
		ClientID:               input.ClientID,
		EncryptedClientSecret:  encSecret,
		GrantClientCredentials: input.GrantClientCredentials,
		Description:            input.Description,
		Salt:                   salt,
		CreateDate:             now,
		UpdateDate:             now,
	}
	if err := clientdb.CreateClient(newCli); err != nil {
		errLogger.WriteLog(err)
		resp.WriteResults(common.ErrorStatusInternalServerError)
		return
	}

	err = resp.WriteResults(NewClientResult(newCli))
	if err != nil {
		errLogger.WriteLog(err)
	}
}
