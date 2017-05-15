package register

import (
	"net/http"
	"time"

	"github.com/asaskevich/govalidator"

	"exeoauth2/common"
	"exeoauth2/common/bearer"
	"exeoauth2/common/encrypt"
	"exeoauth2/database/access-token"
	clientdb "exeoauth2/database/client"
	parent "exeoauth2/handler/client"
	"exeoauth2/logger"
)

const (
	RequiredScope = "admin"
	SaltLength    = 64
)

var (
	PrefixPath = parent.PrefixPath + "/register"
)

type Input struct {
	ClientID               string
	ClientSecret           string
	GrantClientCredentials map[string]bool
	Description            string
}

func Handler(httpResp http.ResponseWriter, req *http.Request) {
	reqLogger, respLogger, errLogger, _ := logger.NewLoggers(PrefixPath)
	resp := common.NewResponseWriter(httpResp, respLogger)

	err := reqLogger.WriteLog(req)
	if err != nil {
		errLogger.WriteLog(err)
		resp.WriteResults(common.ErrorStatusInternalServerError)
		return
	}

	// Basic request validation
	if req.Method != http.MethodPost {
		resp.WriteResults(common.ErrorStatusMethodNotAllowed)
		return
	}
	err = req.ParseForm()
	if err != nil {
		errLogger.WriteLog(err)
		resp.WriteResults(common.ErrorStatusInternalServerError)
		return
	}
	for _, value := range req.PostForm {
		if len(value) > 1 {
			resp.WriteResults(common.ErrorDuplicateParameters)
			return
		}
	}

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
	input := &Input{
		ClientID:               req.PostFormValue("client_id"),
		ClientSecret:           req.PostFormValue("client_secret"),
		GrantClientCredentials: common.StringToSet(req.PostFormValue("client_credentials_scope")),
		Description:            req.PostFormValue("description"),
	}

	valErr := common.ValidateErrorResponse{}

	if len(input.ClientID) < parent.ClientIDLenMin || len(input.ClientID) > parent.ClientIDLenMax {
		valErr.Add(parent.ErrorClientIDLengthInvalid)
	} else if !govalidator.IsAlphanumeric(input.ClientID) {
		valErr.Add(parent.ErrorClientIDInvalid)
	} else if c, _ := clientdb.ReadClient(input.ClientID); c != nil {
		valErr.Add(parent.ErrorClientIDDuplicate)
	}

	if len(input.ClientSecret) < parent.ClientSecretLenMin || len(input.ClientSecret) > parent.ClientSecretLenMax {
		valErr.Add(parent.ErrorClientSecretLengthInvalid)
	} else if !govalidator.IsPrintableASCII(input.ClientSecret) {
		valErr.Add(parent.ErrorClientSecretInvalid)
	}

	if input.GrantClientCredentials == nil {
		valErr.Add(parent.ErrorCliCreScopeMissing)
	} else if !clientdb.ValidateScope(input.GrantClientCredentials) {
		valErr.Add(parent.ErrorCliCreScopeInvalid)
	}

	if len(input.Description) > parent.DescriptionLenMax {
		valErr.Add(parent.ErrorDescriptionLengthInvalid)
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

	err = resp.WriteResults(parent.NewClientResult(newCli))
	if err != nil {
		errLogger.WriteLog(err)
	}
}
