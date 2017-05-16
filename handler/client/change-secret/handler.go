package changesecret

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
)

var (
	PrefixPath = parent.PrefixPath + "/change_secret"
)

type Input struct {
	ClientID  string
	NewSecret string
	OldSecret string
	Forced    string
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
		ClientID:  req.PostFormValue("client_id"),
		NewSecret: req.PostFormValue("new_secret"),
		OldSecret: req.PostFormValue("old_secret"),
		Forced:    req.PostFormValue("forced"),
	}

	valErr := common.ValidateErrorResponse{}

	var client *clientdb.ClientInfo

	if input.ClientID == "" {
		valErr.Add(parent.ErrorClientIDMissing)
	} else if !govalidator.IsAlphanumeric(input.ClientID) {
		valErr.Add(parent.ErrorClientIDInvalid)
	} else if client, err = clientdb.ReadClient(input.ClientID); client == nil {
		if err != nil {
			errLogger.WriteLog(err)
			resp.WriteResults(common.ErrorStatusInternalServerError)
			return
		} else {
			valErr.Add(parent.ErrorClientNotFound)
		}
	}

	if len(input.NewSecret) < parent.ClientSecretLenMin || len(input.NewSecret) > parent.ClientSecretLenMax {
		valErr.Add(parent.ErrorClientSecretLengthInvalid)
	} else if !govalidator.IsPrintableASCII(input.NewSecret) {
		valErr.Add(parent.ErrorClientSecretInvalid)
	}

	if len(valErr.ErrorDescriptions) > 0 {
		resp.WriteResults(&valErr)
		return
	}

	if input.Forced != "true" {
		if !client.VerifySecret(input.OldSecret) {
			resp.WriteResults(ErrorOldSecretIncorrect)
			return
		}
	}

	client.EncryptedClientSecret = encrypt.EncryptText1Way([]byte(input.NewSecret), client.Salt)
	client.UpdateDate = time.Now()

	err = clientdb.UpdateClient(client)
	if err != nil {
		errLogger.WriteLog(err)
		resp.WriteResults(common.ErrorStatusInternalServerError)
		return
	}

	err = resp.WriteResults(parent.NewClientResult(client))
	if err != nil {
		errLogger.WriteLog(err)
	}
}
