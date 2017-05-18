package users

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
	userdb "exeoauth2/database/user"
	"exeoauth2/logger"
)

const (
	RequiredScope = "admin"
	SaltLength    = 64
)

var ()

type Input struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
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
	input := &Input{}
	err = json.Unmarshal(raw, input)
	if err != nil {
		resp.WriteResults(&common.ErrorStatusInternalServerError)
		return
	}

	valErr := common.ValidateErrorResponse{}

	if len(input.Username) < UsernameLenMin || len(input.Username) > UsernameLenMax {
		valErr.Add(ErrorUsernameLengthInvalid)
	} else if !govalidator.IsAlphanumeric(input.Username) {
		valErr.Add(ErrorUsernameInvalid)
	} else if c, _ := userdb.ReadUser(input.Username); c != nil {
		valErr.Add(ErrorUsernameDuplicate)
	}

	if len(input.Password) < PasswordLenMin || len(input.Password) > PasswordLenMax {
		valErr.Add(ErrorPasswordLengthInvalid)
	} else if !govalidator.IsPrintableASCII(input.Password) {
		valErr.Add(ErrorPasswordInvalid)
	}

	if !govalidator.IsEmail(input.Email) {
		valErr.Add(ErrorEmailInvalid)
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
	encSecret := encrypt.EncryptText1Way([]byte(input.Password), salt)

	now := time.Now()

	newUser := &userdb.UserInfo{
		Username:          input.Username,
		EncryptedPassword: encSecret,
		Email:             input.Email,
		Salt:              salt,
		CreateDate:        now,
		UpdateDate:        now,
	}
	if err := userdb.CreateUser(newUser); err != nil {
		errLogger.WriteLog(err)
		resp.WriteResults(common.ErrorStatusInternalServerError)
		return
	}

	err = resp.WriteResults(NewUserResult(newUser))
	if err != nil {
		errLogger.WriteLog(err)
	}
}
