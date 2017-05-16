package register

import (
	"net/http"
	"time"

	"github.com/asaskevich/govalidator"

	"exeoauth2/common"
	"exeoauth2/common/bearer"
	"exeoauth2/common/encrypt"
	"exeoauth2/database/access-token"
	userdb "exeoauth2/database/user"
	parent "exeoauth2/handler/user"
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
	Username string
	Password string
	Email    string
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
		Username: req.PostFormValue("username"),
		Password: req.PostFormValue("password"),
		Email:    req.PostFormValue("email"),
	}

	valErr := common.ValidateErrorResponse{}

	if len(input.Username) < parent.UsernameLenMin || len(input.Username) > parent.UsernameLenMax {
		valErr.Add(parent.ErrorUsernameLengthInvalid)
	} else if !govalidator.IsAlphanumeric(input.Username) {
		valErr.Add(parent.ErrorUsernameInvalid)
	} else if c, _ := userdb.ReadUser(input.Username); c != nil {
		valErr.Add(parent.ErrorUsernameDuplicate)
	}

	if len(input.Password) < parent.PasswordLenMin || len(input.Password) > parent.PasswordLenMax {
		valErr.Add(parent.ErrorPasswordLengthInvalid)
	} else if !govalidator.IsPrintableASCII(input.Password) {
		valErr.Add(parent.ErrorPasswordInvalid)
	}

	if !govalidator.IsEmail(input.Email) {
		valErr.Add(parent.ErrorEmailInvalid)
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

	err = resp.WriteResults(parent.NewUserResult(newUser))
	if err != nil {
		errLogger.WriteLog(err)
	}
}
