package changeemail

import (
	"net/http"
	"time"

	"github.com/asaskevich/govalidator"

	"exeoauth2/common"
	"exeoauth2/common/bearer"
	"exeoauth2/database/access-token"
	userdb "exeoauth2/database/user"
	parent "exeoauth2/handler/user"
	"exeoauth2/logger"
)

const (
	RequiredScope = "admin"
)

var (
	PrefixPath = parent.PrefixPath + "/change_email"
)

type Input struct {
	Username string
	Password string
	Email    string
	Forced   string
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
		Forced:   req.PostFormValue("forced"),
	}

	valErr := common.ValidateErrorResponse{}

	var user *userdb.UserInfo

	if input.Username == "" {
		valErr.Add(parent.ErrorUsernameMissing)
	} else if !govalidator.IsAlphanumeric(input.Username) {
		valErr.Add(parent.ErrorUsernameInvalid)
	} else if user, err = userdb.ReadUser(input.Username); user == nil {
		if err != nil {
			errLogger.WriteLog(err)
			resp.WriteResults(common.ErrorStatusInternalServerError)
			return
		} else {
			valErr.Add(parent.ErrorUserNotFound)
		}
	}

	if !govalidator.IsEmail(input.Email) {
		valErr.Add(parent.ErrorEmailInvalid)
	}

	if len(valErr.ErrorDescriptions) > 0 {
		resp.WriteResults(&valErr)
		return
	}

	if input.Forced != "true" {
		if !user.VerifyPassword(input.Password) {
			resp.WriteResults(ErrorPasswordIncorrect)
			return
		}
	}

	user.Email = input.Email
	user.UpdateDate = time.Now()

	err = userdb.UpdateUser(user)
	if err != nil {
		errLogger.WriteLog(err)
		resp.WriteResults(common.ErrorStatusInternalServerError)
		return
	}

	err = resp.WriteResults(parent.NewUserResult(user))
	if err != nil {
		errLogger.WriteLog(err)
	}
}