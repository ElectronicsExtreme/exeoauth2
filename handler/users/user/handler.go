package users

import (
	"net/http"

	"github.com/asaskevich/govalidator"
	"github.com/gorilla/mux"

	"exeoauth2/common"
	"exeoauth2/common/bearer"
	accesstoken "exeoauth2/database/access-token"
	userdb "exeoauth2/database/user"
	parent "exeoauth2/handler/users"
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
	case http.MethodGet:
		getHandler(resp, req, respLogger, errLogger, transLogger)
	case http.MethodDelete:
		deleteHandler(resp, req, respLogger, errLogger, transLogger)
	default:
		resp.WriteResults(common.ErrorStatusMethodNotAllowed)
	}
}

func getHandler(resp *common.ResponseWriter, req *http.Request, respLogger *logger.ResponseLogger, errLogger *logger.ErrorLogger, transLogger *logger.TransactionLogger) {
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
	vars := mux.Vars(req)
	username := vars["username"]
	valErr := common.ValidateErrorResponse{}

	var user *userdb.UserInfo

	if username == "" {
		valErr.Add(parent.ErrorUsernameMissing)
	} else if !govalidator.IsAlphanumeric(username) {
		valErr.Add(parent.ErrorUsernameInvalid)
	} else if user, err = userdb.ReadUser(username); user == nil {
		if err != nil {
			errLogger.WriteLog(err)
			resp.WriteResults(common.ErrorStatusInternalServerError)
			return
		} else {
			valErr.Add(parent.ErrorUserNotFound)
		}
	}

	if len(valErr.ErrorDescriptions) > 0 {
		resp.WriteResults(&valErr)
		return
	}

	err = resp.WriteResults(parent.NewUserResult(user))
	if err != nil {
		errLogger.WriteLog(err)
	}
}

func deleteHandler(resp *common.ResponseWriter, req *http.Request, respLogger *logger.ResponseLogger, errLogger *logger.ErrorLogger, transLogger *logger.TransactionLogger) {
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
	vars := mux.Vars(req)
	username := vars["username"]
	valErr := common.ValidateErrorResponse{}

	var user *userdb.UserInfo

	if username == "" {
		valErr.Add(parent.ErrorUsernameMissing)
	} else if !govalidator.IsAlphanumeric(username) {
		valErr.Add(parent.ErrorUsernameInvalid)
	} else if user, err = userdb.ReadUser(username); user == nil {
		if err != nil {
			errLogger.WriteLog(err)
			resp.WriteResults(common.ErrorStatusInternalServerError)
			return
		} else {
			valErr.Add(parent.ErrorUserNotFound)
		}
	}

	if len(valErr.ErrorDescriptions) > 0 {
		resp.WriteResults(&valErr)
		return
	}

	err = userdb.DeleteUser(username)
	if err != nil {
		errLogger.WriteLog(err)
		resp.WriteResults(common.ErrorStatusInternalServerError)
		return
	}

	data := &parent.UserResult{}

	err = resp.WriteResults(data)
	if err != nil {
		errLogger.WriteLog(err)
	}
}
