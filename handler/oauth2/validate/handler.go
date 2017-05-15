package validate

import (
	"net/http"

	"exeoauth2/common"
	"exeoauth2/common/bearer"
	"exeoauth2/database/access-token"
	"exeoauth2/handler/oauth2"
	"exeoauth2/logger"
)

const (
	PrefixPath = oauth2.PrefixPath + "/validate"
)

var ()

func init() {}

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
	token := req.FormValue("token")
	scopes := req.FormValue("scopes")
	result, err := accesstoken.Validate(token, scopes, "")
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
	} else {
		data := &Success{
			Token:    result.Token,
			Scopes:   result.Scopes,
			ClientID: result.ClientID,
		}
		resp.WriteResults(data)
	}
}

type Success struct {
	Token    string `json:"token"`
	Scopes   string `json:"scopes"`
	ClientID string `json:"client_id"`
}

func (s *Success) Success() bool {
	return true
}
