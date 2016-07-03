package changepassword

import (
	"net/http"

	"github.com/ElectronicsExtreme/exehttp"
	"github.com/asaskevich/govalidator"
	"github.com/gorilla/schema"

	"dev.corp.extreme.co.th/exeoauth2/database"
	"dev.corp.extreme.co.th/exeoauth2/encrypt"
)

const (
	PrefixPath = "/change-password"
	saltLength = 64
)

var ()

func init() {
}

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
	switch req.Method {
	case "POST":
		self.servePost(resp, req)
	default:
		err := resp.WriteResults(&exehttp.ErrorStatusMethodNotAllowed)
		if err != nil {
			self.errorLogInfo.Body = err.Error()
			self.errorLogInfo.Write()
		}
	}
}

func (self *Handler) servePost(resp *exehttp.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		self.errorLogInfo.Body = err.Error()
		self.errorLogInfo.Write()
		resp.WriteResults(&exehttp.ErrorStatusInternalServerError)
		return
	}

	redisClient, err := database.NewClient()
	if err != nil {
		self.errorLogInfo.Body = err.Error()
		self.errorLogInfo.Write()
		resp.WriteResults(&exehttp.ErrorStatusInternalServerError)
		return
	}

	inUserInfo := &database.UserInfo{}
	err = schema.NewDecoder().Decode(inUserInfo, req.PostForm)
	if inUserInfo.Username == "" {
		resp.WriteResults(&ErrorUserMissing)
		return
	}

	if !govalidator.IsAlphanumeric(inUserInfo.Username) {
		resp.WriteResults(&ErrorUserInvalid)
		return
	}

	userExist, err := redisClient.IsUserExist(inUserInfo.Username)
	if err != nil {
		self.errorLogInfo.Body = err.Error()
		self.errorLogInfo.Write()
		resp.WriteResults(&exehttp.ErrorStatusInternalServerError)
		return
	}
	if !userExist {
		resp.WriteResults(&ErrorUserNotExist)
		return
	}

	if inUserInfo.Password == "" {
		resp.WriteResults(&ErrorPasswordMissing)
		return
	}

	userInfo, err := redisClient.GetUserInfo(inUserInfo.Username)
	if err != nil {
		self.errorLogInfo.Body = err.Error()
		self.errorLogInfo.Write()
		resp.WriteResults(&exehttp.ErrorStatusInternalServerError)
		return
	}

	userInfo.EncryptedPassword = encrypt.EncryptText1Way([]byte(inUserInfo.Password), userInfo.Salt)
	err = redisClient.UpdateUserInfo(userInfo)
	if err != nil {
		self.errorLogInfo.Body = err.Error()
		self.errorLogInfo.Write()
		resp.WriteResults(&exehttp.ErrorStatusInternalServerError)
		return
	}
	resp.WriteResults(&exehttp.Results{
		Success:    true,
		Data:       inUserInfo,
		HTTPStatus: http.StatusOK,
	})
}
