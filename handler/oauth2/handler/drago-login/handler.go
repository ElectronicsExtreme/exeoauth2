package dragologin

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"dev.corp.extreme.co.th/exe-account/account-interface/config"
	"dev.corp.extreme.co.th/exe-account/account-interface/handler/oauth2"
	"dev.corp.extreme.co.th/exe-account/account-interface/handler/oauth2/database/user"
	"dev.corp.extreme.co.th/exe-account/account-interface/handler/oauth2/handler/drago-login/response-writer"
	"dev.corp.extreme.co.th/exe-account/account-interface/handler/oauth2/verify"
	"dev.corp.extreme.co.th/exe-account/account-interface/httputilextend"
)

const (
	PrefixPath  = oauth2.PrefixPath + "/drago_login"
	expiresIn   = 3600
	tokenLength = 32
)

var (
	ErrorLog   = &config.Default.LogInfo.Error
	RequestLog = &config.Default.LogInfo.Request
	reqLogger  *log.Logger
)

func init() {
	if config.Default.LogInfo.Request.Enable {
		var err error
		reqLogger, err = requestLogger()
		if err != nil {
			logger, errr := errorLogger()
			if errr != nil {
				log.Println(PrefixPath+" :", errr)
			} else {
				logger.Println(err)
			}
			log.Println(PrefixPath+" :", err)
		}
	}
}

type Handler struct {
}

func New() *Handler {
	self := &Handler{}
	return self
}

func (self *Handler) ServeHTTP(httpRes http.ResponseWriter, req *http.Request) {
	if config.Default.LogInfo.Request.Enable {
		reqMethod := req.Method
		data, err := httputilextend.DumpRequestBody(req)
		if err != nil {
			logger, errr := errorLogger()
			if errr != nil {
				log.Println(PrefixPath+" :", errr)
			} else {
				logger.Println(err)
			}
			log.Println(PrefixPath+" :", err)
		}
		logString := "Method : " + reqMethod + ", Body : " + string(data)
		reqLogger.Println(logString)
	}
	resp := response.NewResponseWriter(httpRes)
	if req.Method != "POST" {
		resp.WriteError(&response.StatusMethodNotAllowed, "", reqLogger)
		return
	}
	req.ParseForm()
	for _, value := range req.Form {
		if len(value) > 1 {
			resp.WriteError(&response.InvalidRequestError, "request parameters must not be included more than once", reqLogger)
			return
		}
	}
	serveResourceOwnerCredentials(resp, req)
}

func serveResourceOwnerCredentials(resp *response.ResponseWriter, req *http.Request) {
	username := req.Form.Get("username")
	password := req.Form.Get("password")

	if username == "" || password == "" {
		resp.WriteError(&response.InvalidGrantError, "", reqLogger)
		return
	}

	userInfo, err := user.GetUserInfo(username)
	if err != nil {
		logger, errr := errorLogger()
		if errr != nil {
			log.Println(PrefixPath+" :", errr)
		} else {
			logger.Println(err)
		}
		log.Println(PrefixPath+" :", err)
		resp.WriteError(&response.StatusInternalServerError, "", reqLogger)
		return
	}

	if userInfo == nil {
		resp.WriteError(&response.InvalidGrantError, "username or password is invalid", reqLogger)
		return
	}

	if userInfo.UID == "" {
		logger, errr := errorLogger()
		if errr != nil {
			log.Println(PrefixPath+" :", errr)
		} else {
			logger.Println("userinfo does not contain uid")
		}
		log.Println(PrefixPath+" :", err)
		resp.WriteError(&response.StatusInternalServerError, "", reqLogger)
		return
	}

	// verify resource owner credential
	if !verify.VerifyUserPassword(userInfo, password) {
		resp.WriteError(&response.InvalidGrantError, "username or password is invalid", reqLogger)
		return
	}

	if !userInfo.EmailActivated {
		resp.WriteError(&response.UnactivatedAccountError, "", reqLogger)
		return
	}

	resp.WriteSuccess(userInfo.Username, userInfo.UID, reqLogger)
}

func requestLogger() (*log.Logger, error) {
	filename := RequestLog.Path + "/" + strconv.FormatInt(int64(time.Now().Year()), 10) + "-" + strconv.FormatInt(int64(time.Now().Month()), 10) + ".log"
	outfile, err := os.OpenFile(filename, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}
	return log.New(outfile, PrefixPath+" : ", log.Lshortfile|log.LstdFlags), nil
}

func errorLogger() (*log.Logger, error) {
	filename := ErrorLog.Path + "/" + strconv.FormatInt(int64(time.Now().Year()), 10) + "-" + strconv.FormatInt(int64(time.Now().Month()), 10) + ".log"
	outfile, err := os.OpenFile(filename, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}
	return log.New(outfile, PrefixPath+" : ", log.Lshortfile|log.LstdFlags), nil
}
