package delete_account

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"dev.corp.extreme.co.th/exe-account/account-interface/config"
	"dev.corp.extreme.co.th/exe-account/account-interface/handler/oauth2"
	"dev.corp.extreme.co.th/exe-account/account-interface/handler/oauth2/database/user"
	"dev.corp.extreme.co.th/exe-account/account-interface/handler/oauth2/handler/delete/response-writer"
	"dev.corp.extreme.co.th/exe-account/account-interface/httputilextend"
)

const (
	saltLength = 64
	secretKey  = "oLOunT2zkJvlAWFx6a5SbU49PP2DQy7jH-Ed71_h90Nnovy4izREdsKWyPl-trQB"
)

var (
	PrefixPath = oauth2.PrefixPath + "/delete"
	ErrorLog   = &config.Default.LogInfo.Error
	RequestLog = &config.Default.LogInfo.Request
)

func Init() {

}

type Handler struct{}

func New() *Handler {
	self := &Handler{}
	return self
}

func (*Handler) ServeHTTP(httpResp http.ResponseWriter, req *http.Request) {
	if config.Default.LogInfo.Request.Enable {
		logger, err := requestLogger()
		if err != nil {
			logger, errr := errorLogger()
			if errr != nil {
				log.Println(PrefixPath+" :", errr)
			} else {
				logger.Println(err)
			}
			log.Println(PrefixPath+" :", err)
		} else {
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
			logger.Println(logString)
		}
	}
	resp := response.NewResponseWriter(httpResp)
	if req.Method != "POST" {
		resp.WriteResult(&response.ErrorMethodNotAllow)
		return
	}
	req.ParseForm()
	for _, value := range req.Form {
		if len(value) > 1 {
			resp.WriteResult(&response.ErrorDuplicateParameters)
			return
		}
	}

	key := req.FormValue("key")
	if key != secretKey {
		resp.WriteResult(&response.ErrorInvalidSecretKey)
		return
	}
	uid := req.FormValue("uid")
	if uid == "" {
		resp.WriteResult(&response.ErrorUIDMissing)
		return
	}
	username := req.FormValue("username")
	if username == "" {
		resp.WriteResult(&response.ErrorUsernameMissing)
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
		resp.WriteHeader(http.StatusInternalServerError)
		return
	}

	if userInfo == nil {
		resp.WriteResult(&response.ErrorAccountNotFound)
		return
	}

	if userInfo.UID != uid {
		resp.WriteResult(&response.ErrorInfoMissMatch)
		return
	}
	if err := user.DeleteUserInfo(username); err != nil {
		logger, errr := errorLogger()
		if errr != nil {
			log.Println(PrefixPath+" :", errr)
		} else {
			logger.Println(err)
		}
		log.Println(PrefixPath+" :", err)
		resp.WriteHeader(http.StatusInternalServerError)
		resp.WriteHeader(http.StatusInternalServerError)
		return
	}
	resp.WriteResult(&response.SuccessResponse{})
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
