package activateclient

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"dev.corp.extreme.co.th/exe-account/account-interface/config"
	"dev.corp.extreme.co.th/exe-account/account-interface/handler/oauth2"
	"dev.corp.extreme.co.th/exe-account/account-interface/handler/oauth2/database/client"
	"dev.corp.extreme.co.th/exe-account/account-interface/handler/oauth2/database/user"
	"dev.corp.extreme.co.th/exe-account/account-interface/handler/oauth2/handler/activate-client/response-writer"
	"dev.corp.extreme.co.th/exe-account/account-interface/handler/oauth2/handler/validate"
	"dev.corp.extreme.co.th/exe-account/account-interface/httputilextend"
)

const (
	RequireScopes = "activate_client"
)

var (
	PrefixPath       = oauth2.PrefixPath + "/activate_client"
	validateTokenURI = ""
	ErrorLog         = &config.Default.LogInfo.Error
	RequestLog       = &config.Default.LogInfo.Request
)

func init() {
	if config.Default.Server.PrivateListener.Tls.Enable {
		validateTokenURI = "https://localhost" + config.Default.Server.PrivateListener.Address + validate.PrefixPath
	} else {
		validateTokenURI = "http://localhost" + config.Default.Server.PrivateListener.Address + validate.PrefixPath
	}
}

type Handler struct{}

func New() *Handler {
	self := &Handler{}
	return self
}

type resultStruct struct {
	Success bool                   `json:"success"`
	Detail  map[string]interface{} `json:"detail"`
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
	var err error
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

	accessToken := req.FormValue("token")
	clientname := req.FormValue("client")
	username := req.FormValue("user")
	activateClient := req.FormValue("activate_client")

	//Verify token
	var validateResp *http.Response
	httpClient := http.Client{Timeout: 1 * time.Second}

	validateReqForm := url.Values{
		"token":  {accessToken},
		"scope":  {RequireScopes},
		"client": {clientname},
		"user":   {username},
		"type":   {"access-token"},
	}

	for count := 0; count < 5; count++ {
		validateResp, err = httpClient.PostForm(validateTokenURI, validateReqForm)
		if err == nil {
			break
		} else {
			if !strings.Contains(err.Error(), "(Client.Timeout exceeded while awaiting headers)") {
				break
			}
		}
	}
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
	defer validateResp.Body.Close()
	validateResult := &resultStruct{}
	validateData, err := ioutil.ReadAll(validateResp.Body)
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
	err = json.Unmarshal(validateData, validateResult)
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
	if !validateResult.Success {
		resp.WriteHeader(validateResp.StatusCode)
		resp.Write(validateData)
		return
	}

	// Validate activate client
	clientInfo, err := client.GetClientInfo(activateClient)
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

	if clientInfo == nil {
		resp.WriteResult(&response.ErrorActivateClientNotExist)
		return
	}

	if !clientInfo.RequireActivate {
		resp.WriteResult(&response.ErrorNotRequireActivate)
		return
	}

	// Validate user
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
		logger, errr := errorLogger()
		if errr != nil {
			log.Println(PrefixPath+" :", errr)
		} else {
			logger.Println("user", username, "is not exist")
		}
		log.Println(PrefixPath+" : user", username, "is not exist")
		resp.WriteHeader(http.StatusInternalServerError)
		return
	}

	if userInfo.ActivatedClient[activateClient] {
		resp.WriteResult(&response.ErrorAlreadyActivated)
		return
	}

	// Activate client
	userInfo.ActivatedClient[activateClient] = true

	err = user.UpdateUserInfo(userInfo)
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
