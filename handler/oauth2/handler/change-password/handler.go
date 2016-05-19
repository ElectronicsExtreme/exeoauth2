package changepassword

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/asaskevich/govalidator"

	"dev.corp.extreme.co.th/exe-account/account-interface/config"
	"dev.corp.extreme.co.th/exe-account/account-interface/encrypt"
	"dev.corp.extreme.co.th/exe-account/account-interface/handler/oauth2"
	"dev.corp.extreme.co.th/exe-account/account-interface/handler/oauth2/database/user"
	"dev.corp.extreme.co.th/exe-account/account-interface/handler/oauth2/handler/change-password/response-writer"
	//"dev.corp.extreme.co.th/exe-account/account-interface/handler/oauth2/handler/validate"
	"dev.corp.extreme.co.th/exe-account/account-interface/handler/oauth2/verify"
	"dev.corp.extreme.co.th/exe-account/account-interface/httputilextend"
)

const (
	RequireScopes = "change_password"
	verifyKey     = "cuhMyHru2WADY-PiIn0dfFZjc1c908v5DCvgmediRCcO_A9itVbP3SIKivtdXlaq"
)

var (
	PrefixPath       = oauth2.PrefixPath + "/change_password"
	validateTokenURI = ""
	verifyEmailURI   = config.Default.APIURI.VerifyEmail
	cpDragoURI       = config.Default.APIURI.ChangePassDrago
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

type dragoResultStruct struct {
	ResponseCode int    `json:"response_code"`
	Message      string `json:"message"`
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
	client := req.FormValue("client")
	username := req.FormValue("user")
	oldPassword := req.FormValue("old_password")
	newPassword := req.FormValue("new_password")
	email := req.FormValue("email")

	//Verify token
	var validateResp *http.Response
	httpClient := http.Client{Timeout: 1 * time.Second}

	validateReqForm := url.Values{
		"token":  {accessToken},
		"scope":  {RequireScopes},
		"client": {client},
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

	//Validate Request
	if len(newPassword) > 16 || len(newPassword) < 6 {
		resp.WriteResult(&response.ErrorPasswordInvalidLength)
		return
	}
	if !govalidator.IsAlphanumeric(newPassword) {
		resp.WriteResult(&response.ErrorPasswordInvalidCharacter)
		return
	}

	// Verify Current Password
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
	if !verify.VerifyUserPassword(userInfo, oldPassword) {
		resp.WriteResult(&response.ErrorPasswordInvalid)
		return
	}

	// Verify new password
	if newPassword == oldPassword {
		resp.WriteResult(&response.ErrorPasswordRemainTheSame)
		return
	}

	//Verify email
	var verifyEmailResp *http.Response
	verifyEmailReqForm := url.Values{
		"key":   {verifyKey},
		"uid":   {strconv.FormatFloat(validateResult.Detail["uid"].(float64), 'f', 0, 64)},
		"email": {email},
	}

	for count := 0; count < 5; count++ {
		verifyEmailResp, err = httpClient.PostForm(verifyEmailURI, verifyEmailReqForm)
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
	defer verifyEmailResp.Body.Close()
	verifyEmailResult := &resultStruct{}
	verifyEmailData, err := ioutil.ReadAll(verifyEmailResp.Body)
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
	err = json.Unmarshal(verifyEmailData, verifyEmailResult)
	if err != nil {
		logger, errr := errorLogger()
		if errr != nil {
			log.Println(PrefixPath+" :", errr)
		} else {
			logger.Println(err)
		}
		log.Println(PrefixPath+" :", err)
		resp.WriteHeader(http.StatusInternalServerError)
		log.Println(string(verifyEmailData))
		return
	}
	if !verifyEmailResult.Success {
		logger, errr := errorLogger()
		if errr != nil {
			log.Println(PrefixPath+" :", errr)
		} else {
			logger.Println(errors.New(verifyEmailResult.Detail["error_description"].(string)))
		}
		log.Println(PrefixPath+" :", err)
		resp.WriteHeader(http.StatusInternalServerError)
		log.Printf("%+v\n", verifyEmailResult.Detail)
		return
	}

	// Change Password
	encryptedPassword := encrypt.EncryptText1Way([]byte(newPassword), []byte(string(userInfo.Salt)))
	user.ChangeUserPassword(username, encryptedPassword)
	resp.WriteResult(&response.SuccessResponse{})

	// Change Password Dragonica
	var cpDragoResp *http.Response
	cpDragoReqForm := url.Values{
		"uid":      {userInfo.UID},
		"password": {newPassword},
	}

	cpDragoReq, err := http.NewRequest("PUT", cpDragoURI, strings.NewReader(cpDragoReqForm.Encode()))
	if err != nil {
		logger, errr := errorLogger()
		if errr != nil {
			log.Println(PrefixPath+" :", errr)
		} else {
			logger.Println(err)
		}
		log.Println(PrefixPath+" :", err)
		return
	}
	cpDragoReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	for count := 0; count < 5; count++ {
		cpDragoResp, err = httpClient.Do(cpDragoReq)
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
		return
	}
	defer cpDragoResp.Body.Close()
	cpDragoResult := &dragoResultStruct{}
	cpDragoData, err := ioutil.ReadAll(cpDragoResp.Body)
	if err != nil {
		logger, errr := errorLogger()
		if errr != nil {
			log.Println(PrefixPath+" :", errr)
		} else {
			logger.Println(err)
		}
		log.Println(PrefixPath+" :", err)
		return
	}
	err = json.Unmarshal(cpDragoData, cpDragoResult)
	if err != nil {
		logger, errr := errorLogger()
		if errr != nil {
			log.Println(PrefixPath+" :", errr)
		} else {
			logger.Println(err)
		}
		log.Println(PrefixPath+" :", err)
		return
	}
	if cpDragoResult.ResponseCode != 0 {
		message := fmt.Sprintf("dragonica change password uid = %v error %v", userInfo.UID, cpDragoResult.Message)
		logger, errr := errorLogger()
		if errr != nil {
			log.Println(PrefixPath+" :", errr)
		} else {
			logger.Println(message)
		}
		log.Println(PrefixPath+" :", message)
		return
	}
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
