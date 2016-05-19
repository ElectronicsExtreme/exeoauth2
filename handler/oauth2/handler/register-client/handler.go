package registerclient

import (
	"crypto/rand"
	"encoding/json"
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
	"dev.corp.extreme.co.th/exe-account/account-interface/handler/oauth2/database"
	"dev.corp.extreme.co.th/exe-account/account-interface/handler/oauth2/database/client"
	"dev.corp.extreme.co.th/exe-account/account-interface/handler/oauth2/handler/register-client/response-writer"
	"dev.corp.extreme.co.th/exe-account/account-interface/handler/oauth2/handler/validate"
	"dev.corp.extreme.co.th/exe-account/account-interface/httputilextend"
)

const (
	RequireScopes = "register_client"
	saltLength    = 64
)

var (
	PrefixPath       = oauth2.PrefixPath + "/register_client"
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
	reqClient := req.FormValue("client")

	clientUsername := req.FormValue("client_username")
	password := req.FormValue("client_password")
	ownerUsername := req.FormValue("owner_username")
	ownerUID := req.FormValue("owner_uid")
	grantAuthorizationCodeString := req.FormValue("grant_authorization")
	grantImplicitString := req.FormValue("grant_implicit")
	grantResourceOwner := req.FormValue("grant_resource_owner")
	grantClientCredentials := req.FormValue("grant_client_credentials")
	redirectURIAuthorcode := req.FormValue("uri_authorization")
	redirectURIImplicit := req.FormValue("uri_implicit")
	clientName := req.FormValue("client_name")
	description := req.FormValue("client_description")
	requireActivateString := req.FormValue("require_activate")
	regIP := req.FormValue("reg_ip")

	//   validate token
	var err error
	var validateResp *http.Response
	httpClient := http.Client{Timeout: 1 * time.Second}

	validateReqForm := url.Values{
		"token":  {accessToken},
		"scope":  {RequireScopes},
		"client": {reqClient},
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

	//   username size
	if len(clientUsername) < 6 || len(clientUsername) > 20 {
		resp.WriteResult(&response.ErrorUsernameInvalidLength)
		return
	}
	//   username charactor
	if !govalidator.IsAlphanumeric(clientUsername) {
		resp.WriteResult(&response.ErrorUsernameInvalidCharacter)
		return
	}
	//	 username already exist
	clientInfo, err := client.GetClientInfo(clientUsername)
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
	if clientInfo != nil {
		resp.WriteResult(&response.ErrorUsernameDuplicate)
		return
	}
	//   password size
	if len(password) < 10 || len(password) > 100 {
		resp.WriteResult(&response.ErrorPasswordInvalidLength)
		return
	}
	//   password charactor
	if !isValidPassword(password) {
		resp.WriteResult(&response.ErrorPasswordInvalidCharacter)
		return
	}
	//   clientname size
	if len(clientName) < 6 || len(clientName) > 20 {
		resp.WriteResult(&response.ErrorNameInvalidLength)
		return
	}
	//   clientname charactor
	if !govalidator.IsAlphanumeric(clientName) {
		resp.WriteResult(&response.ErrorNameInvalidCharacter)
		return
	}
	//   requireactivate is true or false
	var requireActivate bool
	if strings.ToLower(requireActivateString) == "true" {
		requireActivate = true
	} else if strings.ToLower(requireActivateString) == "false" {
		requireActivate = false
	} else {
		resp.WriteResult(&response.ErrorRequireActivateInvalid)
		return
	}

	//   regIP malform
	if !govalidator.IsIP(regIP) {
		resp.WriteResult(&response.ErrorRegIPInvalid)
		return
	}

	var salt []byte = make([]byte, saltLength)
	_, err = rand.Read(salt)
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
	encryptedPassword := encrypt.EncryptText1Way([]byte(password), salt)

	newClientInfo := &client.ClientInfo{}
	newClientInfo.ClientUsername = clientUsername
	newClientInfo.EncryptedPassword = encryptedPassword
	newClientInfo.OwnerUID = ownerUID
	newClientInfo.OwnerUsername = ownerUsername
	newClientInfo.GrantAuthorizationCode = database.StringToSet(grantAuthorizationCodeString)
	newClientInfo.GrantImplicit = database.StringToSet(grantImplicitString)
	newClientInfo.GrantResourceOwner = database.StringToSet(grantResourceOwner)
	newClientInfo.GrantClientCredentials = database.StringToSet(grantClientCredentials)
	newClientInfo.RedirectURIAuthorCode = redirectURIAuthorcode
	newClientInfo.RedirectURIImplicit = redirectURIImplicit
	newClientInfo.ClientName = clientName
	newClientInfo.Description = description
	newClientInfo.Salt = salt
	newClientInfo.CreateDate = time.Now()
	newClientInfo.UpdateDate = time.Now()
	//newClientInfo.CreateUser
	//newClientInfo.UpdateUser
	newClientInfo.CreateIP = regIP
	newClientInfo.UpdateIP = regIP
	newClientInfo.RequireActivate = requireActivate

	err = client.PutClientInfo(newClientInfo)
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

	successResponse := &response.SuccessResponse{}
	successResponse.ClientUsername = newClientInfo.ClientUsername
	successResponse.OwnerUsername = newClientInfo.OwnerUsername
	successResponse.OwnerUID = newClientInfo.OwnerUID
	successResponse.GrantAuthorizationCode = database.SetToString(newClientInfo.GrantAuthorizationCode)
	successResponse.GrantImplicit = database.SetToString(newClientInfo.GrantImplicit)
	successResponse.GrantResourceOwner = database.SetToString(newClientInfo.GrantResourceOwner)
	successResponse.GrantClientCredentials = database.SetToString(newClientInfo.GrantClientCredentials)
	successResponse.RedirectURIAuthorCode = newClientInfo.RedirectURIAuthorCode
	successResponse.RedirectURIImplicit = newClientInfo.RedirectURIImplicit
	successResponse.ClientName = newClientInfo.ClientName
	successResponse.Description = newClientInfo.Description
	successResponse.RequireActivate = newClientInfo.RequireActivate
	resp.WriteResult(successResponse)
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

func isValidPassword(password string) bool {
	// all printable ascii except space
	for _, character := range password {
		if character < 33 || character > 126 {
			return false
		}
	}
	return true
}
