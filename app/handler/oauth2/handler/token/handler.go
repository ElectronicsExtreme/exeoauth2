package token

import (
	"net/http"
	"time"

	"github.com/ElectronicsExtreme/exehttp"

	"exeoauth2/database"
	"exeoauth2/handler/oauth2"
	"exeoauth2/handler/oauth2/string-generator"
	"exeoauth2/handler/oauth2/verify"
)

const (
	PrefixPath  = oauth2.PrefixPath + "/token"
	expiresIn   = 3600
	tokenLength = 32
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

func (self *Handler) ServeHTTP(httpResp *exehttp.ResponseWriter, req *http.Request) {
	resp := NewResponseWriter(httpResp)
	if req.Method != "POST" {
		resp.WriteHeader(http.StatusMethodNotAllowed)
		resp.ResponseLogInfo.HTTPStatus = http.StatusMethodNotAllowed
		resp.ResponseLogInfo.Write()
		return
	}
	req.ParseForm()
	for _, value := range req.Form {
		if len(value) > 1 {
			resp.WriteError(&InvalidRequestError, "request parameters must not be included more than once")
			return
		}
	}
	grantType := req.Form.Get("grant_type")
	switch grantType {
	case oauth2.ResourceOwnerCredentialsGrant:
		self.serveResourceOwnerCredentials(resp, req)
	case oauth2.ClientCredentialsGrant:
		self.serveClientCredentials(resp, req)
	default:
		resp.WriteError(&UnsupportedGrantTypeError, "")
	}
}

func (self *Handler) serveClientCredentials(resp *ResponseWriter, req *http.Request) {
	redisClient, err := database.NewClient()
	if err != nil {
		self.errorLogInfo.Body = err.Error()
		self.errorLogInfo.Write()
		resp.WriteHeader(http.StatusInternalServerError)
		resp.ResponseLogInfo.HTTPStatus = http.StatusInternalServerError
		resp.ResponseLogInfo.Write()
		return
	}
	grantType := req.Form.Get("grant_type")
	scopes := req.Form.Get("scope")
	username, password, ok := req.BasicAuth()
	if !ok {
		resp.WriteError(&InvalidClientError, "")
		return
	}

	clientInfo, err := redisClient.GetClientInfo(username)
	if err != nil {
		self.errorLogInfo.Body = err.Error()
		self.errorLogInfo.Write()
		resp.WriteHeader(http.StatusInternalServerError)
		resp.ResponseLogInfo.HTTPStatus = http.StatusInternalServerError
		resp.ResponseLogInfo.Write()
		return
	}

	if clientInfo == nil {
		resp.WriteError(&InvalidClientError, "")
		return
	}

	// verify password
	if !verify.VerifyClientPassword(clientInfo, password) {
		resp.WriteError(&InvalidClientError, "")
		return
	}

	// verify client grant
	if clientInfo.GrantClientCredentials == nil {
		resp.WriteError(&UnauthorizedClientError, "")
		return
	}

	// verify client grant scope
	if !verify.VerifyGrantScopes(clientInfo, grantType, scopes) {
		resp.WriteError(&InvalidScopeError, "")
		return
	}

	// generate new token
	token := stringgenerator.RandomString(tokenLength)
	tokenInfo := &database.AccessTokenInfo{}
	tokenInfo.Token = token
	tokenInfo.Client = username
	tokenInfo.User = ""
	tokenInfo.UID = ""
	tokenInfo.Scopes = database.StringToSet(scopes)
	expireTime := time.Now().Add(time.Duration(expiresIn) * time.Second)
	tokenInfo.ExpireTime = expireTime
	for err := redisClient.PutAccessTokenInfo(tokenInfo); err != nil && err.Error() == "duplicate token"; {
		tokenInfo.Token = stringgenerator.RandomString(tokenLength)
		err = redisClient.PutAccessTokenInfo(tokenInfo)
	}
	if err != nil {
		self.errorLogInfo.Body = err.Error()
		self.errorLogInfo.Write()
		resp.WriteHeader(http.StatusInternalServerError)
		resp.ResponseLogInfo.HTTPStatus = http.StatusInternalServerError
		resp.ResponseLogInfo.Write()
		return
	}
	resp.WriteSuccess(tokenInfo.Token, expiresIn, "", scopes)
}

func (self *Handler) serveResourceOwnerCredentials(resp *ResponseWriter, req *http.Request) {
	redisClient, err := database.NewClient()
	grantType := req.Form.Get("grant_type")
	username := req.Form.Get("username")
	password := req.Form.Get("password")
	scopes := req.Form.Get("scope")
	clientUsername, clientPassword, ok := req.BasicAuth()
	if !ok {
		resp.WriteError(&InvalidClientError, "")
		return
	}

	clientInfo, err := redisClient.GetClientInfo(clientUsername)
	if err != nil {
		self.errorLogInfo.Body = err.Error()
		self.errorLogInfo.Write()
		resp.WriteHeader(http.StatusInternalServerError)
		resp.ResponseLogInfo.HTTPStatus = http.StatusInternalServerError
		resp.ResponseLogInfo.Write()
		return
	}

	if clientInfo == nil {
		resp.WriteError(&InvalidClientError, "")
		return
	}

	if username == "" || password == "" {
		resp.WriteError(&InvalidGrantError, "")
		return
	}

	userInfo, err := redisClient.GetUserInfo(username)
	if err != nil {
		self.errorLogInfo.Body = err.Error()
		self.errorLogInfo.Write()
		resp.WriteHeader(http.StatusInternalServerError)
		resp.ResponseLogInfo.HTTPStatus = http.StatusInternalServerError
		resp.ResponseLogInfo.Write()
		return
	}

	if userInfo == nil {
		resp.WriteError(&InvalidGrantError, "username or password is invalid")
		return
	}

	// verify client password
	if !verify.VerifyClientPassword(clientInfo, clientPassword) {
		resp.WriteError(&InvalidClientError, "")
		return
	}

	// verify resource owner credential
	if !verify.VerifyUserPassword(userInfo, password) {
		resp.WriteError(&InvalidGrantError, "username or password is invalid")
		return
	}

	// verify client grant
	if clientInfo.GrantResourceOwner == nil {
		resp.WriteError(&UnauthorizedClientError, "")
		return
	}

	// verify client grant scope
	if !verify.VerifyGrantScopes(clientInfo, grantType, scopes) {
		resp.WriteError(&InvalidScopeError, "")
		return
	}

	// generate new token
	token := stringgenerator.RandomString(tokenLength)
	tokenInfo := &database.AccessTokenInfo{}
	tokenInfo.Token = token
	tokenInfo.Client = clientUsername
	tokenInfo.User = userInfo.Username
	tokenInfo.UID = userInfo.UID
	tokenInfo.Scopes = database.StringToSet(scopes)
	expireTime := time.Now().Add(time.Duration(expiresIn) * time.Second)
	tokenInfo.ExpireTime = expireTime
	for err := redisClient.PutAccessTokenInfo(tokenInfo); err != nil && err.Error() == "duplicate token"; {
		tokenInfo.Token = stringgenerator.RandomString(tokenLength)
		err = redisClient.PutAccessTokenInfo(tokenInfo)
	}
	if err != nil {
		self.errorLogInfo.Body = err.Error()
		self.errorLogInfo.Write()
		resp.WriteHeader(http.StatusInternalServerError)
		resp.ResponseLogInfo.HTTPStatus = http.StatusInternalServerError
		resp.ResponseLogInfo.Write()
		return
	}
	resp.WriteSuccess(tokenInfo.Token, expiresIn, "", scopes)
}