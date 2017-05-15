package token

import (
	"net/http"
	"time"

	"exeoauth2/common"
	str "exeoauth2/common/strings"
	"exeoauth2/config"
	accesstokendb "exeoauth2/database/access-token"
	clientdb "exeoauth2/database/client"
	"exeoauth2/handler/oauth2"
	"exeoauth2/logger"
)

const (
	PrefixPath = oauth2.PrefixPath + "/token"
)

var (
	expiresIn   = config.Config.AccessToken.TTL
	tokenLength = config.Config.AccessToken.TokenLength
)

func init() {
}

func Handler(httpResp http.ResponseWriter, req *http.Request) {
	reqLogger, respLogger, errLogger, _ := logger.NewLoggers(PrefixPath)
	resp := NewResponseWriter(httpResp, respLogger)

	err := reqLogger.WriteLog(req)
	if err != nil {
		errLogger.WriteLog(err)
		resp.WriteStatus(http.StatusInternalServerError)
		return
	}

	if req.Method != http.MethodPost {
		resp.WriteStatus(http.StatusMethodNotAllowed)
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
	case oauth2.ClientCredentialsGrant:
		serveClientCredentials(resp, req, errLogger)
	default:
		resp.WriteError(&UnsupportedGrantTypeError, "")
	}
}

func serveClientCredentials(resp *ResponseWriter, req *http.Request, errLogger *logger.ErrorLogger) {
	grantType := req.Form.Get("grant_type")
	scopes := req.Form.Get("scope")
	clientID, clientSecret, ok := req.BasicAuth()
	if !ok {
		resp.WriteError(&InvalidClientError, "")
		return
	}

	clientInfo, err := clientdb.ReadClient(clientID)
	if err != nil {
		errLogger.WriteLog(err)
		resp.WriteStatus(http.StatusInternalServerError)
		return
	}

	if clientInfo == nil {
		resp.WriteError(&InvalidClientError, "")
		return
	}

	// verify password
	if !clientInfo.VerifySecret(clientSecret) {
		resp.WriteError(&InvalidClientError, "")
		return
	}

	// verify client grant
	if clientInfo.GrantClientCredentials == nil {
		resp.WriteError(&UnauthorizedClientError, "")
		return
	}

	// verify client grant scope
	if !clientInfo.VerifyGrantScopes(grantType, scopes) {
		resp.WriteError(&InvalidScopeError, "")
		return
	}

	// generate new token
	tokenInfo := &accesstokendb.AccessTokenInfo{}
	tokenInfo.Token = str.RandomString(tokenLength)
	tokenInfo.Client = clientID
	tokenInfo.Scopes = common.StringToSet(scopes)
	tokenInfo.ExpireTime = time.Now().Add(time.Duration(expiresIn) * time.Second)
	for err := accesstokendb.CreateToken(tokenInfo); err != nil && err.Error() == "duplicate access-token"; {
		tokenInfo.Token = str.RandomString(tokenLength)
		err = accesstokendb.CreateToken(tokenInfo)
	}
	if err != nil {
		errLogger.WriteLog(err)
		resp.WriteStatus(http.StatusInternalServerError)
		return
	}
	resp.WriteSuccess(tokenInfo.Token, expiresIn, "", scopes)
}
