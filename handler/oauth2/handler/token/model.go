package token

import (
	"encoding/json"
	"net/http"

	"github.com/ElectronicsExtreme/exehttp"
)

type ResponseWriter struct {
	*exehttp.ResponseWriter
}

func NewResponseWriter(resp *exehttp.ResponseWriter) *ResponseWriter {
	return &ResponseWriter{resp}
}

func (self *ResponseWriter) WriteSuccess(accessToken string, expiresIn int, refreshToken string, scopes string) error {
	resp := &SuccessResponse{
		AccessToken:  accessToken,
		TokenType:    "bearer",
		ExpiresIn:    expiresIn,
		RefreshToken: refreshToken,
		Scope:        scopes,
	}
	data, err := json.Marshal(resp)
	if err != nil {
		self.WriteHeader(http.StatusInternalServerError)
		self.ResponseLogInfo.HTTPStatus = http.StatusInternalServerError
		self.ResponseLogInfo.Write()
		return err
	}
	self.Header().Set("Content-Type", "application/json")
	self.Header().Set("Cache-Control", "no-store")
	self.Header().Set("Pragma", "no-cache")
	self.WriteHeader(http.StatusOK)
	self.Write(data)
	self.ResponseLogInfo.HTTPStatus = http.StatusOK
	self.ResponseLogInfo.Body = string(data)
	self.ResponseLogInfo.Write()
	return nil
}

func (self *ResponseWriter) WriteError(resp *ErrorResponse, description string) error {
	var data []byte
	var err error

	if description == "" {
		data, err = json.Marshal(resp)
	} else {
		data, err = json.Marshal(&ErrorResponse{
			ErrorTag:         resp.ErrorTag,
			ErrorDescription: description,
			ErrorURI:         resp.ErrorURI,
		})
	}
	if err != nil {
		self.WriteHeader(http.StatusInternalServerError)
		self.ResponseLogInfo.HTTPStatus = http.StatusInternalServerError
		self.ResponseLogInfo.Write()
		return err
	}
	self.Header().Set("Content-Type", "application/json")
	self.Header().Set("Cache-Control", "no-store")
	self.Header().Set("Pragma", "no-cache")
	self.WriteHeader(resp.HTTPStatus)
	self.Write(data)
	self.ResponseLogInfo.HTTPStatus = resp.HTTPStatus
	self.ResponseLogInfo.Body = string(data)
	return nil
}

type SuccessResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type ErrorResponse struct {
	ErrorTag         string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
	HTTPStatus       int    `json:"-"`
}

var InvalidRequestError ErrorResponse = ErrorResponse{
	ErrorTag:   "invalid_request",
	HTTPStatus: http.StatusBadRequest,
}

var InvalidClientError ErrorResponse = ErrorResponse{
	ErrorTag:         "invalid_client",
	ErrorDescription: "client authentication failed",
	HTTPStatus:       http.StatusUnauthorized,
}

var InvalidGrantError ErrorResponse = ErrorResponse{
	ErrorTag:         "invalid_grant",
	ErrorDescription: "the provided authorization grant or refresh token is invalid",
	HTTPStatus:       http.StatusBadRequest,
}

var UnactivatedAccountError ErrorResponse = ErrorResponse{
	ErrorTag:         "invalid_grant",
	ErrorDescription: "this account is not activated by email yet",
	HTTPStatus:       http.StatusBadRequest,
}

var UnauthorizedClientError ErrorResponse = ErrorResponse{
	ErrorTag:         "unauthorized_client",
	ErrorDescription: "the authenticated client is not authorized to use this authorization grant type",
	HTTPStatus:       http.StatusBadRequest,
}

var AccontNotActivateError ErrorResponse = ErrorResponse{
	ErrorTag:         "unauthorized_client",
	ErrorDescription: "account is not activated for this client",
	HTTPStatus:       http.StatusBadRequest,
}

var UnsupportedGrantTypeError ErrorResponse = ErrorResponse{
	ErrorTag:         "unsupported_grant_type",
	ErrorDescription: "the authorization grant type is not supported by the authorization server",
	HTTPStatus:       http.StatusBadRequest,
}

var InvalidScopeError ErrorResponse = ErrorResponse{
	ErrorTag:         "invalid_scope",
	ErrorDescription: "the request scope is invalid",
	HTTPStatus:       http.StatusBadRequest,
}
