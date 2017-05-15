package token

import (
	"encoding/json"
	"exeoauth2/logger"
	"net/http"
)

// Duplicate of common.ResponseWriter. Write result with different format from the rest of api,
// according to RFC6749.
type ResponseWriter struct {
	http.ResponseWriter
	respLogger *logger.ResponseLogger
}

// NewResponseWriter create new ResponseWriter the received logger binded
func NewResponseWriter(resp http.ResponseWriter, logger *logger.ResponseLogger) *ResponseWriter {
	return &ResponseWriter{resp, logger}
}

func (self *ResponseWriter) WriteSuccess(accessToken string, expiresIn uint, refreshToken string, scopes string) error {
	resp := &SuccessResponse{
		AccessToken:  accessToken,
		TokenType:    "bearer",
		ExpiresIn:    expiresIn,
		RefreshToken: refreshToken,
		Scope:        scopes,
	}
	data, err := json.Marshal(resp)
	if err != nil {
		self.WriteStatus(http.StatusInternalServerError)
		return err
	}
	self.Header().Set("Content-Type", "application/json")
	self.Header().Set("Cache-Control", "no-store")
	self.Header().Set("Pragma", "no-cache")
	self.WriteHeader(http.StatusOK)
	self.Write(data)
	self.respLogger.Logger.HTTPStatus = http.StatusOK
	self.respLogger.Logger.Body = string(data)
	self.respLogger.WriteLog()
	return nil
}

func (self *ResponseWriter) WriteError(resp *ErrorResponse, description string) error {
	if description != "" {
		resp.ErrorDescription = description
	}

	data, err := json.Marshal(resp)
	if err != nil {
		self.WriteStatus(http.StatusInternalServerError)
		return err
	}
	self.Header().Set("Content-Type", "application/json")
	self.Header().Set("Cache-Control", "no-store")
	self.Header().Set("Pragma", "no-cache")
	self.WriteHeader(resp.HTTPStatus)
	self.Write(data)
	self.respLogger.Logger.HTTPStatus = resp.HTTPStatus
	self.respLogger.Logger.Body = string(data)
	self.respLogger.WriteLog()
	return nil
}

func (self *ResponseWriter) WriteStatus(status int) error {
	self.Header().Set("Cache-Control", "no-store")
	self.Header().Set("Pragma", "no-cache")
	self.WriteHeader(status)
	self.respLogger.Logger.HTTPStatus = status
	self.respLogger.WriteLog()
	return nil
}
