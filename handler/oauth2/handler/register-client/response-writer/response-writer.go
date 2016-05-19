package response

import (
	"encoding/json"
	"log"
	"net/http"
)

const ()

var ()

func init() {}

type ResponseWriter struct {
	http.ResponseWriter
}

type ErrorResponse struct {
	ErrorTag         string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	HTTPStatus       int    `json:"-"`
}

type SuccessResponse struct {
	ClientUsername         string `json:"client_username"`
	OwnerUsername          string `json:"owner_username"`
	OwnerUID               string `json:"owner_uid"`
	GrantAuthorizationCode string `json:"grant_authorization,omitempty"`
	GrantImplicit          string `json:"grant_implicit,omitempty"`
	GrantResourceOwner     string `json:"grant_resource_owner,omitempty"`
	GrantClientCredentials string `json:"grant_client_credentials,omitempty"`
	RedirectURIAuthorCode  string `json:"uri_authorization,omitempty"`
	RedirectURIImplicit    string `json:"uri_implicit,omitempty"`
	ClientName             string `json:"client_name"`
	Description            string `json:"client_description"`
	RequireActivate        bool   `json:"require_activate"`
}

type Results struct {
	Success bool        `json:"success"`
	Detail  interface{} `json:"detail"`
}

func NewResponseWriter(resp http.ResponseWriter) *ResponseWriter {
	return &ResponseWriter{
		resp,
	}
}

func (self *ResponseWriter) WriteResult(detail interface{}) {
	results := Results{}
	var httpStatus int = 0
	switch detail := detail.(type) {
	case *ErrorResponse:
		results.Success = false
		if detail.HTTPStatus == 0 {
			log.Println("http status is not defined")
			self.WriteHeader(http.StatusInternalServerError)
			return
		}
		httpStatus = detail.HTTPStatus
	case *SuccessResponse:
		results.Success = true
		httpStatus = http.StatusOK
	default:
		log.Printf("unknown response type for token validator : %T\n", detail)
		self.WriteHeader(http.StatusInternalServerError)
		return
	}
	results.Detail = detail
	data, err := json.Marshal(&results)
	if err != nil {
		self.WriteHeader(http.StatusInternalServerError)
		log.Println(err)
		return
	}
	self.WriteHeader(httpStatus)
	self.Write(data)
}

var ErrorMethodNotAllow ErrorResponse = ErrorResponse{
	ErrorTag:         "invalid_method",
	ErrorDescription: "method other than POST is not allowed",
	HTTPStatus:       http.StatusMethodNotAllowed,
}

var ErrorDuplicateParameters ErrorResponse = ErrorResponse{
	ErrorTag:         "invalid_request",
	ErrorDescription: "request parameters must not be included more than once",
	HTTPStatus:       http.StatusBadRequest,
}

var ErrorUsernameInvalidCharacter ErrorResponse = ErrorResponse{
	ErrorTag:         "invalid_request",
	ErrorDescription: "client's username contain invalid character",
	HTTPStatus:       http.StatusBadRequest,
}

var ErrorUsernameInvalidLength ErrorResponse = ErrorResponse{
	ErrorTag:         "invalid_request",
	ErrorDescription: "client's username has invalid length",
	HTTPStatus:       http.StatusBadRequest,
}

var ErrorUsernameDuplicate ErrorResponse = ErrorResponse{
	ErrorTag:         "invalid_request",
	ErrorDescription: "client's username already exist",
	HTTPStatus:       http.StatusBadRequest,
}

var ErrorPasswordInvalidCharacter ErrorResponse = ErrorResponse{
	ErrorTag:         "invalid_request",
	ErrorDescription: "client's password contain invalid character",
	HTTPStatus:       http.StatusBadRequest,
}

var ErrorPasswordInvalidLength ErrorResponse = ErrorResponse{
	ErrorTag:         "invalid_request",
	ErrorDescription: "client's password has invalid length",
	HTTPStatus:       http.StatusBadRequest,
}

var ErrorNameInvalidCharacter ErrorResponse = ErrorResponse{
	ErrorTag:         "invalid_request",
	ErrorDescription: "client's name contain invalid character",
	HTTPStatus:       http.StatusBadRequest,
}

var ErrorNameInvalidLength ErrorResponse = ErrorResponse{
	ErrorTag:         "invalid_request",
	ErrorDescription: "client's name has invalid length",
	HTTPStatus:       http.StatusBadRequest,
}

var ErrorRequireActivateInvalid ErrorResponse = ErrorResponse{
	ErrorTag:         "invalid_request",
	ErrorDescription: "require_activate field must be true or false",
	HTTPStatus:       http.StatusBadRequest,
}

var ErrorRegIPInvalid ErrorResponse = ErrorResponse{
	ErrorTag:         "invalid_request",
	ErrorDescription: "registered ip is malformed",
	HTTPStatus:       http.StatusBadRequest,
}
