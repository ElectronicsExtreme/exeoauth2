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
	Username           string `json:"username"`
	ActivateEmailToken string `json:"activate-token"`
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

var ErrorDuplicateUsername ErrorResponse = ErrorResponse{
	ErrorTag:         "username_exist",
	ErrorDescription: "username already exist in database",
	HTTPStatus:       http.StatusOK,
}

var ErrorUsernameMissing ErrorResponse = ErrorResponse{
	ErrorTag:         "invalid_request",
	ErrorDescription: "username is missing",
	HTTPStatus:       http.StatusBadRequest,
}

var ErrorPasswordMissing ErrorResponse = ErrorResponse{
	ErrorTag:         "invalid_request",
	ErrorDescription: "password is missing",
	HTTPStatus:       http.StatusBadRequest,
}

var ErrorUIDMissing ErrorResponse = ErrorResponse{
	ErrorTag:         "invalid_request",
	ErrorDescription: "uid is missing",
	HTTPStatus:       http.StatusBadRequest,
}

var ErrorInvalidSecretKey ErrorResponse = ErrorResponse{
	ErrorTag:   "unauthorized_request",
	HTTPStatus: http.StatusUnauthorized,
}
