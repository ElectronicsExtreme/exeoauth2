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
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	HTTPStatus       int    `json:"-"`
}

type SuccessResponse struct {
	ActivationToken string `json:"activate_token"`
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
	Error:            "invalid_method",
	ErrorDescription: "method other than POST is not allowed",
	HTTPStatus:       http.StatusMethodNotAllowed,
}

var ErrorDuplicateParameters ErrorResponse = ErrorResponse{
	Error:            "invalid_request",
	ErrorDescription: "request parameters must not be included more than once",
	HTTPStatus:       http.StatusBadRequest,
}

var ErrorUserNotFound ErrorResponse = ErrorResponse{
	Error:            "invalid_request",
	ErrorDescription: "the requested user is not exist",
	HTTPStatus:       http.StatusBadRequest,
}

var ErrorAccountActivated ErrorResponse = ErrorResponse{
	Error:            "account_activated",
	ErrorDescription: "account is already activated",
	HTTPStatus:       http.StatusBadRequest,
}
