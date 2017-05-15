package common

import (
	"encoding/json"
	"fmt"
	"net/http"

	"exeoauth2/common/bearer"
	"exeoauth2/logger"
)

// ResponseWriter is a http.ResponseWriter bind with its logger.
type ResponseWriter struct {
	http.ResponseWriter
	respLogger *logger.ResponseLogger
}

// NewResponseWriter create new ResponseWriter the received logger binded
func NewResponseWriter(resp http.ResponseWriter, logger *logger.ResponseLogger) *ResponseWriter {
	return &ResponseWriter{resp, logger}
}

// WriteResults receive predefined struct as a results and write it to http response, and also write the response to log.
func (self *ResponseWriter) WriteResults(data interface{}) error {
	results := Results{}
	var httpStatus int = 0
	switch data := data.(type) {
	case *ErrorResponse:
		results.Success = false
		if data.HTTPStatus == 0 {
			self.WriteResults(&ErrorStatusInternalServerError)
			return fmt.Errorf("http status is not defined")
		} else {
			httpStatus = data.HTTPStatus
		}
		results.Data = data
	case *ValidateErrorResponse:
		results.Success = false
		data.ErrorTag = "invalid_request"
		results.Data = data
		httpStatus = http.StatusBadRequest
	case *bearer.ErrorMessage:
		results.Success = false
		httpStatus = data.HTTPStatus
		data.HTTPStatus = 0 // remove HTTPStatus to prevent bearer.WriteError to write header.
		bearer.WriteError(self, *data)
		results.Data = &ErrorResponse{
			ErrorTag:         data.ErrorTag,
			ErrorDescription: data.ErrorDescription,
		}
	case *Results:
		results = *data
		if data.HTTPStatus == 0 {
			httpStatus = http.StatusOK
		} else {
			httpStatus = data.HTTPStatus
		}
	case Data:
		results.Success = data.Success()
		httpStatus = http.StatusOK
		results.Data = data
	case nil:
		self.WriteResults(ErrorStatusInternalServerError)
		return fmt.Errorf("receive nil data", data)
	default:
		self.WriteResults(ErrorStatusInternalServerError)
		return fmt.Errorf("unknown data type %T\n", data)
	}
	resultsByte, err := json.Marshal(&results)
	if err != nil {
		self.WriteResults(ErrorStatusInternalServerError)
		return err
	}
	self.Header().Set("Content-Type", "application/json")
	self.WriteHeader(httpStatus)
	_, err = self.Write(resultsByte)

	//logWriter()
	self.respLogger.Logger.HTTPStatus = httpStatus
	self.respLogger.Logger.Body = string(resultsByte)
	self.respLogger.WriteLog()
	if err != nil {
		return err
	}
	return nil
}

// Results is a top level json which will be writen into response.
type Results struct {
	Success    bool        `json:"success"`
	Data       interface{} `json:"data"`
	HTTPStatus int         `json:"-"`
}

// Data is an interface which will be write into data field of Results. It also contain Success method to determine the result of request.
type Data interface {
	Success() bool
}

// ErrorResponse is a struct that contain info of an error to be writen to response.
type ErrorResponse struct {
	ErrorTag         string `json:"error"`
	ErrorDescription string `json:"error_description"`
	HTTPStatus       int    `json:"-"`
}

// ValidateErrorResponse is a struct which contain slice of string as an error_description
type ValidateErrorResponse struct {
	ErrorTag          string   `json:"error"`
	ErrorDescriptions []string `json:"error_descriptions"`
}

//  Add method add new value to list of error_desctiption
func (v *ValidateErrorResponse) Add(value string) {
	v.ErrorDescriptions = append(v.ErrorDescriptions, value)
}

// Predefined status internal server error
var ErrorStatusInternalServerError *ErrorResponse = &ErrorResponse{
	ErrorTag:   "internal_server_error",
	HTTPStatus: http.StatusInternalServerError,
}

// Predefined status not found
var ErrorStatusNotFound *ErrorResponse = &ErrorResponse{
	ErrorTag:   "not_found",
	HTTPStatus: http.StatusNotFound,
}

// Predefined status method not allowed
var ErrorStatusMethodNotAllowed *ErrorResponse = &ErrorResponse{
	ErrorTag:   "method_not_allowed",
	HTTPStatus: http.StatusMethodNotAllowed,
}

// Predefined duplicate parameter error
var ErrorDuplicateParameters *ErrorResponse = &ErrorResponse{
	ErrorTag:         "invalid_request",
	ErrorDescription: "request parameters must not be included more than once",
	HTTPStatus:       http.StatusBadRequest,
}
