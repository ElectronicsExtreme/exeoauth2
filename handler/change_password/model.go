package changepassword

import (
	"net/http"

	"github.com/ElectronicsExtreme/exehttp"
)

var ErrorUserMissing exehttp.ErrorResponse = exehttp.ErrorResponse{
	ErrorTag:         "invalid_request",
	ErrorDescription: "username is missing",
	HTTPStatus:       http.StatusBadRequest,
}

var ErrorUserInvalid exehttp.ErrorResponse = exehttp.ErrorResponse{
	ErrorTag:         "invalid_request",
	ErrorDescription: "username is invalid",
	HTTPStatus:       http.StatusBadRequest,
}

var ErrorUserNotExist exehttp.ErrorResponse = exehttp.ErrorResponse{
	ErrorTag:         "invalid_request",
	ErrorDescription: "username does not exist",
	HTTPStatus:       http.StatusBadRequest,
}

var ErrorUIDNotNumeric exehttp.ErrorResponse = exehttp.ErrorResponse{
	ErrorTag:         "invalid_request",
	ErrorDescription: "uid must be an integer",
	HTTPStatus:       http.StatusBadRequest,
}

var ErrorPasswordMissing exehttp.ErrorResponse = exehttp.ErrorResponse{
	ErrorTag:         "invalid_request",
	ErrorDescription: "password is missing",
	HTTPStatus:       http.StatusBadRequest,
}
