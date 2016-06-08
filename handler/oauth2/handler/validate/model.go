package validate

import (
	"net/http"

	"github.com/ElectronicsExtreme/exehttp"
)

type SuccessResponse struct {
	Token  string `json:"token"`
	Client string `json:"client"`
	User   string `json:"user,omitempty"`
	UID    uint64 `json:"uid,omitempty"`
	Scopes string `json:"scope"`
}

var ErrorInvalidRequest exehttp.ErrorResponse = exehttp.ErrorResponse{
	ErrorTag:   "invalid_request",
	HTTPStatus: http.StatusBadRequest,
}

var ErrorInvalidToken exehttp.ErrorResponse = exehttp.ErrorResponse{
	ErrorTag:   "invalid_token",
	HTTPStatus: http.StatusUnauthorized,
}

var ErrorClientMismatch exehttp.ErrorResponse = exehttp.ErrorResponse{
	ErrorTag:         "invalid_token",
	ErrorDescription: "the client in request does not match with token's owner",
	HTTPStatus:       http.StatusBadRequest,
}

var ErrorUserMismatch exehttp.ErrorResponse = exehttp.ErrorResponse{
	ErrorTag:         "invalid_token",
	ErrorDescription: "the username in request does not match with token's owner",
	HTTPStatus:       http.StatusUnauthorized,
}

var ErrorInvalidScope exehttp.ErrorResponse = exehttp.ErrorResponse{
	ErrorTag:         "insufficient_scope",
	ErrorDescription: "the request requires higher privileges than provieded by the access token",
	HTTPStatus:       http.StatusForbidden,
}

var ErrorTokenExpired exehttp.ErrorResponse = exehttp.ErrorResponse{
	ErrorTag:         "invalid_token",
	ErrorDescription: "the access token has expired",
	HTTPStatus:       http.StatusUnauthorized,
}

var ErrorDuplicateParameter exehttp.ErrorResponse = exehttp.ErrorResponse{
	ErrorTag:         "invalid_request",
	ErrorDescription: "some parameters are included more than once",
	HTTPStatus:       http.StatusBadRequest,
}
