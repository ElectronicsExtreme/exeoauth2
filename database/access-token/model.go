package accesstoken

import (
	"exeoauth2/common/bearer"
	"net/http"
)

// Result of validation
type ValidateResult struct {
	Token    string
	Scopes   string
	ClientID string
}

var ErrorInvalidRequest bearer.ErrorMessage = bearer.ErrorMessage{
	ErrorTag:   "invalid_request",
	HTTPStatus: http.StatusBadRequest,
}
var ErrorTokenNotFound bearer.ErrorMessage = bearer.ErrorMessage{
	ErrorTag:         "invalid_token",
	ErrorDescription: "token not found",
	HTTPStatus:       http.StatusUnauthorized,
}
var ErrorUserMismatch bearer.ErrorMessage = bearer.ErrorMessage{
	ErrorTag:         "invalid_token",
	ErrorDescription: "the username in request does not match with token's owner",
	HTTPStatus:       http.StatusUnauthorized,
}
var ErrorInvalidScope bearer.ErrorMessage = bearer.ErrorMessage{
	ErrorTag:         "insufficient_scope",
	ErrorDescription: "the request requires scope outside than provided by the access token",
	HTTPStatus:       http.StatusForbidden,
}
var ErrorTokenExpired bearer.ErrorMessage = bearer.ErrorMessage{
	ErrorTag:         "invalid_token",
	ErrorDescription: "the access token has expired",
	HTTPStatus:       http.StatusUnauthorized,
}
