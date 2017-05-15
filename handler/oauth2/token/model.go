package token

import (
	"net/http"
)

type SuccessResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    uint   `json:"expires_in,omitempty"`
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
