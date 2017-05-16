package changepassword

import (
	"net/http"

	"exeoauth2/common"
)

var ErrorOldPasswordIncorrect *common.ErrorResponse = &common.ErrorResponse{
	ErrorTag:         "invalid_request",
	ErrorDescription: "old password is incorrect",
	HTTPStatus:       http.StatusBadRequest,
}
