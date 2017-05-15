package changesecret

import (
	"net/http"

	"exeoauth2/common"
)

var ErrorOldSecretIncorrect *common.ErrorResponse = &common.ErrorResponse{
	ErrorTag:         "Invalid_request",
	ErrorDescription: "old secret is incorrect",
	HTTPStatus:       http.StatusBadRequest,
}
