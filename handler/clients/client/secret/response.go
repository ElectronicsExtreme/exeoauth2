package changesecret

import (
	"net/http"

	"exeoauth2/common"
)

var ErrorOldSecretIncorrect *common.ErrorResponse = &common.ErrorResponse{
	ErrorTag:         "invalid_request",
	ErrorDescription: "old secret is incorrect",
	HTTPStatus:       http.StatusBadRequest,
}
