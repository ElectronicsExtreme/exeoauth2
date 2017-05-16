package changeemail

import (
	"net/http"

	"exeoauth2/common"
)

var ErrorPasswordIncorrect *common.ErrorResponse = &common.ErrorResponse{
	ErrorTag:         "invalid_request",
	ErrorDescription: "password is incorrect",
	HTTPStatus:       http.StatusBadRequest,
}
