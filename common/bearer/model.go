package bearer

import "net/http"

var ErrorTokenMissingMalform = ErrorMessage{
	ErrorTag:         "invalid_request",
	ErrorDescription: "The access token is missing or malform",
	HTTPStatus:       http.StatusUnauthorized,
}
