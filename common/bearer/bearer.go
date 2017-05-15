/*
Bearer Token package implement "Authorization" header in http request and "WWW-Authenticate Response header in http response as in RFC6750.
*/
package bearer

import (
	"bytes"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

var (
	reg *regexp.Regexp
)

// Struct template for returning authentication error.
type ErrorMessage struct {
	HTTPStatus       int
	ErrorTag         string
	ErrorDescription string
}

func (e *ErrorMessage) Error() string {
	return e.ErrorDescription
}

func init() {
	subRegStr := `(\w*?)="([\w\s]*)"`
	reg = regexp.MustCompile(subRegStr)
}

// ReadToken read a bearer token from Authorization header and return as a string.
func ReadToken(req *http.Request) (string, error) {
	token := req.Header.Get("Authorization")
	if token == "" {
		return "", fmt.Errorf("Authorization header not exist")
	}
	matched, err := regexp.MatchString(`Bearer ([\w-.~+/]+=*)\z`, token)
	if err != nil {
		return "", err
	}
	if !matched {
		return "", fmt.Errorf("Authorization header malform")
	}
	token = token[7:]
	return token, nil
}

// WriteToken write a token into Authorization header into a request.
func WriteToken(req *http.Request, token string) {
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", token))
}

// ReadWWWAuthenticate read attribute from WWW-Authenticate header and put it to map.
func ReadWWWAuthenticate(resp *http.Response) (map[string]string, error) {
	challenge := resp.Header.Get("WWW-Authenticate")
	if challenge == "" {
		return nil, nil
	}
	matched, err := regexp.MatchString(`Bearer (\w*?="[\w\s]*",?)+\z`, challenge)
	if err != nil {
		return nil, err
	}
	if !matched {
		return nil, fmt.Errorf("WWW-Authenticate header malform")
	}
	authParams := strings.Split(challenge[7:], ",")
	attributes := make(map[string]string)
	for _, authParam := range authParams {
		res := reg.FindStringSubmatch(authParam)
		attributes[res[1]] = res[2]
	}
	return attributes, nil
}

// WriteWWWAuthenticate write attributes map into WWW-Authenticate header of response.
func WriteWWWAuthenticate(resp http.ResponseWriter, attributes map[string]string) {
	buffer := bytes.NewBufferString("Bearer ")
	for key, value := range attributes {
		buffer.WriteString(fmt.Sprintf("%v=\"%v\",", key, value))
	}
	resp.Header().Add("WWW-Authenticate", buffer.String()[:buffer.Len()-1])
}

// WriteError write WWW-Authenticate response with predefine attrubute for errors.
func WriteError(resp http.ResponseWriter, err ErrorMessage) {
	attributes := map[string]string{
		"error":             err.ErrorTag,
		"error_description": err.ErrorDescription,
	}
	WriteWWWAuthenticate(resp, attributes)
	if err.HTTPStatus != 0 {
		resp.WriteHeader(err.HTTPStatus)
	}
}
