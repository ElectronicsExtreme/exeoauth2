package client

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/gorilla/mux"

	"exeoauth2/common"
	"exeoauth2/common/bearer"
	"exeoauth2/database/access-token"
	clientdb "exeoauth2/database/client"
	parent "exeoauth2/handler/clients"
	"exeoauth2/logger"
)

const (
	RequiredScope = "admin"
	SaltLength    = 64
)

var ()

type Input struct {
	GrantClientCredentialsString string          `json:"client_credentials_scope"`
	GrantClientCredentials       map[string]bool `json:"-"`
	Description                  string          `json:"description"`
}

func Handler(httpResp http.ResponseWriter, req *http.Request) {
	reqLogger, respLogger, errLogger, transLogger := logger.NewLoggers(req.URL.Path)
	resp := common.NewResponseWriter(httpResp, respLogger)

	err := reqLogger.WriteLog(req)
	if err != nil {
		errLogger.WriteLog(err)
		resp.WriteResults(common.ErrorStatusInternalServerError)
		return
	}

	// Basic request validation
	switch req.Method {
	case http.MethodGet:
		getHandler(resp, req, respLogger, errLogger, transLogger)
	case http.MethodPut:
		putHandler(resp, req, respLogger, errLogger, transLogger)
	case http.MethodDelete:
		deleteHandler(resp, req, respLogger, errLogger, transLogger)
	default:
		resp.WriteResults(common.ErrorStatusMethodNotAllowed)
	}
}

func getHandler(resp *common.ResponseWriter, req *http.Request, respLogger *logger.ResponseLogger, errLogger *logger.ErrorLogger, transLogger *logger.TransactionLogger) {
	// Validate Token
	token, err := bearer.ReadToken(req)
	if err != nil {
		resp.WriteResults(&bearer.ErrorTokenMissingMalform)
		return
	}

	_, err = accesstoken.Validate(token, RequiredScope, "")
	if err != nil {
		switch err := err.(type) {
		case *bearer.ErrorMessage:
			// copy error to a new variable to prevent modifying predefined variable
			temp := *err
			resp.WriteResults(&temp)
			return
		default:
			errLogger.WriteLog(err)
			resp.WriteResults(common.ErrorStatusInternalServerError)
			return
		}
	}

	// Validate input
	vars := mux.Vars(req)
	clientID := vars["client_id"]
	valErr := common.ValidateErrorResponse{}

	var client *clientdb.ClientInfo

	if clientID == "" {
		valErr.Add(parent.ErrorClientIDMissing)
	} else if !govalidator.IsAlphanumeric(clientID) {
		valErr.Add(parent.ErrorClientIDInvalid)
	} else if client, err = clientdb.ReadClient(clientID); client == nil {
		if err != nil {
			errLogger.WriteLog(err)
			resp.WriteResults(common.ErrorStatusInternalServerError)
			return
		} else {
			valErr.Add(parent.ErrorClientNotFound)
		}
	}

	if len(valErr.ErrorDescriptions) > 0 {
		resp.WriteResults(&valErr)
		return
	}

	err = resp.WriteResults(parent.NewClientResult(client))
	if err != nil {
		errLogger.WriteLog(err)
	}
}

func putHandler(resp *common.ResponseWriter, req *http.Request, respLogger *logger.ResponseLogger, errLogger *logger.ErrorLogger, transLogger *logger.TransactionLogger) {
	// Validate Token
	token, err := bearer.ReadToken(req)
	if err != nil {
		resp.WriteResults(&bearer.ErrorTokenMissingMalform)
		return
	}

	_, err = accesstoken.Validate(token, RequiredScope, "")
	if err != nil {
		switch err := err.(type) {
		case *bearer.ErrorMessage:
			// copy error to a new variable to prevent modifying predefined variable
			temp := *err
			resp.WriteResults(&temp)
			return
		default:
			errLogger.WriteLog(err)
			resp.WriteResults(common.ErrorStatusInternalServerError)
			return
		}
	}

	// Validate input
	raw, err := ioutil.ReadAll(req.Body)
	if err != nil {
		resp.WriteResults(&common.ErrorStatusInternalServerError)
		return
	}

	input := &Input{}
	err = json.Unmarshal(raw, input)
	if err != nil {
		resp.WriteResults(&common.ErrorStatusInternalServerError)
		return
	}
	input.GrantClientCredentials = common.StringToSet(input.GrantClientCredentialsString)

	vars := mux.Vars(req)
	clientID := vars["client_id"]
	valErr := common.ValidateErrorResponse{}

	if input.GrantClientCredentials != nil {
		if !clientdb.ValidateScope(input.GrantClientCredentials) {
			valErr.Add(parent.ErrorCliCreScopeInvalid)
		}
	}

	var client *clientdb.ClientInfo

	if clientID == "" {
		valErr.Add(parent.ErrorClientIDMissing)
	} else if !govalidator.IsAlphanumeric(clientID) {
		valErr.Add(parent.ErrorClientIDInvalid)
	} else if client, err = clientdb.ReadClient(clientID); client == nil {
		if err != nil {
			errLogger.WriteLog(err)
			resp.WriteResults(common.ErrorStatusInternalServerError)
			return
		} else {
			valErr.Add(parent.ErrorClientNotFound)
		}
	}

	if len(input.Description) > parent.DescriptionLenMax {
		valErr.Add(parent.ErrorDescriptionLengthInvalid)
	}

	if len(valErr.ErrorDescriptions) > 0 {
		resp.WriteResults(&valErr)
		return
	}

	client.Description = input.Description
	client.GrantClientCredentials = input.GrantClientCredentials
	client.UpdateDate = time.Now()

	err = clientdb.UpdateClient(client)
	if err != nil {
		errLogger.WriteLog(err)
		resp.WriteResults(common.ErrorStatusInternalServerError)
		return
	}

	err = resp.WriteResults(parent.NewClientResult(client))
	if err != nil {
		errLogger.WriteLog(err)
	}
}

func postHandler(resp *common.ResponseWriter, req *http.Request, respLogger *logger.ResponseLogger, errLogger *logger.ErrorLogger, transLogger *logger.TransactionLogger) {
}

func deleteHandler(resp *common.ResponseWriter, req *http.Request, respLogger *logger.ResponseLogger, errLogger *logger.ErrorLogger, transLogger *logger.TransactionLogger) {
	// Validate Token
	token, err := bearer.ReadToken(req)
	if err != nil {
		resp.WriteResults(&bearer.ErrorTokenMissingMalform)
		return
	}

	_, err = accesstoken.Validate(token, RequiredScope, "")
	if err != nil {
		switch err := err.(type) {
		case *bearer.ErrorMessage:
			// copy error to a new variable to prevent modifying predefined variable
			temp := *err
			resp.WriteResults(&temp)
			return
		default:
			errLogger.WriteLog(err)
			resp.WriteResults(common.ErrorStatusInternalServerError)
			return
		}
	}

	// Validate input
	vars := mux.Vars(req)
	clientID := vars["client_id"]
	valErr := common.ValidateErrorResponse{}

	var client *clientdb.ClientInfo

	if clientID == "" {
		valErr.Add(parent.ErrorClientIDMissing)
	} else if !govalidator.IsAlphanumeric(clientID) {
		valErr.Add(parent.ErrorClientIDInvalid)
	} else if client, err = clientdb.ReadClient(clientID); client == nil {
		if err != nil {
			errLogger.WriteLog(err)
			resp.WriteResults(common.ErrorStatusInternalServerError)
			return
		} else {
			valErr.Add(parent.ErrorClientNotFound)
		}
	}

	if len(valErr.ErrorDescriptions) > 0 {
		resp.WriteResults(&valErr)
		return
	}

	err = clientdb.DeleteClient(clientID)
	if err != nil {
		errLogger.WriteLog(err)
		resp.WriteResults(common.ErrorStatusInternalServerError)
		return
	}

	data := &parent.ClientResult{}

	err = resp.WriteResults(data)
	if err != nil {
		errLogger.WriteLog(err)
	}
}
