package logger

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	common "exeoauth2/common/strings"
	"exeoauth2/config"
)

const ()

var (
	errorPath          = config.Config.LogPath.Error
	requestPath        = config.Config.LogPath.Request
	transactionPath    = config.Config.LogPath.Transaction
	errorChannel       chan string
	requestChannel     chan string
	transactionChannel chan string
	LogWaitGroup       sync.WaitGroup
)

func init() {
	errorChannel = make(chan string)
	requestChannel = make(chan string)
	transactionChannel = make(chan string)
	go startLogger(errorChannel, errorPath)
	go startLogger(requestChannel, requestPath)
	go startLogger(transactionChannel, transactionPath)
}

type Logger struct {
	API         string
	Path        string
	QueryString string
	RefCode     string
	Body        string
	HTTPStatus  int
	Method      string
	ReqURL      string
}

func (self *Logger) String() string {
	_, path, lineNumber, _ := runtime.Caller(2)
	paths := strings.Split(path, "/")
	filename := fmt.Sprintf("%v(%v)", paths[len(paths)-1], lineNumber)
	logString := fmt.Sprintf("RefCode:%s API:%s File:%s", self.RefCode, self.API, filename)
	if self.Path != "" {
		logString += " Path:" + self.Path
	}
	if self.QueryString != "" {
		logString += " QueryString:" + self.QueryString
	}
	if self.ReqURL != "" {
		logString += " ReqURL:" + self.ReqURL
	}
	if self.Method != "" {
		logString += " Method:" + self.Method
	}
	if self.HTTPStatus != 0 {
		logString += fmt.Sprintf(" HTTPStatus:%v", self.HTTPStatus)
	}
	logString += " Body:" + self.Body
	return logString
}

func NewLoggers(prefixPath string) (*RequestLogger, *ResponseLogger, *ErrorLogger, *TransactionLogger) {
	refCode := common.RandomString(6)
	requestLogger := &RequestLogger{
		logger: Logger{
			API:     prefixPath,
			RefCode: refCode,
		},
	}
	responseLogger := &ResponseLogger{
		Logger: Logger{
			API:     prefixPath,
			RefCode: refCode,
		},
	}
	errorLogger := &ErrorLogger{
		logger: Logger{
			API:     prefixPath,
			RefCode: refCode,
		},
	}
	transLogger := &TransactionLogger{
		logger: Logger{
			API:     prefixPath,
			RefCode: refCode,
		},
	}
	return requestLogger, responseLogger, errorLogger, transLogger
}

type RequestLogger struct {
	logger Logger
}

func (self *RequestLogger) WriteLog(req *http.Request) error {
	self.logger.Method = req.Method
	data, err := dumpRequestBody(req)
	if err != nil {
		return err
	}
	self.logger.Body = string(data)
	WriteRequest(self.logger.String())
	return nil
}

type ResponseLogger struct {
	Logger Logger
}

func (self *ResponseLogger) WriteLog() {
	WriteRequest(self.Logger.String())
}

type ErrorLogger struct {
	logger Logger
}

func (self *ErrorLogger) WriteLog(err error) {
	self.logger.Body = err.Error()
	WriteError(self.logger.String())
}

type TransactionLogger struct {
	logger Logger
}

func (self *TransactionLogger) WriteRequest(req *http.Request) error {
	if req.URL.Path == "" {
		self.logger.ReqURL = req.URL.Host
	} else {
		self.logger.ReqURL = fmt.Sprintf("%v/%v", req.URL.Host, req.URL.Path)
	}
	self.logger.Method = req.Method
	data, err := dumpRequestBody(req)
	if err != nil {
		return err
	}
	self.logger.Body = string(data)
	WriteTransaction(self.logger.String())
	return nil
}

func (self *TransactionLogger) WriteResponse(resp *http.Response) error {
	self.logger.HTTPStatus = resp.StatusCode
	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return err
	}
	resp.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	self.logger.Body = string(body)
	WriteTransaction(self.logger.String())
	return nil
}

func WriteError(msg string) {
	LogWaitGroup.Add(1)
	errorChannel <- msg
}
func WriteRequest(msg string) {
	LogWaitGroup.Add(1)
	requestChannel <- msg
}
func WriteTransaction(msg string) {
	LogWaitGroup.Add(1)
	transactionChannel <- msg
}

func startLogger(ch chan string, logPath string) {
	err := createDirIfNotExist(logPath)
	if err != nil {
		log.Println(err)
		return
	}
	for {
		func() {
			logMsg := <-ch
			defer LogWaitGroup.Done()
			currentTime := time.Now()
			filename := fmt.Sprintf("%v/%04d-%02d.log", logPath, currentTime.Year(), currentTime.Month())
			outfile, err := os.OpenFile(filename, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
			if err != nil {
				log.Println("can't open file", filename)
				log.Println(logMsg)
				return
			}
			defer outfile.Close()
			logger := log.New(outfile, "", log.LstdFlags)
			logger.Println(logMsg)
		}()
	}
}

func createDirIfNotExist(path string) error {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			err := os.MkdirAll(path, 0755)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}
	return nil
}

func dumpRequestBody(req *http.Request) ([]byte, error) {
	body, err := httputil.DumpRequest(req, true)
	if err != nil {
		return nil, err
	}
	lastIndex := bytes.LastIndex(body, []byte("\r\n\r\n")) + 4
	return body[lastIndex:], nil
}
