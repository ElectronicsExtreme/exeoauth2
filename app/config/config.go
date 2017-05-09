package config

import (
	"encoding/xml"
	"log"
	"runtime"
	"strings"
)

const (
	DefaultFile = "conf/main.xml"
)

var (
	Default *Root
)

func init() {
	_, currentPath, _, _ := runtime.Caller(1)
	splitPath := strings.SplitAfter(currentPath, "exeoauth2/")

	var err error
	// load default configurations
	Default, err = Load(splitPath[0] + DefaultFile)
	if err != nil {
		log.Fatalln(err)
	}
}

type Root struct {
	XMLName  xml.Name `xml:"itemcode-db"`
	Server   *Server  `xml:"server"`
	Database Database `xml:"database"`
	LogPath  string   `xml:"log-path"`
}

type Server struct {
	PublicListener  *Listener `xml:"public-listener"`
	PrivateListener *Listener `xml:"private-listener"`
}

type Listener struct {
	Address string `xml:"address"`
	Tls     *Tls   `xml:"tls"`
}

type Tls struct {
	Enable             bool   `xml:"enable,attr"`
	CertificateFile    string `xml:"certificate-file"`
	CertificateKeyFile string `xml:"certificate-key-file"`
}

type Database struct {
	Redis Redis `xml:"redis"`
}

type Redis struct {
	Address  string `xml:"address"`
	Password string `xml:"password"`
	DB       int64  `xml:"db"`
}
