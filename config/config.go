package config

import (
	"log"
	"runtime"
	"strings"

	"github.com/spf13/viper"
)

const (
	DefaultFile = "conf/main.xml"
)

var (
	Config *Root
)

func init() {
	_, currentPath, _, _ := runtime.Caller(1)
	projectPath := strings.SplitAfter(currentPath, "exeoauth2/")[0]

	viper.SetConfigType("yaml")
	viper.SetConfigName("main")
	viper.AddConfigPath("conf/")

	viper.AddConfigPath(projectPath + "conf/")

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalln(err)
	}

	Config = &Root{}
	if err := viper.Unmarshal(Config); err != nil {
		log.Fatalln(err)
	}
}
