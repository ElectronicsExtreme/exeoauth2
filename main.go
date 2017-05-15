package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/spf13/pflag"

	"exeoauth2/common/encrypt"
	"exeoauth2/config"
	clientdb "exeoauth2/database/client"

	cliaddscope "exeoauth2/handler/client/add-scope"
	clichangedesc "exeoauth2/handler/client/change-description"
	clichangesec "exeoauth2/handler/client/change-secret"
	clidelete "exeoauth2/handler/client/delete"
	cliregister "exeoauth2/handler/client/register"
	clirmscope "exeoauth2/handler/client/remove-scope"
	cliview "exeoauth2/handler/client/view"

	authtoken "exeoauth2/handler/oauth2/token"
	authvalidate "exeoauth2/handler/oauth2/validate"
)

const ()

var (
	Addr       = config.Config.Server.Address
	initialize bool
)

func init() {
	pflag.BoolVar(&initialize, "init", false, "Initialize admin account. Warning!! if client_id \"Admin\" is already exist, this will replace it.")
	pflag.Parse()
}

func addHandler() {
	http.HandleFunc(cliregister.PrefixPath, cliregister.Handler)
	http.HandleFunc(cliview.PrefixPath, cliview.Handler)
	http.HandleFunc(clichangedesc.PrefixPath, clichangedesc.Handler)
	http.HandleFunc(clichangesec.PrefixPath, clichangesec.Handler)
	http.HandleFunc(cliaddscope.PrefixPath, cliaddscope.Handler)
	http.HandleFunc(clirmscope.PrefixPath, clirmscope.Handler)
	http.HandleFunc(clidelete.PrefixPath, clidelete.Handler)

	http.HandleFunc(authtoken.PrefixPath, authtoken.Handler)
	http.HandleFunc(authvalidate.PrefixPath, authvalidate.Handler)
}

func main() {
	if initialize {
		initializeAdmin()
		fmt.Println("Initialize admin account successfully")
		return
	}
	termsig := make(chan os.Signal, 1)
	signal.Notify(termsig, os.Interrupt)

	server := http.Server{Addr: Addr}
	server.SetKeepAlivesEnabled(false)

	addHandler()

	go func() {
		log.Printf("starting requests listener on %v\n", Addr)
		log.Println(server.ListenAndServe())
	}()

	select {
	case <-termsig:
		log.Println("terminate signal received: stopping server")
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		err := server.Shutdown(ctx)
		if err != nil {
			log.Println("Server stopped with an error:", err)
		}
		log.Println("Server stopped gracefully")
	}
}

func initializeAdmin() {
	clientID := "Admin"
	clientSecret := "Password"
	salt, err := encrypt.GenerateSalt(cliregister.SaltLength)
	if err != nil {
		panic(err)
	}
	encSecret := encrypt.EncryptText1Way([]byte(clientSecret), salt)

	now := time.Now()

	newCli := &clientdb.ClientInfo{
		ClientID:               clientID,
		EncryptedClientSecret:  encSecret,
		GrantClientCredentials: map[string]bool{"admin": true},
		Description:            "Default admin account",
		Salt:                   salt,
		CreateDate:             now,
		UpdateDate:             now,
	}

	if err := clientdb.CreateClient(newCli); err != nil {
		if err.Error() == "duplicate client id" {
			err := clientdb.UpdateClient(newCli)
			if err != nil {
				panic(err)
			}
		} else {
			panic(err)
		}
	}
}
