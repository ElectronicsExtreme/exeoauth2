package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/mux"
	"github.com/spf13/pflag"

	"exeoauth2/common/encrypt"
	"exeoauth2/config"
	clientdb "exeoauth2/database/client"

	clis "exeoauth2/handler/clients"
	cli "exeoauth2/handler/clients/client"
	clisecret "exeoauth2/handler/clients/client/secret"

	usrs "exeoauth2/handler/users"
	usr "exeoauth2/handler/users/user"
	usremail "exeoauth2/handler/users/user/email"
	usrpassword "exeoauth2/handler/users/user/password"

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

	r := mux.NewRouter()
	r.HandleFunc("/client/", clis.Handler)
	r.HandleFunc("/client/{client_id}", cli.Handler)
	r.HandleFunc("/client/{client_id}/secret", clisecret.Handler)

	r.HandleFunc("/user/", usrs.Handler)
	r.HandleFunc("/user/{username}", usr.Handler)
	r.HandleFunc("/user/{username}/password", usrpassword.Handler)
	r.HandleFunc("/user/{username}/email", usremail.Handler)

	r.HandleFunc(authtoken.PrefixPath, authtoken.Handler)
	r.HandleFunc(authvalidate.PrefixPath, authvalidate.Handler)

	http.Handle("/", r)

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
	salt, err := encrypt.GenerateSalt(clis.SaltLength)
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
