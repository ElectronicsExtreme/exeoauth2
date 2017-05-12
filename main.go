package main

import (
	"github.com/ElectronicsExtreme/exehttp"

	"exeoauth2/config"
	"exeoauth2/handler/change_password"
	"exeoauth2/handler/oauth2/handler/token"
	"exeoauth2/handler/oauth2/handler/validate"
	"exeoauth2/handler/user"
)

func main() {
	exehttp.StartLogger(config.Default.LogPath)

	// setup request handlers
	server := exehttp.NewServer(config.Default.Server.PublicListener.Address)
	server.Handle(token.PrefixPath, token.New())
	server.Handle(user.PrefixPath, user.New())
	server.Handle(changepassword.PrefixPath, changepassword.New())

	server.Handle(validate.PrefixPath, validate.New())

	servers := make([]exehttp.Server, 0, 0)
	servers = append(servers, server)
	exehttp.ListenAndServe(servers)
}
