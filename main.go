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
	public := exehttp.NewServer(config.Default.Server.PublicListener.Address)
	public.Handle(token.PrefixPath, token.New())
	public.Handle(user.PrefixPath, user.New())
	public.Handle(changepassword.PrefixPath, changepassword.New())

	private := exehttp.NewServer(config.Default.Server.PrivateListener.Address)
	private.Handle(validate.PrefixPath, validate.New())

	servers := make([]exehttp.Server, 0, 0)
	servers = append(servers, public, private)
	exehttp.ListenAndServe(servers)
}
