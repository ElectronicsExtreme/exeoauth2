package main

import (
	"github.com/ElectronicsExtreme/exehttp"

	"dev.corp.extreme.co.th/exeoauth2/config"
	"dev.corp.extreme.co.th/exeoauth2/handler/oauth2/handler/token"
	"dev.corp.extreme.co.th/exeoauth2/handler/oauth2/handler/validate"
	"dev.corp.extreme.co.th/exeoauth2/handler/user"
)

func main() {
	exehttp.StartLogger(config.Default.LogPath)

	// setup request handlers
	public := exehttp.NewServer(config.Default.Server.PublicListener.Address)
	public.Handle(token.PrefixPath, token.New())
	public.Handle(user.PrefixPath, user.New())

	private := exehttp.NewServer(config.Default.Server.PrivateListener.Address)
	private.Handle(validate.PrefixPath, validate.New())

	servers := make([]exehttp.Server, 0, 0)
	servers = append(servers, public, private)
	exehttp.ListenAndServe(servers)
}
