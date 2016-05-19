package main

import (
	"github.com/ElectronicsExtreme/exehttp"

	"dev.corp.extreme.co.th/exeoauth2/config"
	//"dev.corp.extreme.co.th/exeoauth2/handler/oauth2/handler/activate-client"
	//"dev.corp.extreme.co.th/exeoauth2/handler/oauth2/handler/activate-email"
	//"dev.corp.extreme.co.th/exeoauth2/handler/oauth2/handler/change-password"
	//"dev.corp.extreme.co.th/exeoauth2/handler/oauth2/handler/delete"
	//"dev.corp.extreme.co.th/exeoauth2/handler/oauth2/handler/drago-login"
	//"dev.corp.extreme.co.th/exeoauth2/handler/oauth2/handler/force-change-password"
	//"dev.corp.extreme.co.th/exeoauth2/handler/oauth2/handler/register"
	//"dev.corp.extreme.co.th/exeoauth2/handler/oauth2/handler/register-client"
	"dev.corp.extreme.co.th/exeoauth2/handler/oauth2/handler/token"
	"dev.corp.extreme.co.th/exeoauth2/handler/oauth2/handler/validate"
	//"dev.corp.extreme.co.th/exeoauth2/handler/oauth2/handler/view-activate-token"
	//"dev.corp.extreme.co.th/exeoauth2/handler/oauth2/handler/view-activated-clients"
)

func main() {
	exehttp.StartLogger(config.Default.LogPath)

	// setup request handlers
	public := exehttp.NewServer(config.Default.Server.PublicListener.Address)
	public.Handle(token.PrefixPath, token.New())
	//public.Handle(changepassword.PrefixPath, changepassword.New())
	//public.Handle(activateemail.PrefixPath, activateemail.New())
	//public.Handle(activateclient.PrefixPath, activateclient.New())
	//public.Handle(registerclient.PrefixPath, registerclient.New())
	//public.Handle(viewactivatedclients.PrefixPath, viewactivatedclients.New())
	//public.Handle(viewactivatetoken.PrefixPath, viewactivatetoken.New())

	private := exehttp.NewServer(config.Default.Server.PrivateListener.Address)
	private.Handle(validate.PrefixPath, validate.New())
	//private.Handle(register.PrefixPath, register.New())
	//private.Handle(delete_account.PrefixPath, delete_account.New())
	//private.Handle(fchangepassword.PrefixPath, fchangepassword.New())

	servers := make([]exehttp.Server, 0, 0)
	servers = append(servers, public, private)
	exehttp.ListenAndServe(servers)
}
