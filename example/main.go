// Copyright 2014 beego authors
// Copyright 2015 tango authors
//
// Licensed under the Apache License, Version 2.0 (the "License"): you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.
//
// Maintain by https://github.com/slene

package main

import (
	"fmt"

	"github.com/go-xorm/xorm"
	"github.com/lunny/config"
	"github.com/lunny/log"
	"github.com/lunny/tango"
	"github.com/tango-contrib/events"
	"github.com/tango-contrib/renders"
	"github.com/tango-contrib/session"

	"github.com/go-tango/social-auth"
	"github.com/go-tango/social-auth/apps"

	_ "github.com/go-sql-driver/mysql"
)

func IsUserLogin(session *session.Session) (int, bool) {
	if id, ok := session.Get("login_user").(int); ok && id == 1 {
		return id, true
	}
	return 0, false
}

func Logout(session *session.Session) {
	session.Del("login_user")
	types := social.GetAllTypes()
	for _, t := range types {
		session.Del(t.NameLower())
	}
}

func SetInfoToSession(session *session.Session, userSocial *social.UserSocial) {
	session.Set(userSocial.Type.NameLower(),
		fmt.Sprintf("Identify: %s, AccessToken: %s", userSocial.Identify, userSocial.Data.AccessToken))
}

type HandleRedirect struct {
	session.Session
	tango.Ctx
}

func (h *HandleRedirect) Get() {
	redirect, err := SocialAuth.OAuthRedirect(h.Context, &h.Session)
	if err != nil {
		h.Error("SocialAuth.handleRedirect", err)
	}

	if len(redirect) > 0 {
		h.Redirect(redirect, 302)
	}
}

type HandleAccess struct {
	session.Session
	tango.Ctx
}

func (h *HandleAccess) Get() {
	redirect, userSocial, err := SocialAuth.OAuthAccess(h.Context, &h.Session)
	if err != nil {
		h.Error("SocialAuth.handleAccess", err)
	}

	if userSocial != nil {
		SetInfoToSession(&h.Session, userSocial)
	}

	if len(redirect) > 0 {
		h.Redirect(redirect, 302)
	}
}

type MainRouter struct {
	tango.Ctx
	renders.Renderer
	session.Session
	Data     renders.T
	TplNames string
}

func (this *MainRouter) Before() {
	this.Data = make(renders.T)
}

func (this *MainRouter) After() {
	if !this.Written() && this.TplNames != "" {
		err := this.Render(this.TplNames, this.Data)
		if err != nil {
			this.Result = err
		}
	}
}

func (this *MainRouter) GetString(key string) string {
	return this.Req().FormValue(key)
}

func (this *MainRouter) Home() {
	this.Redirect("/login", 302)
}

func (this *MainRouter) Login() {
	this.TplNames = "index.tpl"

	_, isLogin := IsUserLogin(&this.Session)

	switch this.GetString("flag") {
	case "logout":
		Logout(&this.Session)
		this.Redirect("/login", 302)
		return
	case "connect_success":
		this.Data["Msg"] = "Connect Success"
	case "connect_failed":
		this.Data["Msg"] = "Connect Failed"
	}

	types := social.GetAllTypes()
	this.Data["IsLogin"] = isLogin
	this.Data["Types"] = types

	for _, t := range types {
		this.Data[t.NameLower()] = this.Session.Get(t.NameLower())
	}
}

func (this *MainRouter) Connect() {
	this.TplNames = "index.tpl"

	st, ok := SocialAuth.ReadyConnect(this.Context, &this.Session)
	if !ok {
		this.Redirect("/login", 302)
		return
	}

	// Your app need custom connect behavior
	// example just direct connect and login
	loginRedirect, userSocial, err := SocialAuth.ConnectAndLogin(this.Context, &this.Session, st, 1)
	if err != nil {
		// may be has error
		log.Error(err)
	} else {
		SetInfoToSession(&this.Session, userSocial)
	}

	this.Redirect(loginRedirect, 302)
}

type socialAuther struct {
}

func (p *socialAuther) IsUserLogin(ctx *tango.Context, session *session.Session) (int, bool) {
	return IsUserLogin(session)
}

func (p *socialAuther) LoginUser(ctx *tango.Context, session *session.Session, uid int) (string, error) {
	// fake login the user
	if uid == 1 {
		session.Set("login_user", 1)
	}
	return "/login", nil
}

var SocialAuth *social.SocialAuth

func initialize() {
	cfg, err := config.Load("./conf/app.conf")
	if err != nil {
		panic(err)
	}

	orm, err := xorm.NewEngine("mysql", cfg.Get("orm_source"))
	if err != nil {
		panic(err)
	}

	social.SetORM(orm)

	// OAuth
	var clientId, secret string

	appURL := cfg.Get("social_auth_url")
	if len(appURL) > 0 {
		social.DefaultAppUrl = appURL
	}

	clientId = cfg.Get("github_client_id")
	secret = cfg.Get("github_client_secret")
	err = social.RegisterProvider(apps.NewGithub(clientId, secret))
	if err != nil {
		log.Error(err)
	} else {
		log.Info("registered github")
	}

	clientId = cfg.Get("google_client_id")
	secret = cfg.Get("google_client_secret")
	err = social.RegisterProvider(apps.NewGoogle(clientId, secret))
	if err != nil {
		log.Error(err)
	}

	clientId = cfg.Get("weibo_client_id")
	secret = cfg.Get("weibo_client_secret")
	err = social.RegisterProvider(apps.NewWeibo(clientId, secret))
	if err != nil {
		log.Error(err)
	}

	clientId = cfg.Get("qq_client_id")
	secret = cfg.Get("qq_client_secret")
	err = social.RegisterProvider(apps.NewQQ(clientId, secret))
	if err != nil {
		log.Error(err)
	}

	clientId = cfg.Get("dropbox_client_id")
	secret = cfg.Get("dropbox_client_secret")
	err = social.RegisterProvider(apps.NewDropbox(clientId, secret))
	if err != nil {
		log.Error(err)
	}

	clientId = cfg.Get("facebook_client_id")
	secret = cfg.Get("facebook_client_secret")
	err = social.RegisterProvider(apps.NewFacebook(clientId, secret))
	if err != nil {
		log.Error(err)
	}

	// global create a SocialAuth and auto set filter
	SocialAuth = social.NewSocial("/login/", new(socialAuther))

	// set the DefaultTransport of social-auth
	//
	// social.DefaultTransport = &http.Transport{
	// 	Proxy: func(req *http.Request) (*url.URL, error) {
	// 		u, _ := url.ParseRequestURI("http://127.0.0.1:8118")
	// 		return u, nil
	// 	},
	// 	DisableKeepAlives: true,
	// }
}

func main() {
	initialize()

	t := tango.Classic()
	sess := session.New()
	t.Use(sess,
		renders.New(renders.Options{
			Reload:     true,
			Directory:  "./views",
			Extensions: []string{".tpl"},
		}),
		events.Events(),
	)
	mainR := new(MainRouter)
	t.Route("GET:Home", "/", mainR)
	t.Route("GET:Login", "/login", mainR)
	t.Route("GET:Connect", "/register/connect", mainR)
	t.Get("/login/:splat", new(HandleRedirect))
	t.Get("/login/:splat/access", new(HandleAccess))
	t.Run()
}
