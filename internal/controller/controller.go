package controller

type FrontendLoginFor string

const (
	FrontendLoginForOIDC FrontendLoginFor = "oidc"
	FrontendLoginForApp  FrontendLoginFor = "app"
)

type UnauthorizedQuery struct {
	Username string `url:"username"`
	Resource string `url:"resource"`
	GroupErr bool   `url:"groupErr"`
	IP       string `url:"ip"`
}

type RedirectQuery struct {
	RedirectURI string           `url:"redirect_uri"`
	LoginFor    FrontendLoginFor `url:"login_for"`
}
