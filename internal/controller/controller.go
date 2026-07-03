package controller

type FrontendLoginFor string

const (
	FrontendLoginForOIDC FrontendLoginFor = "oidc"
	FrontendLoginForApp  FrontendLoginFor = "app"
)

type SimpleResponse struct {
	Status  int    `json:"status"`
	Message string `json:"message,omitempty"`
}
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
