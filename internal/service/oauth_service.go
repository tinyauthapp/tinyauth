package service

import (
	"context"
	"crypto/tls"
	"net/http"
	"time"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"golang.org/x/oauth2"
)

type OAuthUserinfoExtractor func(client *http.Client, ctx context.Context, url string) (*model.Claims, error)

type OAuthService struct {
	serviceCfg        model.OAuthServiceConfig
	config            *oauth2.Config
	ctx               context.Context
	userinfoExtractor OAuthUserinfoExtractor
	id                string
}

func NewOAuthService(config model.OAuthServiceConfig, id string, ctx context.Context) *OAuthService {
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: config.Insecure,
				MinVersion:         tls.VersionTLS12,
			},
		},
	}
	vctx := context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	return &OAuthService{
		serviceCfg: config,
		config: &oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			RedirectURL:  config.RedirectURL,
			Scopes:       config.Scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  config.AuthURL,
				TokenURL: config.TokenURL,
			},
		},
		ctx:               vctx,
		userinfoExtractor: defaultExtractor,
		id:                id,
	}
}

func (s *OAuthService) WithUserinfoExtractor(extractor OAuthUserinfoExtractor) *OAuthService {
	s.userinfoExtractor = extractor
	return s
}

func (s *OAuthService) Name() string {
	return s.serviceCfg.Name
}

func (s *OAuthService) ID() string {
	return s.id
}

func (s *OAuthService) NewRandom() string {
	// The generate verifier function just creates a random string,
	// so we can use it to generate a random state as well
	random := oauth2.GenerateVerifier()
	return random
}

func (s *OAuthService) GetAuthURL(state, verifier string) string {
	return s.config.AuthCodeURL(state, oauth2.AccessTypeOnline, oauth2.S256ChallengeOption(verifier))
}

func (s *OAuthService) GetToken(code string, verifier string) (*oauth2.Token, error) {
	return s.config.Exchange(s.ctx, code, oauth2.VerifierOption(verifier))
}

func (s *OAuthService) GetUserinfo(token *oauth2.Token) (*model.Claims, error) {
	client := oauth2.NewClient(s.ctx, oauth2.StaticTokenSource(token))
	return s.userinfoExtractor(client, s.ctx, s.serviceCfg.UserinfoURL)
}

func (s *OAuthService) GetConfig() model.OAuthServiceConfig {
	return s.serviceCfg
}

func (s *OAuthService) UpdateConfig(config model.OAuthServiceConfig) {
	s.serviceCfg = config
	s.config.ClientID = config.ClientID
	s.config.ClientSecret = config.ClientSecret
	s.config.Scopes = config.Scopes
	s.config.Endpoint.AuthURL = config.AuthURL
	s.config.Endpoint.TokenURL = config.TokenURL
	s.config.RedirectURL = config.RedirectURL
}
