package controller

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"go.uber.org/dig"
)

const OpenIDConnectRel = "http://openid.net/specs/connect/1.0/issuer"

type WebfingerResponseLink struct {
	Rel  string `json:"rel,omitempty"`
	Href string `json:"href"`
}

type WebfingerResponse struct {
	Subject string                  `json:"subject"`
	Links   []WebfingerResponseLink `json:"links"`
}

type OpenIDConnectConfiguration struct {
	Issuer                                 string   `json:"issuer"`
	AuthorizationEndpoint                  string   `json:"authorization_endpoint"`
	TokenEndpoint                          string   `json:"token_endpoint"`
	UserinfoEndpoint                       string   `json:"userinfo_endpoint"`
	JwksUri                                string   `json:"jwks_uri"`
	ScopesSupported                        []string `json:"scopes_supported"`
	ResponseTypesSupported                 []string `json:"response_types_supported"`
	GrantTypesSupported                    []string `json:"grant_types_supported"`
	SubjectTypesSupported                  []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported       []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported      []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                        []string `json:"claims_supported"`
	ServiceDocumentation                   string   `json:"service_documentation"`
	RequestParameterSupported              bool     `json:"request_parameter_supported"`
	RequestObjectSigningAlgValuesSupported []string `json:"request_object_signing_alg_values_supported"`
}

type WellKnownController struct {
	oidc *service.OIDCService
}

type WellKnownControllerInput struct {
	dig.In

	OIDCService *service.OIDCService
	RouterGroup *gin.RouterGroup `name:"mainRouterGroup"`
}

func NewWellKnownController(i WellKnownControllerInput) *WellKnownController {
	controller := &WellKnownController{
		oidc: i.OIDCService,
	}

	i.RouterGroup.GET("/.well-known/openid-configuration", controller.OpenIDConnectConfiguration)
	i.RouterGroup.GET("/.well-known/jwks.json", controller.JWKS)
	i.RouterGroup.GET("/.well-known/webfinger", controller.WebFinger)

	return controller
}

func (controller *WellKnownController) OpenIDConnectConfiguration(c *gin.Context) {
	if controller.oidc == nil {
		c.JSON(500, gin.H{
			"status":  500,
			"message": "OIDC service not configured",
		})
		return
	}

	issuer := controller.oidc.GetIssuer()
	c.JSON(200, OpenIDConnectConfiguration{
		Issuer:                                 issuer,
		AuthorizationEndpoint:                  fmt.Sprintf("%s/authorize", issuer),
		TokenEndpoint:                          fmt.Sprintf("%s/api/oidc/token", issuer),
		UserinfoEndpoint:                       fmt.Sprintf("%s/api/oidc/userinfo", issuer),
		JwksUri:                                fmt.Sprintf("%s/.well-known/jwks.json", issuer),
		ScopesSupported:                        service.SupportedScopes,
		ResponseTypesSupported:                 service.SupportedResponseTypes,
		GrantTypesSupported:                    service.SupportedGrantTypes,
		SubjectTypesSupported:                  []string{"pairwise"},
		IDTokenSigningAlgValuesSupported:       []string{"RS256"},
		TokenEndpointAuthMethodsSupported:      []string{"client_secret_basic", "client_secret_post"},
		ClaimsSupported:                        []string{"sub", "updated_at", "name", "preferred_username", "email", "email_verified", "groups", "phone_number", "phone_number_verified", "address", "given_name", "family_name", "middle_name", "nickname", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale"},
		ServiceDocumentation:                   "https://tinyauth.app/docs/guides/oidc",
		RequestParameterSupported:              true,
		RequestObjectSigningAlgValuesSupported: []string{"none"},
	})
}

func (controller *WellKnownController) JWKS(c *gin.Context) {
	if controller.oidc == nil {
		c.JSON(500, gin.H{
			"status":  500,
			"message": "OIDC service not configured",
		})
		return
	}

	jwks, err := controller.oidc.GetJWK()

	if err != nil {
		c.JSON(500, gin.H{
			"status":  500,
			"message": "failed to get JWK",
		})
		return
	}

	c.Header("content-type", "application/json")

	c.Writer.WriteString(`{"keys":[`)
	c.Writer.Write(jwks)
	c.Writer.WriteString(`]}`)

	c.Status(http.StatusOK)
}

func (controller *WellKnownController) WebFinger(c *gin.Context) {
	c.Header("Content-Type", "application/jrd+json")
	c.Header("Access-Control-Allow-Origin", "*")

	resource := c.Query("resource")

	if !controller.validateWebFingerResource(resource) {
		c.JSON(400, gin.H{
			"status":  400,
			"message": "invalid resource",
		})
		return
	}

	res := WebfingerResponse{
		Subject: resource,
		Links:   []WebfingerResponseLink{},
	}

	rel := c.Request.URL.Query()["rel"]

	if controller.oidc != nil && (len(rel) == 0 || slices.Contains(rel, OpenIDConnectRel)) {
		res.Links = append(res.Links, WebfingerResponseLink{Rel: OpenIDConnectRel, Href: controller.oidc.GetIssuer()})
	}

	c.JSON(200, res)
}

func (controller *WellKnownController) validateWebFingerResource(resource string) bool {
	prefix, suffix, found := strings.Cut(resource, ":")

	if !found {
		return false
	}

	switch prefix {
	case "acct":
		if strings.Count(suffix, "@") != 1 {
			return false
		}
		username, domain, found := strings.Cut(suffix, "@")
		if !found || username == "" || domain == "" {
			return false
		}
	case "https", "http":
		u, err := url.Parse(resource)
		if err != nil {
			return false
		}
		if u.Host == "" {
			return false
		}
	default:
		return false
	}

	return true
}
