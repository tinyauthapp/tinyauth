package controller

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/tinyauthapp/tinyauth/internal/service"
)

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

func NewWellKnownController(oidc *service.OIDCService, router *gin.RouterGroup) *WellKnownController {
	controller := &WellKnownController{
		oidc: oidc,
	}

	router.GET("/.well-known/openid-configuration", controller.OpenIDConnectConfiguration)
	router.GET("/.well-known/jwks.json", controller.JWKS)

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
