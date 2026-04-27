package controller

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/tinyauthapp/tinyauth/internal/config"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/tinyauth/internal/utils/tlog"

	"github.com/gin-gonic/gin"
	"github.com/google/go-querystring/query"
)

type AuthModuleType int

const (
	AuthRequest AuthModuleType = iota
	ExtAuthz
	ForwardAuth
)

type ProxyType int

const (
	Traefik ProxyType = iota
	Caddy
	Envoy
	Nginx
)

var BrowserUserAgentRegex = regexp.MustCompile("Chrome|Gecko|AppleWebKit|Opera|Edge")

type Proxy struct {
	Proxy string `uri:"proxy" binding:"required"`
}

type ProxyContext struct {
	Host      string
	Proto     string
	Path      string
	Method    string
	Type      AuthModuleType
	IsBrowser bool
	ProxyType ProxyType
}

type ProxyControllerConfig struct {
	AppURL string
}

type ProxyController struct {
	config ProxyControllerConfig
	router *gin.RouterGroup
	acls   *service.AccessControlsService
	auth   *service.AuthService
}

func NewProxyController(config ProxyControllerConfig, router *gin.RouterGroup, acls *service.AccessControlsService, auth *service.AuthService) *ProxyController {
	return &ProxyController{
		config: config,
		router: router,
		acls:   acls,
		auth:   auth,
	}
}

func (controller *ProxyController) SetupRoutes() {
	proxyGroup := controller.router.Group("/auth")
	proxyGroup.Any("/:proxy", controller.proxyHandler)
}

func (controller *ProxyController) proxyHandler(c *gin.Context) {
	// Load proxy context based on the request type
	proxyCtx, err := controller.getProxyContext(c)

	if err != nil {
		tlog.App.Warn().Err(err).Msg("Failed to get proxy context")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad request",
		})
		return
	}

	tlog.App.Trace().Interface("ctx", proxyCtx).Msg("Got proxy context")

	// Get acls
	acls, err := controller.acls.GetAccessControls(proxyCtx.Host)

	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to get access controls for resource")
		controller.handleError(c, proxyCtx)
		return
	}

	tlog.App.Trace().Interface("acls", acls).Msg("ACLs for resource")

	clientIP := c.ClientIP()

	if controller.auth.IsBypassedIP(acls.IP, clientIP) {
		controller.setHeaders(c, acls)
		c.JSON(200, gin.H{
			"status":  200,
			"message": "Authenticated",
		})
		return
	}

	authEnabled, err := controller.auth.IsAuthEnabled(proxyCtx.Path, acls.Path)

	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to check if auth is enabled for resource")
		controller.handleError(c, proxyCtx)
		return
	}

	if !authEnabled {
		tlog.App.Debug().Msg("Authentication disabled for resource, allowing access")
		controller.setHeaders(c, acls)
		c.JSON(200, gin.H{
			"status":  200,
			"message": "Authenticated",
		})
		return
	}

	if !controller.auth.CheckIP(acls.IP, clientIP) {
		queries, err := query.Values(config.UnauthorizedQuery{
			Resource: strings.Split(proxyCtx.Host, ".")[0],
			IP:       clientIP,
		})

		if err != nil {
			tlog.App.Error().Err(err).Msg("Failed to encode unauthorized query")
			controller.handleError(c, proxyCtx)
			return
		}

		redirectURL := fmt.Sprintf("%s/unauthorized?%s", controller.config.AppURL, queries.Encode())

		if !controller.useBrowserResponse(proxyCtx) {
			c.Header("x-tinyauth-location", redirectURL)
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			return
		}

		c.Redirect(http.StatusTemporaryRedirect, redirectURL)
		return
	}

	var userContext config.UserContext

	context, err := utils.GetContext(c)

	if err != nil {
		tlog.App.Debug().Msg("No user context found in request, treating as not logged in")
		userContext = config.UserContext{
			IsLoggedIn: false,
		}
	} else {
		userContext = context
	}

	tlog.App.Trace().Interface("context", userContext).Msg("User context from request")

	if userContext.IsLoggedIn {
		userAllowed := controller.auth.IsUserAllowed(c, userContext, acls)

		if !userAllowed {
			tlog.App.Warn().Str("user", userContext.Username).Str("resource", strings.Split(proxyCtx.Host, ".")[0]).Msg("User not allowed to access resource")

			queries, err := query.Values(config.UnauthorizedQuery{
				Resource: strings.Split(proxyCtx.Host, ".")[0],
			})

			if err != nil {
				tlog.App.Error().Err(err).Msg("Failed to encode unauthorized query")
				controller.handleError(c, proxyCtx)
				return
			}

			if userContext.OAuth {
				queries.Set("username", userContext.Email)
			} else {
				queries.Set("username", userContext.Username)
			}

			redirectURL := fmt.Sprintf("%s/unauthorized?%s", controller.config.AppURL, queries.Encode())

			if !controller.useBrowserResponse(proxyCtx) {
				c.Header("x-tinyauth-location", redirectURL)
				c.JSON(403, gin.H{
					"status":  403,
					"message": "Forbidden",
				})
				return
			}

			c.Redirect(http.StatusTemporaryRedirect, redirectURL)
			return
		}

		if userContext.OAuth || userContext.Provider == "ldap" {
			var groupOK bool

			if userContext.OAuth {
				groupOK = controller.auth.IsInOAuthGroup(c, userContext, acls.OAuth.Groups)
			} else {
				groupOK = controller.auth.IsInLdapGroup(c, userContext, acls.LDAP.Groups)
			}

			if !groupOK {
				tlog.App.Warn().Str("user", userContext.Username).Str("resource", strings.Split(proxyCtx.Host, ".")[0]).Msg("User groups do not match resource requirements")

				queries, err := query.Values(config.UnauthorizedQuery{
					Resource: strings.Split(proxyCtx.Host, ".")[0],
					GroupErr: true,
				})

				if err != nil {
					tlog.App.Error().Err(err).Msg("Failed to encode unauthorized query")
					controller.handleError(c, proxyCtx)
					return
				}

				if userContext.OAuth {
					queries.Set("username", userContext.Email)
				} else {
					queries.Set("username", userContext.Username)
				}

				redirectURL := fmt.Sprintf("%s/unauthorized?%s", controller.config.AppURL, queries.Encode())

				if !controller.useBrowserResponse(proxyCtx) {
					c.Header("x-tinyauth-location", redirectURL)
					c.JSON(403, gin.H{
						"status":  403,
						"message": "Forbidden",
					})
					return
				}

				c.Redirect(http.StatusTemporaryRedirect, redirectURL)
				return
			}
		}

		c.Header("Remote-User", utils.SanitizeHeader(userContext.Username))
		c.Header("Remote-Name", utils.SanitizeHeader(userContext.Name))
		c.Header("Remote-Email", utils.SanitizeHeader(userContext.Email))

		if userContext.Provider == "ldap" {
			c.Header("Remote-Groups", utils.SanitizeHeader(userContext.LdapGroups))
		} else if userContext.Provider != "local" {
			c.Header("Remote-Groups", utils.SanitizeHeader(userContext.OAuthGroups))
		}

		c.Header("Remote-Sub", utils.SanitizeHeader(userContext.OAuthSub))

		controller.setHeaders(c, acls)

		c.JSON(200, gin.H{
			"status":  200,
			"message": "Authenticated",
		})
		return
	}

	queries, err := query.Values(config.RedirectQuery{
		RedirectURI: fmt.Sprintf("%s://%s%s", proxyCtx.Proto, proxyCtx.Host, proxyCtx.Path),
	})

	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to encode redirect URI query")
		controller.handleError(c, proxyCtx)
		return
	}

	redirectURL := fmt.Sprintf("%s/login?%s", controller.config.AppURL, queries.Encode())

	if !controller.useBrowserResponse(proxyCtx) {
		c.Header("x-tinyauth-location", redirectURL)
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	c.Redirect(http.StatusTemporaryRedirect, redirectURL)
}

func (controller *ProxyController) setHeaders(c *gin.Context, acls config.App) {
	c.Header("Authorization", c.Request.Header.Get("Authorization"))

	headers := utils.ParseHeaders(acls.Response.Headers)

	for key, value := range headers {
		tlog.App.Debug().Str("header", key).Msg("Setting header")
		c.Header(key, value)
	}

	basicPassword := utils.GetSecret(acls.Response.BasicAuth.Password, acls.Response.BasicAuth.PasswordFile)

	if acls.Response.BasicAuth.Username != "" && basicPassword != "" {
		tlog.App.Debug().Str("username", acls.Response.BasicAuth.Username).Msg("Setting basic auth header")
		c.Header("Authorization", fmt.Sprintf("Basic %s", utils.GetBasicAuth(acls.Response.BasicAuth.Username, basicPassword)))
	}
}

func (controller *ProxyController) handleError(c *gin.Context, proxyCtx ProxyContext) {
	redirectURL := fmt.Sprintf("%s/error", controller.config.AppURL)

	if !controller.useBrowserResponse(proxyCtx) {
		c.Header("x-tinyauth-location", redirectURL)
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	c.Redirect(http.StatusTemporaryRedirect, redirectURL)
}

func (controller *ProxyController) getHeader(c *gin.Context, header string) (string, bool) {
	val := c.Request.Header.Get(header)
	return val, strings.TrimSpace(val) != ""
}

func (controller *ProxyController) useBrowserResponse(proxyCtx ProxyContext) bool {
	// If it's nginx we need non-browser response
	if proxyCtx.ProxyType == Nginx {
		return false
	}

	// For other proxies (traefik/caddy/envoy) we can check
	// the user agent to determine if it's a browser or not
	if proxyCtx.IsBrowser {
		return true
	}

	return false
}

func (controller *ProxyController) getProxyType(proxy string) (ProxyType, error) {
	switch proxy {
	case "traefik":
		return Traefik, nil
	case "caddy":
		return Caddy, nil
	case "envoy":
		return Envoy, nil
	case "nginx":
		return Nginx, nil
	default:
		return 0, fmt.Errorf("unsupported proxy type: %v", proxy)
	}
}

// Code below is inspired from https://github.com/authelia/authelia/blob/master/internal/handlers/handler_authz.go
// and thus it may be subject to Apache 2.0 License
func (controller *ProxyController) getForwardAuthContext(c *gin.Context) (ProxyContext, error) {
	host, ok := controller.getHeader(c, "x-forwarded-host")

	if !ok {
		return ProxyContext{}, errors.New("x-forwarded-host not found")
	}

	uri, ok := controller.getHeader(c, "x-forwarded-uri")

	if !ok {
		return ProxyContext{}, errors.New("x-forwarded-uri not found")
	}

	proto, ok := controller.getHeader(c, "x-forwarded-proto")

	if !ok {
		return ProxyContext{}, errors.New("x-forwarded-proto not found")
	}

	// Normally we should only allow GET for forward auth but since it's a fallback
	// for envoy we should allow everything, not a big deal
	method := c.Request.Method

	return ProxyContext{
		Host:   host,
		Proto:  proto,
		Path:   uri,
		Method: method,
		Type:   ForwardAuth,
	}, nil
}

func (controller *ProxyController) getAuthRequestContext(c *gin.Context) (ProxyContext, error) {
	xOriginalUrl, ok := controller.getHeader(c, "x-original-url")

	if !ok {
		return ProxyContext{}, errors.New("x-original-url not found")
	}

	url, err := url.Parse(xOriginalUrl)

	if err != nil {
		return ProxyContext{}, err
	}

	host := url.Host

	if strings.TrimSpace(host) == "" {
		return ProxyContext{}, errors.New("host not found")
	}

	proto := url.Scheme

	if strings.TrimSpace(proto) == "" {
		return ProxyContext{}, errors.New("proto not found")
	}

	path := url.Path
	method := c.Request.Method

	return ProxyContext{
		Host:   host,
		Proto:  proto,
		Path:   path,
		Method: method,
		Type:   AuthRequest,
	}, nil
}

func (controller *ProxyController) getExtAuthzContext(c *gin.Context) (ProxyContext, error) {
	// We hope for the someone to set the x-forwarded-proto header
	proto, ok := controller.getHeader(c, "x-forwarded-proto")

	if !ok {
		return ProxyContext{}, errors.New("x-forwarded-proto not found")
	}

	// It sets the host to the original host, not the forwarded host
	host := c.Request.Host

	if strings.TrimSpace(host) == "" {
		return ProxyContext{}, errors.New("host not found")
	}

	// We get the path from the query string
	path := c.Query("path")

	// For envoy we need to support every method
	method := c.Request.Method

	return ProxyContext{
		Host:   host,
		Proto:  proto,
		Path:   path,
		Method: method,
		Type:   ExtAuthz,
	}, nil
}

func (controller *ProxyController) determineAuthModules(proxy ProxyType) []AuthModuleType {
	switch proxy {
	case Traefik, Caddy:
		return []AuthModuleType{ForwardAuth}
	case Envoy:
		return []AuthModuleType{ExtAuthz, ForwardAuth}
	case Nginx:
		return []AuthModuleType{AuthRequest, ForwardAuth}
	default:
		return []AuthModuleType{}
	}
}

func (controller *ProxyController) getContextFromAuthModule(c *gin.Context, module AuthModuleType) (ProxyContext, error) {
	switch module {
	case ForwardAuth:
		ctx, err := controller.getForwardAuthContext(c)
		if err != nil {
			return ProxyContext{}, err
		}
		return ctx, nil
	case ExtAuthz:
		ctx, err := controller.getExtAuthzContext(c)
		if err != nil {
			return ProxyContext{}, err
		}
		return ctx, nil
	case AuthRequest:
		ctx, err := controller.getAuthRequestContext(c)
		if err != nil {
			return ProxyContext{}, err
		}
		return ctx, nil
	}
	return ProxyContext{}, fmt.Errorf("unsupported auth module: %v", module)
}

func (controller *ProxyController) getProxyContext(c *gin.Context) (ProxyContext, error) {
	var req Proxy

	err := c.BindUri(&req)
	if err != nil {
		return ProxyContext{}, err
	}

	proxy, err := controller.getProxyType(req.Proxy)

	if err != nil {
		return ProxyContext{}, err
	}

	tlog.App.Debug().Msgf("Proxy: %v", req.Proxy)

	authModules := controller.determineAuthModules(proxy)

	if len(authModules) == 0 {
		return ProxyContext{}, fmt.Errorf("no auth modules supported for proxy: %v", req.Proxy)
	}

	var ctx ProxyContext

	for _, module := range authModules {
		tlog.App.Debug().Msgf("Trying auth module: %v", module)
		ctx, err = controller.getContextFromAuthModule(c, module)
		if err == nil {
			tlog.App.Debug().Msgf("Auth module %v succeeded", module)
			break
		}
		tlog.App.Debug().Err(err).Msgf("Auth module %v failed", module)
	}

	if err != nil {
		return ProxyContext{}, err
	}

	// We don't care if the header is empty, we will just assume it's not a browser
	userAgent, _ := controller.getHeader(c, "user-agent")
	isBrowser := BrowserUserAgentRegex.MatchString(userAgent)

	if isBrowser {
		tlog.App.Debug().Msg("Request identified as coming from a browser")
	} else {
		tlog.App.Debug().Msg("Request identified as coming from a non-browser client")
	}

	ctx.IsBrowser = isBrowser
	ctx.ProxyType = proxy
	return ctx, nil
}
