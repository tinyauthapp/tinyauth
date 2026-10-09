package controller

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"go.uber.org/dig"

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

var envoyAuthPath = "/api/auth/envoy?path="

type Proxy struct {
	Proxy string `uri:"proxy" binding:"required"`
}

type ProxyContext struct {
	Host      string
	Proto     string
	Path      string
	PathRaw   string
	Method    string
	Type      AuthModuleType
	IsBrowser bool
	ProxyType ProxyType
}

type ProxyController struct {
	log          *logger.Logger
	runtime      *model.RuntimeConfig
	config       *model.Config
	acls         *service.AccessControlsService
	auth         *service.AuthService
	policyEngine *service.PolicyEngine
}

type ProxyControllerInput struct {
	dig.In

	Log           *logger.Logger
	RuntimeConfig *model.RuntimeConfig
	Config        *model.Config
	RouterGroup   *gin.RouterGroup `name:"apiRouterGroup"`
	ACLsService   *service.AccessControlsService
	AuthService   *service.AuthService
	PolicyEngine  *service.PolicyEngine
}

func NewProxyController(i ProxyControllerInput) *ProxyController {
	controller := &ProxyController{
		log:          i.Log,
		runtime:      i.RuntimeConfig,
		config:       i.Config,
		acls:         i.ACLsService,
		auth:         i.AuthService,
		policyEngine: i.PolicyEngine,
	}

	proxyGroup := i.RouterGroup.Group("/auth")
	proxyGroup.Any("/:proxy", controller.proxyHandler)

	return controller
}

func (controller *ProxyController) proxyHandler(c *gin.Context) {
	// Load proxy context based on the request type
	proxyCtx, err := controller.getProxyContext(c)

	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to get proxy context from request")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad request",
		})
		return
	}

	// Get acls
	acls, err := controller.acls.GetAccessControls(proxyCtx.Host)

	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to get ACLs for resource")
		controller.handleError(c, proxyCtx)
		return
	}

	clientIP := c.ClientIP()

	aclsCtx := &service.ACLContext{
		ACLs:                     acls,
		IP:                       net.ParseIP(clientIP),
		Path:                     proxyCtx.Path,
		TrustedProxiesConfigured: controller.runtime.TrustedProxiesConfigured,
	}

	if controller.policyEngine.Evaluate(service.RuleIPBypassed, aclsCtx) {
		controller.setHeaders(c, acls)
		c.JSON(200, gin.H{
			"status":  200,
			"message": "Authenticated",
		})
		return
	}

	if controller.policyEngine.Evaluate(service.RuleAuthEnabled, aclsCtx) {
		controller.log.App.Debug().Msg("Authentication is disabled for this resource, allowing access without authentication")
		controller.setHeaders(c, acls)
		c.JSON(200, gin.H{
			"status":  200,
			"message": "Authenticated",
		})
		return
	}

	if !controller.policyEngine.Evaluate(service.RuleIPAllowed, aclsCtx) {
		queries, err := query.Values(UnauthorizedQuery{
			Resource: strings.Split(proxyCtx.Host, ".")[0],
			IP:       clientIP,
		})

		if err != nil {
			controller.log.App.Error().Err(err).Msg("Failed to encode unauthorized query")
			controller.handleError(c, proxyCtx)
			return
		}

		redirectURL := fmt.Sprintf("%s/unauthorized?%s", controller.runtime.AppURL, queries.Encode())

		if !controller.useBrowserResponse(proxyCtx) {
			c.Header("x-tinyauth-location", redirectURL)
			c.JSON(403, gin.H{
				"status":  403,
				"message": "Forbidden",
			})
			return
		}

		c.Redirect(http.StatusFound, redirectURL)
		return
	}

	userContext, err := new(model.UserContext).NewFromGin(c)

	if err != nil {
		// No user context found is not an issue
		if !errors.Is(err, model.ErrUserContextNotFound) {
			controller.log.App.Error().Err(err).Msg("Failed to create user context from request, treating as unauthenticated")
		}
		userContext = &model.UserContext{
			Authenticated: false,
		}
	}

	aclsCtx.UserContext = userContext

	if userContext.Authenticated {
		if !controller.policyEngine.Evaluate(service.RuleUserAllowed, aclsCtx) {
			controller.log.App.Warn().Str("user", userContext.GetUsername()).Str("resource", strings.Split(proxyCtx.Host, ".")[0]).Msg("User is not allowed to access resource")

			queries, err := query.Values(UnauthorizedQuery{
				Resource: strings.Split(proxyCtx.Host, ".")[0],
			})

			if err != nil {
				controller.log.App.Error().Err(err).Msg("Failed to encode unauthorized query")
				controller.handleError(c, proxyCtx)
				return
			}

			if userContext.IsOAuth() {
				queries.Set("username", userContext.GetEmail())
			} else {
				queries.Set("username", userContext.GetUsername())
			}

			redirectURL := fmt.Sprintf("%s/unauthorized?%s", controller.runtime.AppURL, queries.Encode())

			if !controller.useBrowserResponse(proxyCtx) {
				c.Header("x-tinyauth-location", redirectURL)
				c.JSON(403, gin.H{
					"status":  403,
					"message": "Forbidden",
				})
				return
			}

			c.Redirect(http.StatusFound, redirectURL)
			return
		}

		if userContext.IsOAuth() || userContext.IsLDAP() {
			var groupOK bool

			if userContext.IsOAuth() {
				groupOK = controller.policyEngine.Evaluate(service.RuleOAuthGroup, aclsCtx)
			} else {
				groupOK = controller.policyEngine.Evaluate(service.RuleLDAPGroup, aclsCtx)
			}

			if !groupOK {
				controller.log.App.Warn().Str("user", userContext.GetUsername()).Str("resource", strings.Split(proxyCtx.Host, ".")[0]).Msg("User is not in the required group to access resource")

				queries, err := query.Values(UnauthorizedQuery{
					Resource: strings.Split(proxyCtx.Host, ".")[0],
					GroupErr: true,
				})

				if err != nil {
					controller.log.App.Error().Err(err).Msg("Failed to encode unauthorized query")
					controller.handleError(c, proxyCtx)
					return
				}

				if userContext.IsOAuth() {
					queries.Set("username", userContext.GetEmail())
				} else {
					queries.Set("username", userContext.GetUsername())
				}

				redirectURL := fmt.Sprintf("%s/unauthorized?%s", controller.runtime.AppURL, queries.Encode())

				if !controller.useBrowserResponse(proxyCtx) {
					c.Header("x-tinyauth-location", redirectURL)
					c.JSON(403, gin.H{
						"status":  403,
						"message": "Forbidden",
					})
					return
				}

				c.Redirect(http.StatusFound, redirectURL)
				return
			}
		}

		c.Header("Remote-User", utils.SanitizeHeader(userContext.GetUsername()))
		c.Header("Remote-Name", utils.SanitizeHeader(userContext.GetName()))
		c.Header("Remote-Email", utils.SanitizeHeader(userContext.GetEmail()))

		if userContext.IsLDAP() {
			c.Header("Remote-Groups", utils.SanitizeHeader(strings.Join(userContext.LDAP.Groups, ",")))
		}

		if userContext.IsOAuth() {
			c.Header("Remote-Groups", utils.SanitizeHeader(strings.Join(userContext.OAuth.Groups, ",")))
			c.Header("Remote-Sub", utils.SanitizeHeader(userContext.OAuth.Sub))
		}

		controller.setHeaders(c, acls)

		c.JSON(200, gin.H{
			"status":  200,
			"message": "Authenticated",
		})
		return
	}

	queries, err := query.Values(RedirectQuery{
		RedirectURI: fmt.Sprintf("%s://%s%s", proxyCtx.Proto, proxyCtx.Host, proxyCtx.PathRaw),
		LoginFor:    FrontendLoginForApp,
	})

	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to encode redirect query")
		controller.handleError(c, proxyCtx)
		return
	}

	redirectURL := fmt.Sprintf("%s/login?%s", controller.runtime.AppURL, queries.Encode())

	if !controller.useBrowserResponse(proxyCtx) {
		c.Header("x-tinyauth-location", redirectURL)
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	c.Redirect(http.StatusFound, redirectURL)
}

func (controller *ProxyController) setHeaders(c *gin.Context, acls *model.App) {
	c.Header("Authorization", c.Request.Header.Get("Authorization"))

	if acls == nil {
		return
	}

	headers := utils.ParseHeaders(acls.Response.Headers)

	for key, value := range headers {
		c.Header(key, value)
	}

	basicPassword := utils.GetSecret(acls.Response.BasicAuth.Password, acls.Response.BasicAuth.PasswordFile)

	if acls.Response.BasicAuth.Username != "" && basicPassword != "" {
		controller.log.App.Debug().Msg("Setting basic auth header for response")
		c.Header("Authorization", fmt.Sprintf("Basic %s", utils.EncodeBasicAuth(acls.Response.BasicAuth.Username, basicPassword)))
	}
}

func (controller *ProxyController) handleError(c *gin.Context, proxyCtx ProxyContext) {
	redirectURL := fmt.Sprintf("%s/error", controller.runtime.AppURL)

	if !controller.useBrowserResponse(proxyCtx) {
		c.Header("x-tinyauth-location", redirectURL)
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	c.Redirect(http.StatusFound, redirectURL)
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
		Host:    host,
		Proto:   proto,
		PathRaw: uri,
		Method:  method,
		Type:    ForwardAuth,
	}, nil
}

func (controller *ProxyController) getAuthRequestContext(c *gin.Context) (ProxyContext, error) {
	xOriginalUrl, ok := controller.getHeader(c, "x-original-url")

	if !ok {
		return ProxyContext{}, errors.New("x-original-url not found")
	}

	u, err := url.Parse(xOriginalUrl)

	if err != nil {
		return ProxyContext{}, err
	}

	host := u.Host

	if strings.TrimSpace(host) == "" {
		return ProxyContext{}, errors.New("host not found")
	}

	proto := u.Scheme

	if strings.TrimSpace(proto) == "" {
		return ProxyContext{}, errors.New("proto not found")
	}

	method := c.Request.Method

	return ProxyContext{
		Host:    host,
		Proto:   proto,
		PathRaw: u.RequestURI(),
		Method:  method,
		Type:    AuthRequest,
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

	// The path is attached to the end of the /api/auth/envoy?path= string so we just strip it out
	if !strings.HasPrefix(c.Request.RequestURI, envoyAuthPath) {
		return ProxyContext{}, errors.New("path not found")
	}

	p := strings.TrimPrefix(c.Request.RequestURI, envoyAuthPath)

	if strings.TrimSpace(p) == "" {
		return ProxyContext{}, errors.New("path not found")
	}

	// For ext_authz we need to support every method
	method := c.Request.Method

	return ProxyContext{
		Host:    host,
		Proto:   proto,
		PathRaw: p,
		Method:  method,
		Type:    ExtAuthz,
	}, nil
}

func (controller *ProxyController) determineAuthModules(proxy ProxyType, fallbacks bool) []AuthModuleType {
	switch proxy {
	case Traefik, Caddy:
		return []AuthModuleType{ForwardAuth}
	case Envoy:
		authModules := []AuthModuleType{ExtAuthz}
		if fallbacks {
			authModules = append(authModules, ForwardAuth)
		}
		return authModules
	case Nginx:
		authModules := []AuthModuleType{AuthRequest}
		if fallbacks {
			authModules = append(authModules, ForwardAuth)
		}
		return authModules
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

func (controller *ProxyController) compareProxyContext(ctx1, ctx2 ProxyContext) bool {
	return ctx1.Host == ctx2.Host && ctx1.Proto == ctx2.Proto && ctx1.PathRaw == ctx2.PathRaw && ctx1.Method == ctx2.Method
}

func (controller *ProxyController) includedAuthModules(c *gin.Context, discoveredModules []AuthModuleType) []AuthModuleType {
	var modules []AuthModuleType

	if strings.HasPrefix(c.Request.RequestURI, envoyAuthPath) &&
		strings.TrimPrefix(c.Request.RequestURI, envoyAuthPath) != "" {
		modules = append(modules, ExtAuthz)
	}

	hasURI := c.GetHeader("x-forwarded-uri") != ""
	hasHost := c.GetHeader("x-forwarded-host") != ""

	if hasURI && hasHost {
		modules = append(modules, ForwardAuth)
	}

	hasXOriginalUrl := c.GetHeader("x-original-url") != ""

	if hasXOriginalUrl {
		modules = append(modules, AuthRequest)
	}

	return utils.Filter(modules, func(module AuthModuleType) bool {
		return slices.Contains(discoveredModules, module)
	})
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

	controller.log.App.Debug().Msgf("Determined proxy type: %v", proxy)

	authModules := controller.determineAuthModules(proxy, !controller.config.Experimental.DisableAuthModuleFallback)

	if len(authModules) == 0 {
		return ProxyContext{}, fmt.Errorf("no auth modules supported for proxy: %v", req.Proxy)
	}

	var extracted []ProxyContext

	for _, module := range authModules {
		controller.log.App.Debug().Msgf("Trying to get context from auth module %v", module)
		authModuleCtx, err := controller.getContextFromAuthModule(c, module)
		if err != nil {
			controller.log.App.Debug().Msgf("Failed to get context from auth module %v: %v", module, err)
			continue
		}
		controller.log.App.Debug().Msgf("Successfully got context from auth module %v", module)
		extracted = append(extracted, authModuleCtx)
	}

	if len(extracted) == 0 {
		return ProxyContext{}, fmt.Errorf("failed to get context from any auth module")
	}

	includedAuthModules := controller.includedAuthModules(c, authModules)

	if len(extracted) != len(includedAuthModules) {
		controller.log.App.Warn().
			Msg("Request carries context for multiple auth modules but some failed to extract, cannot determine correct auth modules")
		return ProxyContext{}, fmt.Errorf("cannot determine correct auth module")
	}

	if s := slices.CompactFunc(extracted, controller.compareProxyContext); len(s) > 1 {
		controller.log.App.Warn().
			Msg("Request carries context for multiple auth modules but they don't match, cannot determine correct auth modules")
		return ProxyContext{}, fmt.Errorf("cannot determine correct auth module")
	}

	ctx := extracted[0]

	// Parse the raw path to populate the cleaned path used for ACLs
	upath, err := url.Parse(ctx.PathRaw)

	if err != nil {
		return ProxyContext{}, fmt.Errorf("failed to parse request path: %v", err)
	}

	if upath.Host != "" || !strings.HasPrefix(upath.Path, "/") {
		return ProxyContext{}, fmt.Errorf("invalid request path")
	}

	ctx.Path = path.Clean(upath.Path)

	// We don't care if the header is empty, we will just assume it's not a browser
	userAgent, _ := controller.getHeader(c, "user-agent")
	isBrowser := BrowserUserAgentRegex.MatchString(userAgent)

	if isBrowser {
		controller.log.App.Debug().Msg("Request identified as coming from a browser client")
	} else {
		controller.log.App.Debug().Msg("Request identified as coming from a non-browser client")
	}

	ctx.IsBrowser = isBrowser
	ctx.ProxyType = proxy
	return ctx, nil
}
