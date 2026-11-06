package model

import (
	"errors"
	"strings"

	"github.com/gin-gonic/gin"
)

var (
	ErrUserContextNotFound = errors.New("user context not found")
)

type ProviderType int

const (
	ProviderLocal ProviderType = iota
	ProviderBasicAuth
	ProviderOAuth
	ProviderLDAP
	ProviderTailscale
)

func (t ProviderType) String() string {
	switch t {
	case ProviderLocal:
		return "local"
	case ProviderBasicAuth:
		return "basic"
	case ProviderOAuth:
		return "oauth"
	case ProviderLDAP:
		return "ldap"
	case ProviderTailscale:
		return "tailscale"
	default:
		return "unknown"
	}
}

func ProviderFromString(s string) (ProviderType, error) {
	switch s {
	case "local":
		return ProviderLocal, nil
	case "basic":
		return ProviderBasicAuth, nil
	case "oauth":
		return ProviderOAuth, nil
	case "ldap":
		return ProviderLDAP, nil
	case "tailscale":
		return ProviderTailscale, nil
	default:
		return ProviderLocal, errors.New("unknown provider")
	}
}

type UserContext struct {
	Authenticated bool
	Provider      ProviderType
	AuthTime      int64
	Local         *LocalContext
	OAuth         *OAuthContext
	LDAP          *LDAPContext
	Tailscale     *TailscaleContext
}

type BaseContext struct {
	DistinctUserID string
	Username       string
	Name           string
	Email          string
}

type LocalContext struct {
	BaseContext
	TOTPPending bool
	Attributes  UserAttributes
}

type OAuthContext struct {
	BaseContext
	Groups      []string
	Sub         string
	DisplayName string
	ID          string
}

type LDAPContext struct {
	BaseContext
	Groups []string
}

type TailscaleContext struct {
	BaseContext
	NodeName string
}

func (c *UserContext) IsAuthenticated() bool {
	return c.Authenticated
}

func (c *UserContext) IsLocal() bool {
	return c.Provider == ProviderLocal && c.Local != nil
}

func (c *UserContext) IsOAuth() bool {
	return c.Provider == ProviderOAuth && c.OAuth != nil
}

func (c *UserContext) IsLDAP() bool {
	return c.Provider == ProviderLDAP && c.LDAP != nil
}

func (c *UserContext) IsBasicAuth() bool {
	return c.Provider == ProviderBasicAuth && c.Local != nil
}

func (c *UserContext) IsTailscale() bool {
	return c.Provider == ProviderTailscale && c.Tailscale != nil
}

func (c *UserContext) NewFromGin(ginctx *gin.Context) (*UserContext, error) {
	userContextValue, exists := ginctx.Get("context")

	if !exists {
		return nil, ErrUserContextNotFound
	}

	userContext, ok := userContextValue.(*UserContext)

	if !ok || userContext == nil {
		return nil, errors.New("invalid user context type")
	}

	if userContext.LDAP == nil && userContext.Local == nil && userContext.OAuth == nil && userContext.Tailscale == nil {
		return nil, errors.New("incomplete user context")
	}

	*c = *userContext
	return c, nil
}

func (c *UserContext) NewFromSession(session SessionGetResult, identity IdentityResult) (*UserContext, error) {
	*c = UserContext{
		Authenticated: !session.SessionContext.Local.TOTPPending,
		AuthTime:      session.Session.CreatedAt,
	}

	switch identity.Provider {
	case ProviderLocal:
		c.Provider = ProviderLocal
		c.Local = &LocalContext{
			BaseContext: BaseContext{
				DistinctUserID: identity.ProviderUserID,
				Username:       identity.Username,
				Name:           identity.Name,
				Email:          identity.Email,
			},
			TOTPPending: session.SessionContext.Local.TOTPPending,
		}
	case ProviderLDAP:
		c.Provider = ProviderLDAP
		c.LDAP = &LDAPContext{
			BaseContext: BaseContext{
				DistinctUserID: identity.ProviderUserID,
				Username:       identity.Username,
				Name:           identity.Name,
				Email:          identity.Email,
			},
		}
	case ProviderTailscale:
		c.Provider = ProviderTailscale
		c.Tailscale = &TailscaleContext{
			BaseContext: BaseContext{
				DistinctUserID: identity.ProviderUserID,
				Username:       identity.Username,
				Name:           identity.Name,
				Email:          identity.Email,
			},
		}
	case ProviderOAuth:
		c.Provider = ProviderOAuth
		c.OAuth = &OAuthContext{
			BaseContext: BaseContext{
				DistinctUserID: identity.ProviderUserID,
				Username:       identity.Username,
				Name:           identity.Name,
				Email:          identity.Email,
			},
			Groups: func() []string {
				if identity.IdentityContext.OAuth.Groups == "" {
					return nil
				}
				return strings.Split(identity.IdentityContext.OAuth.Groups, ",")
			}(),
			DisplayName: identity.IdentityContext.OAuth.DisplayName,
		}
	default:
		return nil, errors.New("unknown provider")
	}

	return c, nil
}

func (c *UserContext) getBaseContext() *BaseContext {
	switch c.Provider {
	case ProviderLocal, ProviderBasicAuth:
		if c.Local == nil {
			return nil
		}
		return &c.Local.BaseContext
	case ProviderLDAP:
		if c.LDAP == nil {
			return nil
		}
		return &c.LDAP.BaseContext
	case ProviderOAuth:
		if c.OAuth == nil {
			return nil
		}
		return &c.OAuth.BaseContext
	case ProviderTailscale:
		if c.Tailscale == nil {
			return nil
		}
		return &c.Tailscale.BaseContext
	default:
		return nil
	}
}

func (c *UserContext) GetUsername() string {
	base := c.getBaseContext()
	if base == nil {
		return ""
	}
	return base.Username
}

func (c *UserContext) GetEmail() string {
	base := c.getBaseContext()
	if base == nil {
		return ""
	}
	return base.Email
}

func (c *UserContext) GetName() string {
	base := c.getBaseContext()
	if base == nil {
		return ""
	}
	return base.Name
}

func (c *UserContext) GetProviderID() string {
	switch c.Provider {
	case ProviderBasicAuth, ProviderLocal:
		return "local"
	case ProviderLDAP:
		return "ldap"
	case ProviderOAuth:
		return c.OAuth.ID
	case ProviderTailscale:
		return "tailscale"
	default:
		return "unknown"
	}
}

func (c *UserContext) TOTPPending() bool {
	if c.Provider == ProviderLocal && c.Local != nil {
		return c.Local.TOTPPending
	}
	return false
}

func (c *UserContext) OAuthName() string {
	if c.Provider == ProviderOAuth && c.OAuth != nil {
		return c.OAuth.DisplayName
	}
	return ""
}

func (c *UserContext) TailscaleNodeName() string {
	if c.Tailscale != nil {
		return c.Tailscale.NodeName
	}
	return ""
}
