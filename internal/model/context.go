package model

import (
	"errors"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/tinyauthapp/tinyauth/internal/repository"
)

type ProviderType int

const (
	ProviderLocal ProviderType = iota
	ProviderBasicAuth
	ProviderOAuth
	ProviderLDAP
)

type UserContext struct {
	Authenticated bool
	Provider      ProviderType
	Local         *LocalContext
	OAuth         *OAuthContext
	LDAP          *LDAPContext
}

type BaseContext struct {
	Username string
	Name     string
	Email    string
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

func (c *UserContext) NewFromGin(ginctx *gin.Context) (*UserContext, error) {
	userContextValue, exists := ginctx.Get("context")

	if !exists {
		return nil, errors.New("failed to get user context")
	}

	userContext, ok := userContextValue.(*UserContext)

	if !ok || userContext == nil {
		return nil, errors.New("invalid user context type")
	}

	if userContext.LDAP == nil && userContext.Local == nil && userContext.OAuth == nil {
		return nil, errors.New("incomplete user context")
	}

	*c = *userContext
	return c, nil
}

// Compatability layer until we get an excuse to drop in database migrations
func (c *UserContext) NewFromSession(session *repository.Session) (*UserContext, error) {
	*c = UserContext{
		Authenticated: !session.TotpPending,
	}

	switch session.Provider {
	case "local":
		c.Provider = ProviderLocal
		c.Local = &LocalContext{
			BaseContext: BaseContext{
				Username: session.Username,
				Name:     session.Name,
				Email:    session.Email,
			},
			TOTPPending: session.TotpPending,
		}
	case "ldap":
		c.Provider = ProviderLDAP
		c.LDAP = &LDAPContext{
			BaseContext: BaseContext{
				Username: session.Username,
				Name:     session.Name,
				Email:    session.Email,
			},
		}
	// By default we assume an unkown name which is oauth
	default:
		c.Provider = ProviderOAuth
		c.OAuth = &OAuthContext{
			BaseContext: BaseContext{
				Username: session.Username,
				Name:     session.Name,
				Email:    session.Email,
			},
			Groups: func() []string {
				if session.OAuthGroups == "" {
					return nil
				}
				return strings.Split(session.OAuthGroups, ",")
			}(),
			Sub:         session.OAuthSub,
			DisplayName: session.OAuthName,
			ID:          session.Provider,
		}
	}

	return c, nil
}

func (c *UserContext) GetUsername() string {
	switch c.Provider {
	case ProviderLocal:
		if c.Local == nil {
			return ""
		}
		return c.Local.Username
	case ProviderLDAP:
		if c.LDAP == nil {
			return ""
		}
		return c.LDAP.Username
	case ProviderBasicAuth:
		if c.Local == nil {
			return ""
		}
		return c.Local.Username
	case ProviderOAuth:
		if c.OAuth == nil {
			return ""
		}
		return c.OAuth.Username
	default:
		return ""
	}
}

func (c *UserContext) GetEmail() string {
	switch c.Provider {
	case ProviderLocal:
		if c.Local == nil {
			return ""
		}
		return c.Local.Email
	case ProviderLDAP:
		if c.LDAP == nil {
			return ""
		}
		return c.LDAP.Email
	case ProviderBasicAuth:
		if c.Local == nil {
			return ""
		}
		return c.Local.Email
	case ProviderOAuth:
		if c.OAuth == nil {
			return ""
		}
		return c.OAuth.Email
	default:
		return ""
	}
}

func (c *UserContext) GetName() string {
	switch c.Provider {
	case ProviderLocal:
		if c.Local == nil {
			return ""
		}
		return c.Local.Name
	case ProviderLDAP:
		if c.LDAP == nil {
			return ""
		}
		return c.LDAP.Name
	case ProviderBasicAuth:
		if c.Local == nil {
			return ""
		}
		return c.Local.Name
	case ProviderOAuth:
		if c.OAuth == nil {
			return ""
		}
		return c.OAuth.Name
	default:
		return ""
	}
}

func (c *UserContext) GetProviderID() string {
	switch c.Provider {
	case ProviderBasicAuth, ProviderLocal:
		return "local"
	case ProviderLDAP:
		return "ldap"
	case ProviderOAuth:
		return c.OAuth.ID
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
