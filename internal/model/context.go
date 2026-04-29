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
	TOTPEnabled bool
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
	return c.Provider == ProviderLocal
}

func (c *UserContext) IsOAuth() bool {
	return c.Provider == ProviderOAuth
}

func (c *UserContext) IsLDAP() bool {
	return c.Provider == ProviderLDAP
}

func (c *UserContext) IsBasicAuth() bool {
	return c.Provider == ProviderBasicAuth
}

func (c *UserContext) NewFromGin(ginctx *gin.Context) (*UserContext, error) {
	userContextValue, exists := ginctx.Get("context")

	if !exists {
		return nil, errors.New("failed to get user context")
	}

	userContext, ok := userContextValue.(*UserContext)

	if !ok {
		return nil, errors.New("invalid user context type")
	}

	*c = *userContext
	return c, nil
}

// Compatability layer until we get an excuse to drop in database migrations
func (c *UserContext) NewFromSession(session *repository.Session) (*UserContext, error) {
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
			Groups:      strings.Split(session.OAuthGroups, ","),
			Sub:         session.OAuthSub,
			DisplayName: session.OAuthName,
			ID:          session.Provider,
		}
	}

	if !session.TotpPending {
		c.Authenticated = true
	}

	return c, nil
}

func (c *UserContext) GetUsername() string {
	switch c.Provider {
	case ProviderLocal:
		return c.Local.Username
	case ProviderLDAP:
		return c.LDAP.Username
	case ProviderBasicAuth:
		return c.Local.Username
	case ProviderOAuth:
		return c.OAuth.Username
	default:
		return ""
	}
}

func (c *UserContext) GetEmail() string {
	switch c.Provider {
	case ProviderLocal:
		return c.Local.Email
	case ProviderLDAP:
		return c.LDAP.Email
	case ProviderBasicAuth:
		return c.Local.Email
	case ProviderOAuth:
		return c.OAuth.Email
	default:
		return ""
	}
}

func (c *UserContext) GetName() string {
	switch c.Provider {
	case ProviderLocal:
		return c.Local.Name
	case ProviderLDAP:
		return c.LDAP.Name
	case ProviderBasicAuth:
		return c.Local.Name
	case ProviderOAuth:
		return c.OAuth.Name
	default:
		return ""
	}
}

func (c *UserContext) ProviderName() string {
	switch c.Provider {
	case ProviderBasicAuth, ProviderLocal:
		return "local"
	case ProviderLDAP:
		return "ldap"
	case ProviderOAuth:
		return c.OAuth.DisplayName // compatability
	default:
		return "unknown"
	}
}

func (c *UserContext) TOTPPending() bool {
	if c.Provider == ProviderLocal {
		return c.Local.TOTPPending
	}
	return false
}

func (c *UserContext) OAuthName() string {
	if c.Provider == ProviderOAuth {
		return c.OAuth.DisplayName
	}
	return ""
}
