package service

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v5"
	ldapgo "github.com/go-ldap/ldap/v3"
	"github.com/steveiliop56/ding"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"github.com/tinyauthapp/tinyauth/pkg/cache"
	"go.uber.org/dig"
)

var (
	ErrLDAPNoUsers       = errors.New("no users found")
	ErrLDAPMultipleUsers = errors.New("multiple users found")
)

type LDAPLookupType string

const (
	LDAPLookupTypeDN  LDAPLookupType = "dn"
	LDAPLookupTypeUID LDAPLookupType = "uid"
)

type LDAPCacheEntry struct {
	CN     string
	Email  string
	Groups []string
}

type LDAPUserLookupResult struct {
	LDAPCacheEntry
	DN string
}

type LDAPService struct {
	log    *logger.Logger
	ctx    context.Context
	config *model.Config

	conn   *ldapgo.Conn
	mutex  sync.RWMutex
	cert   *tls.Certificate
	bindPw string

	caches struct {
		users *cache.CacheStore[LDAPCacheEntry]
	}
}

type LDAPServiceInput struct {
	dig.In

	Log    *logger.Logger
	Config *model.Config
	Ding   *ding.Ding
	Ctx    context.Context
}

func NewLDAPService(i LDAPServiceInput) (*LDAPService, error) {
	if i.Config.LDAP.Address == "" {
		return nil, nil
	}

	ldap := &LDAPService{
		log:    i.Log,
		config: i.Config,
		ctx:    i.Ctx,
	}

	ldap.bindPw = utils.GetSecret(i.Config.LDAP.BindPassword, i.Config.LDAP.BindPasswordFile)

	// Check whether authentication with client certificate is possible
	if i.Config.LDAP.AuthCert != "" && i.Config.LDAP.AuthKey != "" {
		cert, err := tls.LoadX509KeyPair(i.Config.LDAP.AuthCert, i.Config.LDAP.AuthKey)

		if err != nil {
			return nil, fmt.Errorf("failed to initialize LDAP with mTLS authentication: %w", err)
		}

		i.Log.App.Info().Msg("LDAP mTLS authentication configured successfully")

		ldap.cert = &cert

		// TODO: Add optional extra CA certificates, instead of `InsecureSkipVerify`
		/*
			caCert, _ := ioutil.ReadFile(*caFile)
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			tlsConfig := &tls.Config{
						...
			RootCAs:      caCertPool,
			}
		*/
	}

	_, err := ldap.connect()

	if err != nil {
		// 3s + 4.5s (3x1.5) = ~6.75-8.25s total wait time before giving up
		err = ldap.reconnect(3 * time.Second)
		return nil, fmt.Errorf("failed to connect to ldap server: %w", err)
	}

	i.Ding.Go(func(ctx context.Context) {
		ldap.log.App.Debug().Msg("Starting LDAP connection heartbeat routine")

		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				err := ldap.heartbeat()
				if err != nil {
					ldap.log.App.Warn().Err(err).Msg("LDAP connection heartbeat failed, attempting to reconnect")
					if reconnectErr := ldap.reconnect(1 * time.Second); reconnectErr != nil {
						ldap.log.App.Error().Err(reconnectErr).Msg("Failed to reconnect to LDAP server")
						continue
					}
					ldap.log.App.Info().Msg("Successfully reconnected to LDAP server")
				}
			case <-ctx.Done():
				ldap.log.App.Debug().Msg("LDAP service context cancelled, stopping heartbeat")
				return
			}
		}
	}, ding.RingMajor)

	// Tinyauth *probably* isn't used in setups with more than 256
	// users, so this seems like a good default
	ldap.caches.users = cache.NewCacheStore[LDAPCacheEntry](256)

	i.Ding.Go(func(ctx context.Context) {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				ldap.caches.users.Sweep()
			case <-ctx.Done():
				return
			}
		}
	}, ding.RingMinor)

	return ldap, nil
}

func (l *LDAPService) LookupUser(filter string, lookupType LDAPLookupType) (*LDAPUserLookupResult, error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if lookupType == LDAPLookupTypeDN {
		entry, ok := l.cacheLookupByDN(filter)
		if ok {
			return entry, nil
		}
	}

	userSearch, err := l.conn.Search(l.getUserSR(filter, lookupType))

	if err != nil {
		return nil, fmt.Errorf("failed to lookup user: %w", err)
	}

	if len(userSearch.Entries) != 1 {
		if len(userSearch.Entries) == 0 {
			return nil, ErrLDAPNoUsers
		}
		return nil, ErrLDAPMultipleUsers
	}

	name := userSearch.Entries[0].GetAttributeValue("cn")
	email := userSearch.Entries[0].GetAttributeValue("mail")
	dn := userSearch.Entries[0].DN

	groupsSearch, err := l.conn.Search(ldapgo.NewSearchRequest(
		l.config.LDAP.BaseDN,
		ldapgo.ScopeWholeSubtree, ldapgo.NeverDerefAliases, 0, 0, false,
		strings.Replace(l.config.LDAP.GroupSearchFilter, "%s", ldapgo.EscapeFilter(dn), 1),
		[]string{"dn"},
		nil,
	))
	if err != nil {
		return nil, fmt.Errorf("failed to lookup user groups: %w", err)
	}

	var groupDNs []string

	for _, entry := range groupsSearch.Entries {
		groupDNs = append(groupDNs, entry.DN)
	}

	var groups []string

	for _, groupDN := range groupDNs {
		parts, err := ldapgo.ParseDN(groupDN)

		if err != nil {
			return nil, fmt.Errorf("failed to parse group dn: %w", err)
		}

		if len(parts.RDNs) == 0 || len(parts.RDNs[0].Attributes) == 0 {
			return nil, fmt.Errorf("invalid DN format: %s", dn)
		}

		groups = append(groups, parts.RDNs[0].Attributes[0].Value)
	}

	res := &LDAPUserLookupResult{
		DN: dn,
		LDAPCacheEntry: LDAPCacheEntry{
			CN:     name,
			Email:  email,
			Groups: groups,
		},
	}

	// The config option should just be UserTTL but since we have this old option
	// everyone already uses, why break?
	l.caches.users.Set(dn, res.LDAPCacheEntry, time.Duration(l.config.LDAP.GroupCacheTTL)*time.Second)

	return res, nil
}

func (l *LDAPService) getUserSR(filter string, lookupType LDAPLookupType) *ldapgo.SearchRequest {
	if lookupType == LDAPLookupTypeDN {
		return ldapgo.NewSearchRequest(
			ldapgo.EscapeFilter(filter),
			ldapgo.ScopeBaseObject, ldapgo.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)",
			[]string{"dn", "mail", "cn"},
			nil,
		)
	}

	return ldapgo.NewSearchRequest(
		l.config.LDAP.BaseDN,
		ldapgo.ScopeWholeSubtree, ldapgo.NeverDerefAliases, 0, 0, false,
		strings.Replace(l.config.LDAP.SearchFilter, "%s", ldapgo.EscapeFilter(filter), 1),
		[]string{"dn", "mail", "cn"},
		nil,
	)
}

func (l *LDAPService) cacheLookupByDN(dn string) (*LDAPUserLookupResult, bool) {
	entry, ok := l.caches.users.Get(dn)
	if !ok {
		return nil, false
	}
	return &LDAPUserLookupResult{
		LDAPCacheEntry: entry,
		DN:             dn,
	}, true
}

func (l *LDAPService) GetUserCount() (int, error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	searchResult, err := l.conn.Search(ldapgo.NewSearchRequest(
		l.config.LDAP.BaseDN,
		ldapgo.ScopeWholeSubtree, ldapgo.NeverDerefAliases, 0, 0, false,
		"(objectClass=person)",
		[]string{"dn"},
		nil,
	))
	if err != nil {
		return 0, fmt.Errorf("failed to get user count: %w", err)
	}

	return len(searchResult.Entries), nil
}

func (l *LDAPService) BindService() error {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return l.bindServiceCallback()
}

func (l *LDAPService) Bind(userDN string, password string) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	err := l.conn.Bind(userDN, password)
	if err != nil {
		return err
	}
	return nil
}

func (l *LDAPService) connect() (*ldapgo.Conn, error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if l.conn != nil {
		_ = l.conn.Close()
	}

	var conn *ldapgo.Conn
	var err error

	// TODO: There's also STARTTLS (or SASL)-based mTLS authentication
	// scenario, where we first connect to plain text port (389) and
	// continue with a STARTTLS negotiation:
	// 1. conn = ldap.DialURL("ldap://ldap.example.com:389")
	// 2. conn.StartTLS(tlsConfig)
	// 3. conn.externalBind()
	if l.cert != nil {
		conn, err = ldapgo.DialURL(l.config.LDAP.Address, ldapgo.DialWithTLSConfig(&tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{*l.cert},
		}))
	} else {
		conn, err = ldapgo.DialURL(l.config.LDAP.Address, ldapgo.DialWithTLSConfig(&tls.Config{
			InsecureSkipVerify: l.config.LDAP.Insecure,
			MinVersion:         tls.VersionTLS12,
		}))
	}
	if err != nil {
		return nil, err
	}

	l.conn = conn

	err = l.bindServiceCallback()
	if err != nil {
		return nil, err
	}
	return l.conn, nil
}

func (l *LDAPService) bindServiceCallback() error {
	if l.cert != nil {
		return l.conn.ExternalBind()
	}

	// attempt unauthenticated/anonymous bind if both bind dn and password are unset
	if l.config.LDAP.BindDN == "" && l.bindPw == "" {
		return l.conn.UnauthenticatedBind("")
	}

	return l.conn.Bind(l.config.LDAP.BindDN, l.bindPw)
}

func (l *LDAPService) heartbeat() error {
	l.log.App.Debug().Msg("Performing LDAP connection heartbeat")

	searchRequest := ldapgo.NewSearchRequest(
		"",
		ldapgo.ScopeBaseObject, ldapgo.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{},
		nil,
	)

	l.mutex.Lock()
	defer l.mutex.Unlock()
	_, err := l.conn.Search(searchRequest)
	if err != nil {
		return err
	}

	// No error means the connection is alive
	return nil
}

func (l *LDAPService) reconnect(interval time.Duration) error {
	l.log.App.Info().Msg("Attempting to reconnect to LDAP server")

	exp := backoff.NewExponentialBackOff()
	exp.InitialInterval = interval
	exp.RandomizationFactor = 0.1
	exp.Multiplier = 1.5
	exp.Reset()

	_, err := backoff.Retry(l.ctx, l.connect, backoff.WithBackOff(exp), backoff.WithMaxTries(3))

	if err != nil {
		return err
	}

	return nil
}
