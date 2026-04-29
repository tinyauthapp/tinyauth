package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v5"
	ldapgo "github.com/go-ldap/ldap/v3"
	"github.com/tinyauthapp/tinyauth/internal/utils/tlog"
)

type LdapServiceConfig struct {
	Address      string
	BindDN       string
	BindPassword string
	BaseDN       string
	Insecure     bool
	SearchFilter string
	AuthCert     string
	AuthKey      string
}

type LdapService struct {
	config       LdapServiceConfig
	conn         *ldapgo.Conn
	mutex        sync.RWMutex
	cert         *tls.Certificate
	isConfigured bool
}

func NewLdapService(config LdapServiceConfig) *LdapService {
	return &LdapService{
		config: config,
	}
}

func (ldap *LdapService) IsConfigured() bool {
	return ldap.isConfigured
}

func (ldap *LdapService) Unconfigure() error {
	if !ldap.isConfigured {
		return nil
	}

	if ldap.conn != nil {
		if err := ldap.conn.Close(); err != nil {
			return fmt.Errorf("failed to close LDAP connection: %w", err)
		}
	}

	ldap.isConfigured = false
	return nil
}

func (ldap *LdapService) Init() error {
	if ldap.config.Address == "" {
		ldap.isConfigured = false
		return nil
	}

	ldap.isConfigured = true

	// Check whether authentication with client certificate is possible
	if ldap.config.AuthCert != "" && ldap.config.AuthKey != "" {
		cert, err := tls.LoadX509KeyPair(ldap.config.AuthCert, ldap.config.AuthKey)
		if err != nil {
			return fmt.Errorf("failed to initialize LDAP with mTLS authentication: %w", err)
		}
		ldap.cert = &cert
		tlog.App.Info().Msg("Using LDAP with mTLS authentication")

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
		return fmt.Errorf("failed to connect to LDAP server: %w", err)
	}

	go func() {
		for range time.Tick(time.Duration(5) * time.Minute) {
			err := ldap.heartbeat()
			if err != nil {
				tlog.App.Error().Err(err).Msg("LDAP connection heartbeat failed")
				if reconnectErr := ldap.reconnect(); reconnectErr != nil {
					tlog.App.Error().Err(reconnectErr).Msg("Failed to reconnect to LDAP server")
					continue
				}
				tlog.App.Info().Msg("Successfully reconnected to LDAP server")
			}
		}
	}()

	return nil
}

func (ldap *LdapService) connect() (*ldapgo.Conn, error) {
	ldap.mutex.Lock()
	defer ldap.mutex.Unlock()

	var conn *ldapgo.Conn
	var err error

	// TODO: There's also STARTTLS (or SASL)-based mTLS authentication
	// scenario, where we first connect to plain text port (389) and
	// continue with a STARTTLS negotiation:
	// 1. conn = ldap.DialURL("ldap://ldap.example.com:389")
	// 2. conn.StartTLS(tlsConfig)
	// 3. conn.externalBind()
	if ldap.cert != nil {
		conn, err = ldapgo.DialURL(ldap.config.Address, ldapgo.DialWithTLSConfig(&tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{*ldap.cert},
		}))
	} else {
		conn, err = ldapgo.DialURL(ldap.config.Address, ldapgo.DialWithTLSConfig(&tls.Config{
			InsecureSkipVerify: ldap.config.Insecure,
			MinVersion:         tls.VersionTLS12,
		}))
	}
	if err != nil {
		return nil, err
	}

	ldap.conn = conn

	err = ldap.BindService(false)
	if err != nil {
		return nil, err
	}
	return ldap.conn, nil
}

func (ldap *LdapService) GetUserDN(username string) (string, error) {
	// Escape the username to prevent LDAP injection
	escapedUsername := ldapgo.EscapeFilter(username)
	filter := fmt.Sprintf(ldap.config.SearchFilter, escapedUsername)

	searchRequest := ldapgo.NewSearchRequest(
		ldap.config.BaseDN,
		ldapgo.ScopeWholeSubtree, ldapgo.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{"dn"},
		nil,
	)

	ldap.mutex.Lock()
	defer ldap.mutex.Unlock()

	searchResult, err := ldap.conn.Search(searchRequest)
	if err != nil {
		return "", err
	}

	if len(searchResult.Entries) != 1 {
		return "", fmt.Errorf("multiple or no entries found for user %s", username)
	}

	userDN := searchResult.Entries[0].DN
	return userDN, nil
}

func (ldap *LdapService) GetUserGroups(userDN string) ([]string, error) {
	escapedUserDN := ldapgo.EscapeFilter(userDN)

	searchRequest := ldapgo.NewSearchRequest(
		ldap.config.BaseDN,
		ldapgo.ScopeWholeSubtree, ldapgo.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(objectclass=groupOfUniqueNames)(uniquemember=%s))", escapedUserDN),
		[]string{"dn"},
		nil,
	)

	ldap.mutex.Lock()
	defer ldap.mutex.Unlock()

	searchResult, err := ldap.conn.Search(searchRequest)
	if err != nil {
		return []string{}, err
	}

	groupDNs := []string{}

	for _, entry := range searchResult.Entries {
		groupDNs = append(groupDNs, entry.DN)
	}

	groups := []string{}

	// I guess it should work for most ldap providers
	for _, dn := range groupDNs {
		rdnParts, err := ldapgo.ParseDN(dn)
		if err != nil {
			return []string{}, err
		}
		if len(rdnParts.RDNs) == 0 || len(rdnParts.RDNs[0].Attributes) == 0 {
			return []string{}, fmt.Errorf("invalid DN format: %s", dn)
		}
		groups = append(groups, rdnParts.RDNs[0].Attributes[0].Value)
	}

	return groups, nil
}

func (ldap *LdapService) BindService(rebind bool) error {
	// Locks must not be used for initial binding attempt
	if rebind {
		ldap.mutex.Lock()
		defer ldap.mutex.Unlock()
	}

	if ldap.cert != nil {
		return ldap.conn.ExternalBind()
	}
	return ldap.conn.Bind(ldap.config.BindDN, ldap.config.BindPassword)
}

func (ldap *LdapService) Bind(userDN string, password string) error {
	ldap.mutex.Lock()
	defer ldap.mutex.Unlock()
	err := ldap.conn.Bind(userDN, password)
	if err != nil {
		return err
	}
	return nil
}

func (ldap *LdapService) heartbeat() error {
	tlog.App.Debug().Msg("Performing LDAP connection heartbeat")

	searchRequest := ldapgo.NewSearchRequest(
		"",
		ldapgo.ScopeBaseObject, ldapgo.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{},
		nil,
	)

	ldap.mutex.Lock()
	defer ldap.mutex.Unlock()
	_, err := ldap.conn.Search(searchRequest)
	if err != nil {
		return err
	}

	// No error means the connection is alive
	return nil
}

func (ldap *LdapService) reconnect() error {
	tlog.App.Info().Msg("Reconnecting to LDAP server")

	exp := backoff.NewExponentialBackOff()
	exp.InitialInterval = 500 * time.Millisecond
	exp.RandomizationFactor = 0.1
	exp.Multiplier = 1.5
	exp.Reset()

	operation := func() (*ldapgo.Conn, error) {
		ldap.conn.Close()
		conn, err := ldap.connect()
		if err != nil {
			return nil, err
		}
		return conn, nil
	}

	_, err := backoff.Retry(context.TODO(), operation, backoff.WithBackOff(exp), backoff.WithMaxTries(3))

	if err != nil {
		return err
	}

	return nil
}
