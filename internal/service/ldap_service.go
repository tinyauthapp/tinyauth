package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v5"
	ldapgo "github.com/go-ldap/ldap/v3"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

type LdapService struct {
	log     *logger.Logger
	config  model.Config
	context context.Context

	conn  *ldapgo.Conn
	mutex sync.RWMutex
	cert  *tls.Certificate
}

func NewLdapService(
	log *logger.Logger,
	config model.Config,
	ctx context.Context,
	wg *sync.WaitGroup,
) (*LdapService, error) {
	if config.LDAP.Address == "" {
		return nil, nil
	}

	ldap := &LdapService{
		log:     log,
		config:  config,
		context: ctx,
	}

	// Check whether authentication with client certificate is possible
	if config.LDAP.AuthCert != "" && config.LDAP.AuthKey != "" {
		cert, err := tls.LoadX509KeyPair(config.LDAP.AuthCert, config.LDAP.AuthKey)

		if err != nil {
			return nil, fmt.Errorf("failed to initialize LDAP with mTLS authentication: %w", err)
		}

		log.App.Info().Msg("LDAP mTLS authentication configured successfully")

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
		return nil, fmt.Errorf("failed to connect to ldap server: %w", err)
	}

	wg.Go(func() {
		ldap.log.App.Debug().Msg("Starting LDAP connection heartbeat routine")

		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				err := ldap.heartbeat()
				if err != nil {
					ldap.log.App.Warn().Err(err).Msg("LDAP connection heartbeat failed, attempting to reconnect")
					if reconnectErr := ldap.reconnect(); reconnectErr != nil {
						ldap.log.App.Error().Err(reconnectErr).Msg("Failed to reconnect to LDAP server")
						continue
					}
					ldap.log.App.Info().Msg("Successfully reconnected to LDAP server")
				}
			case <-ldap.context.Done():
				ldap.log.App.Debug().Msg("LDAP service context cancelled, stopping heartbeat")
				return
			}
		}
	})

	return ldap, nil
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
		conn, err = ldapgo.DialURL(ldap.config.LDAP.Address, ldapgo.DialWithTLSConfig(&tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{*ldap.cert},
		}))
	} else {
		conn, err = ldapgo.DialURL(ldap.config.LDAP.Address, ldapgo.DialWithTLSConfig(&tls.Config{
			InsecureSkipVerify: ldap.config.LDAP.Insecure,
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

func (ldap *LdapService) GetUserInfo(username string) (dn string, email string, err error) {
	escapedUsername := ldapgo.EscapeFilter(username)
	filter := fmt.Sprintf(ldap.config.LDAP.SearchFilter, escapedUsername)

	searchRequest := ldapgo.NewSearchRequest(
		ldap.config.LDAP.BaseDN,
		ldapgo.ScopeWholeSubtree, ldapgo.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{"dn", "mail"},
		nil,
	)

	ldap.mutex.Lock()
	defer ldap.mutex.Unlock()

	searchResult, err := ldap.conn.Search(searchRequest)
	if err != nil {
		return "", "", err
	}

	if len(searchResult.Entries) != 1 {
		return "", "", fmt.Errorf("multiple or no entries found for user %s", username)
	}

	entry := searchResult.Entries[0]
	return entry.DN, entry.GetAttributeValue("mail"), nil
}

func (ldap *LdapService) GetUserGroups(userDN string) ([]string, error) {
	escapedUserDN := ldapgo.EscapeFilter(userDN)

	searchRequest := ldapgo.NewSearchRequest(
		ldap.config.LDAP.BaseDN,
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
	return ldap.conn.Bind(ldap.config.LDAP.BindDN, ldap.config.LDAP.BindPassword)
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
	ldap.log.App.Debug().Msg("Performing LDAP connection heartbeat")

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
	ldap.log.App.Info().Msg("Attempting to reconnect to LDAP server")

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
