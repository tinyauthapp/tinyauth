package service

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"slices"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"github.com/tinyauthapp/tinyauth/internal/config"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/tinyauth/internal/utils/tlog"
)

var (
	SupportedScopes        = []string{"openid", "profile", "email", "phone", "address", "groups"}
	SupportedResponseTypes = []string{"code"}
	SupportedGrantTypes    = []string{"authorization_code", "refresh_token"}
)

var (
	ErrCodeExpired   = errors.New("code_expired")
	ErrCodeNotFound  = errors.New("code_not_found")
	ErrTokenNotFound = errors.New("token_not_found")
	ErrTokenExpired  = errors.New("token_expired")
	ErrInvalidClient = errors.New("invalid_client")
)

type ClaimSet struct {
	Iss               string   `json:"iss"`
	Aud               string   `json:"aud"`
	Sub               string   `json:"sub"`
	Iat               int64    `json:"iat"`
	Exp               int64    `json:"exp"`
	Name              string   `json:"name,omitempty"`
	GivenName         string   `json:"given_name,omitempty"`
	FamilyName        string   `json:"family_name,omitempty"`
	MiddleName        string   `json:"middle_name,omitempty"`
	Nickname          string   `json:"nickname,omitempty"`
	Profile           string   `json:"profile,omitempty"`
	Picture           string   `json:"picture,omitempty"`
	Website           string   `json:"website,omitempty"`
	Gender            string   `json:"gender,omitempty"`
	Birthdate         string   `json:"birthdate,omitempty"`
	Zoneinfo          string   `json:"zoneinfo,omitempty"`
	Locale            string   `json:"locale,omitempty"`
	Email             string   `json:"email,omitempty"`
	EmailVerified     bool     `json:"email_verified,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Groups            []string `json:"groups,omitempty"`
	Nonce             string   `json:"nonce,omitempty"`
}

type UserinfoResponse struct {
	Sub                 string               `json:"sub"`
	Name                string               `json:"name,omitempty"`
	GivenName           string               `json:"given_name,omitempty"`
	FamilyName          string               `json:"family_name,omitempty"`
	MiddleName          string               `json:"middle_name,omitempty"`
	Nickname            string               `json:"nickname,omitempty"`
	Profile             string               `json:"profile,omitempty"`
	Picture             string               `json:"picture,omitempty"`
	Website             string               `json:"website,omitempty"`
	Gender              string               `json:"gender,omitempty"`
	Birthdate           string               `json:"birthdate,omitempty"`
	Zoneinfo            string               `json:"zoneinfo,omitempty"`
	Locale              string               `json:"locale,omitempty"`
	Email               string               `json:"email,omitempty"`
	PreferredUsername   string               `json:"preferred_username,omitempty"`
	Groups              []string             `json:"groups,omitempty"`
	EmailVerified       bool                 `json:"email_verified,omitempty"`
	PhoneNumber         string               `json:"phone_number,omitempty"`
	PhoneNumberVerified *bool                `json:"phone_number_verified,omitempty"`
	Address             *config.AddressClaim `json:"address,omitempty"`
	UpdatedAt           int64                `json:"updated_at"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
}

type AuthorizeRequest struct {
	Scope               string `json:"scope" binding:"required"`
	ResponseType        string `json:"response_type" binding:"required"`
	ClientID            string `json:"client_id" binding:"required"`
	RedirectURI         string `json:"redirect_uri" binding:"required"`
	State               string `json:"state"`
	Nonce               string `json:"nonce"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

type OIDCServiceConfig struct {
	Clients        map[string]config.OIDCClientConfig
	PrivateKeyPath string
	PublicKeyPath  string
	Issuer         string
	SessionExpiry  int
}

type OIDCService struct {
	config       OIDCServiceConfig
	queries      *repository.Queries
	clients      map[string]config.OIDCClientConfig
	privateKey   *rsa.PrivateKey
	publicKey    crypto.PublicKey
	issuer       string
	isConfigured bool
}

func NewOIDCService(config OIDCServiceConfig, queries *repository.Queries) *OIDCService {
	return &OIDCService{
		config:  config,
		queries: queries,
	}
}

func (service *OIDCService) IsConfigured() bool {
	return service.isConfigured
}

func (service *OIDCService) Init() error {
	// If not configured, skip init
	if len(service.config.Clients) == 0 {
		service.isConfigured = false
		return nil
	}

	service.isConfigured = true

	// Ensure issuer is https
	uissuer, err := url.Parse(service.config.Issuer)

	if err != nil {
		return err
	}

	if uissuer.Scheme != "https" {
		return errors.New("issuer must be https")
	}

	service.issuer = fmt.Sprintf("%s://%s", uissuer.Scheme, uissuer.Host)

	// Create/load private and public keys
	if strings.TrimSpace(service.config.PrivateKeyPath) == "" ||
		strings.TrimSpace(service.config.PublicKeyPath) == "" {
		return errors.New("private key path and public key path are required")
	}

	var privateKey *rsa.PrivateKey

	fprivateKey, err := os.ReadFile(service.config.PrivateKeyPath)

	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	if errors.Is(err, os.ErrNotExist) {
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		der := x509.MarshalPKCS1PrivateKey(privateKey)
		if der == nil {
			return errors.New("failed to marshal private key")
		}
		encoded := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: der,
		})
		tlog.App.Trace().Str("type", "RSA PRIVATE KEY").Msg("Generated private RSA key")
		err = os.WriteFile(service.config.PrivateKeyPath, encoded, 0600)
		if err != nil {
			return err
		}
		service.privateKey = privateKey
	} else {
		block, _ := pem.Decode(fprivateKey)
		if block == nil {
			return errors.New("failed to decode private key")
		}
		tlog.App.Trace().Str("type", block.Type).Msg("Loaded private key")
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		service.privateKey = privateKey
	}

	fpublicKey, err := os.ReadFile(service.config.PublicKeyPath)

	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	if errors.Is(err, os.ErrNotExist) {
		publicKey := service.privateKey.Public()
		der := x509.MarshalPKCS1PublicKey(publicKey.(*rsa.PublicKey))
		if der == nil {
			return errors.New("failed to marshal public key")
		}
		encoded := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: der,
		})
		tlog.App.Trace().Str("type", "RSA PUBLIC KEY").Msg("Generated public RSA key")
		err = os.WriteFile(service.config.PublicKeyPath, encoded, 0644)
		if err != nil {
			return err
		}
		service.publicKey = publicKey
	} else {
		block, _ := pem.Decode(fpublicKey)
		if block == nil {
			return errors.New("failed to decode public key")
		}
		tlog.App.Trace().Str("type", block.Type).Msg("Loaded public key")
		switch block.Type {
		case "RSA PUBLIC KEY":
			publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
			if err != nil {
				return err
			}
			service.publicKey = publicKey
		case "PUBLIC KEY":
			publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return err
			}
			service.publicKey = publicKey.(crypto.PublicKey)
		default:
			return fmt.Errorf("unsupported public key type: %s", block.Type)
		}
	}

	// We will reorganize the client into a map with the client ID as the key
	service.clients = make(map[string]config.OIDCClientConfig)

	for id, client := range service.config.Clients {
		client.ID = id
		if client.Name == "" {
			client.Name = utils.Capitalize(client.ID)
		}
		service.clients[client.ClientID] = client
	}

	// Load the client secrets from files if they exist
	for id, client := range service.clients {
		secret := utils.GetSecret(client.ClientSecret, client.ClientSecretFile)
		if secret != "" {
			client.ClientSecret = secret
		}
		client.ClientSecretFile = ""
		service.clients[id] = client
		tlog.App.Info().Str("id", client.ID).Msg("Registered OIDC client")
	}

	return nil
}

func (service *OIDCService) GetIssuer() string {
	return service.issuer
}

func (service *OIDCService) GetClient(id string) (config.OIDCClientConfig, bool) {
	client, ok := service.clients[id]
	return client, ok
}

func (service *OIDCService) ValidateAuthorizeParams(req AuthorizeRequest) error {
	// Validate client ID
	client, ok := service.GetClient(req.ClientID)
	if !ok {
		return errors.New("access_denied")
	}

	// Scopes
	scopes := strings.Split(req.Scope, " ")

	if len(scopes) == 0 || strings.TrimSpace(req.Scope) == "" {
		return errors.New("invalid_scope")
	}

	for _, scope := range scopes {
		if strings.TrimSpace(scope) == "" {
			return errors.New("invalid_scope")
		}
		if !slices.Contains(SupportedScopes, scope) {
			tlog.App.Warn().Str("scope", scope).Msg("Unsupported OIDC scope, will be ignored")
		}
	}

	// Response type
	if !slices.Contains(SupportedResponseTypes, req.ResponseType) {
		return errors.New("unsupported_response_type")
	}

	// Redirect URI
	if !slices.Contains(client.TrustedRedirectURIs, req.RedirectURI) {
		return errors.New("invalid_request_uri")
	}

	// PKCE code challenge method if set
	if req.CodeChallenge != "" && req.CodeChallengeMethod != "" {
		if req.CodeChallengeMethod != "S256" && req.CodeChallengeMethod != "plain" {
			return errors.New("invalid_request")
		}
	}

	return nil
}

func (service *OIDCService) filterScopes(scopes []string) []string {
	return utils.Filter(scopes, func(scope string) bool {
		return slices.Contains(SupportedScopes, scope)
	})
}

func (service *OIDCService) StoreCode(c *gin.Context, sub string, code string, req AuthorizeRequest) error {
	// Fixed 10 minutes
	expiresAt := time.Now().Add(time.Minute * time.Duration(10)).Unix()

	entry := repository.CreateOidcCodeParams{
		Sub:      sub,
		CodeHash: service.Hash(code),
		// Here it's safe to split and trust the output since, we validated the scopes before
		Scope:       strings.Join(service.filterScopes(strings.Split(req.Scope, " ")), ","),
		RedirectURI: req.RedirectURI,
		ClientID:    req.ClientID,
		ExpiresAt:   expiresAt,
		Nonce:       req.Nonce,
	}

	if req.CodeChallenge != "" {
		if req.CodeChallengeMethod == "S256" {
			entry.CodeChallenge = req.CodeChallenge
		} else {
			entry.CodeChallenge = service.hashAndEncodePKCE(req.CodeChallenge)
			tlog.App.Warn().Msg("Received plain PKCE code challenge, it's recommended to use S256 for better security")
		}
	}

	// Insert the code into the database
	_, err := service.queries.CreateOidcCode(c, entry)

	return err
}

func (service *OIDCService) StoreUserinfo(c *gin.Context, sub string, userContext config.UserContext, req AuthorizeRequest) error {
	addressJSON, err := json.Marshal(userContext.Attributes.Address)
	if err != nil {
		return err
	}

	userInfoParams := repository.CreateOidcUserInfoParams{
		Sub:               sub,
		Name:              userContext.Name,
		Email:             userContext.Email,
		PreferredUsername: userContext.Username,
		UpdatedAt:         time.Now().Unix(),
		GivenName:         userContext.Attributes.GivenName,
		FamilyName:        userContext.Attributes.FamilyName,
		MiddleName:        userContext.Attributes.MiddleName,
		Nickname:          userContext.Attributes.Nickname,
		Profile:           userContext.Attributes.Profile,
		Picture:           userContext.Attributes.Picture,
		Website:           userContext.Attributes.Website,
		Gender:            userContext.Attributes.Gender,
		Birthdate:         userContext.Attributes.Birthdate,
		Zoneinfo:          userContext.Attributes.Zoneinfo,
		Locale:            userContext.Attributes.Locale,
		PhoneNumber:       userContext.Attributes.PhoneNumber,
		Address:           string(addressJSON),
	}

	// Tinyauth will pass through the groups it got from an LDAP or an OIDC server
	if userContext.Provider == "ldap" {
		userInfoParams.Groups = userContext.LdapGroups
	}

	if userContext.OAuth && len(userContext.OAuthGroups) > 0 {
		userInfoParams.Groups = userContext.OAuthGroups
	}

	_, err = service.queries.CreateOidcUserInfo(c, userInfoParams)

	return err
}

func (service *OIDCService) ValidateGrantType(grantType string) error {
	if !slices.Contains(SupportedGrantTypes, grantType) {
		return errors.New("unsupported_grant_type")
	}

	return nil
}

func (service *OIDCService) GetCodeEntry(c *gin.Context, codeHash string, clientId string) (repository.OidcCode, error) {
	oidcCode, err := service.queries.GetOidcCode(c, codeHash)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return repository.OidcCode{}, ErrCodeNotFound
		}
		return repository.OidcCode{}, err
	}

	if time.Now().Unix() > oidcCode.ExpiresAt {
		err = service.queries.DeleteOidcCode(c, codeHash)
		if err != nil {
			return repository.OidcCode{}, err
		}
		err = service.DeleteUserinfo(c, oidcCode.Sub)
		if err != nil {
			return repository.OidcCode{}, err
		}
		return repository.OidcCode{}, ErrCodeExpired
	}

	if oidcCode.ClientID != clientId {
		return repository.OidcCode{}, ErrInvalidClient
	}

	return oidcCode, nil
}

func (service *OIDCService) generateIDToken(client config.OIDCClientConfig, user repository.OidcUserinfo, scope string, nonce string) (string, error) {
	createdAt := time.Now().Unix()
	expiresAt := time.Now().Add(time.Duration(service.config.SessionExpiry) * time.Second).Unix()

	hasher := sha256.New()

	der := x509.MarshalPKCS1PublicKey(&service.privateKey.PublicKey)

	if der == nil {
		return "", errors.New("failed to marshal public key")
	}

	hasher.Write(der)

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       service.privateKey,
	}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]any{
			"typ": "jwt",
			"jku": fmt.Sprintf("%s/.well-known/jwks.json", service.issuer),
			"kid": base64.URLEncoding.EncodeToString(hasher.Sum(nil)),
		},
	})

	if err != nil {
		return "", err
	}

	userInfo := service.CompileUserinfo(user, scope)

	claims := ClaimSet{
		Iss:               service.issuer,
		Aud:               client.ClientID,
		Sub:               user.Sub,
		Iat:               createdAt,
		Exp:               expiresAt,
		Name:              userInfo.Name,
		Email:             userInfo.Email,
		EmailVerified:     userInfo.EmailVerified,
		PreferredUsername: userInfo.PreferredUsername,
		Groups:            userInfo.Groups,
		Nonce:             nonce,
	}

	payload, err := json.Marshal(claims)

	if err != nil {
		return "", err
	}

	object, err := signer.Sign(payload)

	if err != nil {
		return "", err
	}

	token, err := object.CompactSerialize()

	if err != nil {
		return "", err
	}

	return token, nil
}

func (service *OIDCService) GenerateAccessToken(c *gin.Context, client config.OIDCClientConfig, codeEntry repository.OidcCode) (TokenResponse, error) {
	user, err := service.GetUserinfo(c, codeEntry.Sub)

	if err != nil {
		return TokenResponse{}, err
	}

	idToken, err := service.generateIDToken(client, user, codeEntry.Scope, codeEntry.Nonce)

	if err != nil {
		return TokenResponse{}, err
	}

	accessToken := utils.GenerateString(32)
	refreshToken := utils.GenerateString(32)

	tokenExpiresAt := time.Now().Add(time.Duration(service.config.SessionExpiry) * time.Second).Unix()

	// Refresh token lives double the time of an access token but can't be used to access userinfo
	refreshTokenExpiresAt := time.Now().Add(time.Duration(service.config.SessionExpiry*2) * time.Second).Unix()

	tokenResponse := TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(service.config.SessionExpiry),
		IDToken:      idToken,
		Scope:        strings.ReplaceAll(codeEntry.Scope, ",", " "),
	}

	_, err = service.queries.CreateOidcToken(c, repository.CreateOidcTokenParams{
		Sub:                   codeEntry.Sub,
		AccessTokenHash:       service.Hash(accessToken),
		RefreshTokenHash:      service.Hash(refreshToken),
		ClientID:              client.ClientID,
		Scope:                 codeEntry.Scope,
		TokenExpiresAt:        tokenExpiresAt,
		RefreshTokenExpiresAt: refreshTokenExpiresAt,
		Nonce:                 codeEntry.Nonce,
		CodeHash:              codeEntry.CodeHash,
	})

	if err != nil {
		return TokenResponse{}, err
	}

	return tokenResponse, nil
}

func (service *OIDCService) RefreshAccessToken(c *gin.Context, refreshToken string, reqClientId string) (TokenResponse, error) {
	entry, err := service.queries.GetOidcTokenByRefreshToken(c, service.Hash(refreshToken))

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return TokenResponse{}, ErrTokenNotFound
		}
		return TokenResponse{}, err
	}

	if entry.RefreshTokenExpiresAt < time.Now().Unix() {
		return TokenResponse{}, ErrTokenExpired
	}

	// Ensure the client ID in the request matches the client ID in the token
	if entry.ClientID != reqClientId {
		return TokenResponse{}, ErrInvalidClient
	}

	user, err := service.GetUserinfo(c, entry.Sub)

	if err != nil {
		return TokenResponse{}, err
	}

	idToken, err := service.generateIDToken(config.OIDCClientConfig{
		ClientID: entry.ClientID,
	}, user, entry.Scope, entry.Nonce)

	if err != nil {
		return TokenResponse{}, err
	}

	accessToken := utils.GenerateString(32)
	newRefreshToken := utils.GenerateString(32)

	tokenExpiresAt := time.Now().Add(time.Duration(service.config.SessionExpiry) * time.Second).Unix()
	refreshTokenExpiresAt := time.Now().Add(time.Duration(service.config.SessionExpiry*2) * time.Second).Unix()

	tokenResponse := TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(service.config.SessionExpiry),
		IDToken:      idToken,
		Scope:        strings.ReplaceAll(entry.Scope, ",", " "),
	}

	_, err = service.queries.UpdateOidcTokenByRefreshToken(c, repository.UpdateOidcTokenByRefreshTokenParams{
		AccessTokenHash:       service.Hash(accessToken),
		RefreshTokenHash:      service.Hash(newRefreshToken),
		TokenExpiresAt:        tokenExpiresAt,
		RefreshTokenExpiresAt: refreshTokenExpiresAt,
		RefreshTokenHash_2:    service.Hash(refreshToken), // that's the selector, it's not stored in the db
	})

	if err != nil {
		return TokenResponse{}, err
	}

	return tokenResponse, nil
}

func (service *OIDCService) DeleteCodeEntry(c *gin.Context, codeHash string) error {
	return service.queries.DeleteOidcCode(c, codeHash)
}

func (service *OIDCService) DeleteUserinfo(c *gin.Context, sub string) error {
	return service.queries.DeleteOidcUserInfo(c, sub)
}

func (service *OIDCService) DeleteToken(c *gin.Context, tokenHash string) error {
	return service.queries.DeleteOidcToken(c, tokenHash)
}

func (service *OIDCService) DeleteTokenByCodeHash(c *gin.Context, codeHash string) error {
	return service.queries.DeleteOidcTokenByCodeHash(c, codeHash)
}

func (service *OIDCService) GetAccessToken(c *gin.Context, tokenHash string) (repository.OidcToken, error) {
	entry, err := service.queries.GetOidcToken(c, tokenHash)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return repository.OidcToken{}, ErrTokenNotFound
		}
		return repository.OidcToken{}, err
	}

	if entry.TokenExpiresAt < time.Now().Unix() {
		// If refresh token is expired, delete the token and userinfo since there is no way for the client to access anything anymore
		if entry.RefreshTokenExpiresAt < time.Now().Unix() {
			err := service.DeleteToken(c, tokenHash)
			if err != nil {
				return repository.OidcToken{}, err
			}
			err = service.DeleteUserinfo(c, entry.Sub)
			if err != nil {
				return repository.OidcToken{}, err
			}
		}
		return repository.OidcToken{}, ErrTokenExpired
	}

	return entry, nil
}

func (service *OIDCService) GetUserinfo(c *gin.Context, sub string) (repository.OidcUserinfo, error) {
	return service.queries.GetOidcUserInfo(c, sub)
}

func (service *OIDCService) CompileUserinfo(user repository.OidcUserinfo, scope string) UserinfoResponse {
	scopes := strings.Split(scope, ",") // split by comma since it's a db entry
	userInfo := UserinfoResponse{
		Sub:       user.Sub,
		UpdatedAt: user.UpdatedAt,
	}

	if slices.Contains(scopes, "profile") {
		userInfo.Name = user.Name
		userInfo.PreferredUsername = user.PreferredUsername
		userInfo.GivenName = user.GivenName
		userInfo.FamilyName = user.FamilyName
		userInfo.MiddleName = user.MiddleName
		userInfo.Nickname = user.Nickname
		userInfo.Profile = user.Profile
		userInfo.Picture = user.Picture
		userInfo.Website = user.Website
		userInfo.Gender = user.Gender
		userInfo.Birthdate = user.Birthdate
		userInfo.Zoneinfo = user.Zoneinfo
		userInfo.Locale = user.Locale
	}

	if slices.Contains(scopes, "email") {
		userInfo.Email = user.Email
		userInfo.EmailVerified = user.Email != ""
	}

	if slices.Contains(scopes, "groups") {
		if user.Groups != "" {
			userInfo.Groups = strings.Split(user.Groups, ",")
		} else {
			userInfo.Groups = []string{}
		}
	}

	if slices.Contains(scopes, "phone") {
		userInfo.PhoneNumber = user.PhoneNumber
		verified := user.PhoneNumber != ""
		userInfo.PhoneNumberVerified = &verified
	}

	if slices.Contains(scopes, "address") {
		var addr config.AddressClaim
		if err := json.Unmarshal([]byte(user.Address), &addr); err == nil {
			userInfo.Address = &addr
		}
	}

	return userInfo
}

func (service *OIDCService) Hash(token string) string {
	hasher := sha256.New()
	hasher.Write([]byte(token))
	return fmt.Sprintf("%x", hasher.Sum(nil))
}

func (service *OIDCService) DeleteOldSession(ctx context.Context, sub string) error {
	err := service.queries.DeleteOidcCodeBySub(ctx, sub)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	err = service.queries.DeleteOidcTokenBySub(ctx, sub)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	err = service.queries.DeleteOidcUserInfo(ctx, sub)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	return nil
}

// Cleanup routine - Resource heavy due to the linked tables
func (service *OIDCService) Cleanup() {
	// We need a context for the routine
	ctx := context.Background()

	ticker := time.NewTicker(time.Duration(30) * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		currentTime := time.Now().Unix()

		// For the OIDC tokens, if they are expired we delete the userinfo and codes
		expiredTokens, err := service.queries.DeleteExpiredOidcTokens(ctx, repository.DeleteExpiredOidcTokensParams{
			TokenExpiresAt:        currentTime,
			RefreshTokenExpiresAt: currentTime,
		})

		if err != nil {
			tlog.App.Warn().Err(err).Msg("Failed to delete expired tokens")
		}

		for _, expiredToken := range expiredTokens {
			err := service.DeleteOldSession(ctx, expiredToken.Sub)
			if err != nil {
				tlog.App.Warn().Err(err).Msg("Failed to delete old session")
			}
		}

		// For expired codes, we need to get the sub, check if tokens are expired and if they are remove everything
		expiredCodes, err := service.queries.DeleteExpiredOidcCodes(ctx, currentTime)

		if err != nil {
			tlog.App.Warn().Err(err).Msg("Failed to delete expired codes")
		}

		for _, expiredCode := range expiredCodes {
			token, err := service.queries.GetOidcTokenBySub(ctx, expiredCode.Sub)

			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					continue
				}
				tlog.App.Warn().Err(err).Msg("Failed to get OIDC token by sub")
			}

			if token.TokenExpiresAt < currentTime && token.RefreshTokenExpiresAt < currentTime {
				err := service.DeleteOldSession(ctx, expiredCode.Sub)
				if err != nil {
					tlog.App.Warn().Err(err).Msg("Failed to delete session")
				}
			}
		}
	}
}

func (service *OIDCService) GetJWK() ([]byte, error) {
	hasher := sha256.New()

	der := x509.MarshalPKCS1PublicKey(&service.privateKey.PublicKey)

	if der == nil {
		return nil, errors.New("failed to marshal public key")
	}

	hasher.Write(der)

	jwk := jose.JSONWebKey{
		Key:       service.privateKey,
		Algorithm: string(jose.RS256),
		Use:       "sig",
		KeyID:     base64.URLEncoding.EncodeToString(hasher.Sum(nil)),
	}

	return jwk.Public().MarshalJSON()
}

func (service *OIDCService) ValidatePKCE(codeChallenge string, codeVerifier string) bool {
	if codeChallenge == "" {
		return true
	}
	return codeChallenge == service.hashAndEncodePKCE(codeVerifier)
}

func (service *OIDCService) hashAndEncodePKCE(codeVerifier string) string {
	hasher := sha256.New()
	hasher.Write([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))
}
