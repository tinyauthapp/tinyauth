package config

// Default configuration
func NewDefaultConfiguration() *Config {
	return &Config{
		Database: DatabaseConfig{
			Path: "./tinyauth.db",
		},
		Analytics: AnalyticsConfig{
			Enabled: true,
		},
		Resources: ResourcesConfig{
			Enabled: true,
			Path:    "./resources",
		},
		Server: ServerConfig{
			Port:    3000,
			Address: "0.0.0.0",
		},
		Auth: AuthConfig{
			SessionExpiry:      86400, // 1 day
			SessionMaxLifetime: 0,     // disabled
			LoginTimeout:       300,   // 5 minutes
			LoginMaxRetries:    3,
		},
		UI: UIConfig{
			Title:                 "Tinyauth",
			ForgotPasswordMessage: "You can change your password by changing the configuration.",
			BackgroundImage:       "/background.jpg",
			WarningsEnabled:       true,
		},
		Ldap: LdapConfig{
			Insecure:      false,
			SearchFilter:  "(uid=%s)",
			GroupCacheTTL: 900, // 15 minutes
		},
		Log: LogConfig{
			Level: "info",
			Json:  false,
			Streams: LogStreams{
				HTTP: LogStreamConfig{
					Enabled: true,
					Level:   "",
				},
				App: LogStreamConfig{
					Enabled: true,
					Level:   "",
				},
				Audit: LogStreamConfig{
					Enabled: false,
					Level:   "",
				},
			},
		},
		OIDC: OIDCConfig{
			PrivateKeyPath: "./tinyauth_oidc_key",
			PublicKeyPath:  "./tinyauth_oidc_key.pub",
		},
		Experimental: ExperimentalConfig{
			ConfigFile: "",
		},
		LabelProvider: "auto",
	}
}

// Version information, set at build time

var Version = "development"
var CommitHash = "development"
var BuildTimestamp = "0000-00-00T00:00:00Z"

// Cookie name templates

var SessionCookieName = "tinyauth-session"
var CSRFCookieName = "tinyauth-csrf"
var RedirectCookieName = "tinyauth-redirect"
var OAuthSessionCookieName = "tinyauth-oauth"

// Main app config
type Config struct {
	AppURL        string             `description:"The base URL where the app is hosted." yaml:"appUrl"`
	Database      DatabaseConfig     `description:"Database configuration." yaml:"database"`
	Analytics     AnalyticsConfig    `description:"Analytics configuration." yaml:"analytics"`
	Resources     ResourcesConfig    `description:"Resources configuration." yaml:"resources"`
	Server        ServerConfig       `description:"Server configuration." yaml:"server"`
	Auth          AuthConfig         `description:"Authentication configuration." yaml:"auth"`
	Apps          map[string]App     `description:"Application ACLs configuration." yaml:"apps"`
	OAuth         OAuthConfig        `description:"OAuth configuration." yaml:"oauth"`
	OIDC          OIDCConfig         `description:"OIDC configuration." yaml:"oidc"`
	UI            UIConfig           `description:"UI customization." yaml:"ui"`
	Ldap          LdapConfig         `description:"LDAP configuration." yaml:"ldap"`
	Experimental  ExperimentalConfig `description:"Experimental features, use with caution." yaml:"experimental"`
	LabelProvider string             `description:"Label provider to use for ACLs (auto, docker, or kubernetes). auto detects the environment." yaml:"labelProvider"`
	Log           LogConfig          `description:"Logging configuration." yaml:"log"`
}

type DatabaseConfig struct {
	Path string `description:"The path to the database, including file name." yaml:"path"`
}

type AnalyticsConfig struct {
	Enabled bool `description:"Enable periodic version information collection." yaml:"enabled"`
}

type ResourcesConfig struct {
	Enabled bool   `description:"Enable the resources server." yaml:"enabled"`
	Path    string `description:"The directory where resources are stored." yaml:"path"`
}

type ServerConfig struct {
	Port       int    `description:"The port on which the server listens." yaml:"port"`
	Address    string `description:"The address on which the server listens." yaml:"address"`
	SocketPath string `description:"The path to the Unix socket." yaml:"socketPath"`
}

type AuthConfig struct {
	IP                 IPConfig                  `description:"IP whitelisting config options." yaml:"ip"`
	Users              []string                  `description:"Comma-separated list of users (username:hashed_password)." yaml:"users"`
	UserAttributes     map[string]UserAttributes `description:"Map of per-user OIDC attributes (username -> attributes)." yaml:"userAttributes"`
	UsersFile          string                    `description:"Path to the users file." yaml:"usersFile"`
	SecureCookie       bool                      `description:"Enable secure cookies." yaml:"secureCookie"`
	SessionExpiry      int                       `description:"Session expiry time in seconds." yaml:"sessionExpiry"`
	SessionMaxLifetime int                       `description:"Maximum session lifetime in seconds." yaml:"sessionMaxLifetime"`
	LoginTimeout       int                       `description:"Login timeout in seconds." yaml:"loginTimeout"`
	LoginMaxRetries    int                       `description:"Maximum login retries." yaml:"loginMaxRetries"`
	TrustedProxies     []string                  `description:"Comma-separated list of trusted proxy addresses." yaml:"trustedProxies"`
}

type UserAttributes struct {
	Name        string       `description:"Full name of the user." yaml:"name"`
	GivenName   string       `description:"Given (first) name of the user." yaml:"givenName"`
	FamilyName  string       `description:"Family (last) name of the user." yaml:"familyName"`
	MiddleName  string       `description:"Middle name of the user." yaml:"middleName"`
	Nickname    string       `description:"Nickname of the user." yaml:"nickname"`
	Profile     string       `description:"URL of the user's profile page." yaml:"profile"`
	Picture     string       `description:"URL of the user's profile picture." yaml:"picture"`
	Website     string       `description:"URL of the user's website." yaml:"website"`
	Email       string       `description:"Email address of the user." yaml:"email"`
	Gender      string       `description:"Gender of the user." yaml:"gender"`
	Birthdate   string       `description:"Birthdate of the user (YYYY-MM-DD)." yaml:"birthdate"`
	Zoneinfo    string       `description:"Time zone of the user (e.g. Europe/Athens)." yaml:"zoneinfo"`
	Locale      string       `description:"Locale of the user (e.g. en-US)." yaml:"locale"`
	PhoneNumber string       `description:"Phone number of the user." yaml:"phoneNumber"`
	Address     AddressClaim `description:"Address of the user." yaml:"address"`
}

type AddressClaim struct {
	Formatted     string `description:"Full mailing address, formatted for display." yaml:"formatted" json:"formatted,omitempty"`
	StreetAddress string `description:"Street address." yaml:"streetAddress" json:"street_address,omitempty"`
	Locality      string `description:"City or locality." yaml:"locality" json:"locality,omitempty"`
	Region        string `description:"State, province, or region." yaml:"region" json:"region,omitempty"`
	PostalCode    string `description:"Zip or postal code." yaml:"postalCode" json:"postal_code,omitempty"`
	Country       string `description:"Country." yaml:"country" json:"country,omitempty"`
}

type IPConfig struct {
	Allow []string `description:"List of allowed IPs or CIDR ranges." yaml:"allow"`
	Block []string `description:"List of blocked IPs or CIDR ranges." yaml:"block"`
}

type OAuthConfig struct {
	Whitelist    []string                      `description:"Comma-separated list of allowed OAuth domains." yaml:"whitelist"`
	AutoRedirect string                        `description:"The OAuth provider to use for automatic redirection." yaml:"autoRedirect"`
	Providers    map[string]OAuthServiceConfig `description:"OAuth providers configuration." yaml:"providers"`
}

type OIDCConfig struct {
	PrivateKeyPath string                      `description:"Path to the private key file, including file name." yaml:"privateKeyPath"`
	PublicKeyPath  string                      `description:"Path to the public key file, including file name." yaml:"publicKeyPath"`
	Clients        map[string]OIDCClientConfig `description:"OIDC clients configuration." yaml:"clients"`
}

type UIConfig struct {
	Title                 string `description:"The title of the UI." yaml:"title"`
	ForgotPasswordMessage string `description:"Message displayed on the forgot password page." yaml:"forgotPasswordMessage"`
	BackgroundImage       string `description:"Path to the background image." yaml:"backgroundImage"`
	WarningsEnabled       bool   `description:"Enable UI warnings." yaml:"warningsEnabled"`
}

type LdapConfig struct {
	Address       string `description:"LDAP server address." yaml:"address"`
	BindDN        string `description:"Bind DN for LDAP authentication." yaml:"bindDn"`
	BindPassword  string `description:"Bind password for LDAP authentication." yaml:"bindPassword"`
	BaseDN        string `description:"Base DN for LDAP searches." yaml:"baseDn"`
	Insecure      bool   `description:"Allow insecure LDAP connections." yaml:"insecure"`
	SearchFilter  string `description:"LDAP search filter." yaml:"searchFilter"`
	AuthCert      string `description:"Certificate for mTLS authentication." yaml:"authCert"`
	AuthKey       string `description:"Certificate key for mTLS authentication." yaml:"authKey"`
	GroupCacheTTL int    `description:"Cache duration for LDAP group membership in seconds." yaml:"groupCacheTTL"`
}

type LogConfig struct {
	Level   string     `description:"Log level (trace, debug, info, warn, error)." yaml:"level"`
	Json    bool       `description:"Enable JSON formatted logs." yaml:"json"`
	Streams LogStreams `description:"Configuration for specific log streams." yaml:"streams"`
}

type LogStreams struct {
	HTTP  LogStreamConfig `description:"HTTP request logging." yaml:"http"`
	App   LogStreamConfig `description:"Application logging." yaml:"app"`
	Audit LogStreamConfig `description:"Audit logging." yaml:"audit"`
}

type LogStreamConfig struct {
	Enabled bool   `description:"Enable this log stream." yaml:"enabled"`
	Level   string `description:"Log level for this stream. Use global if empty." yaml:"level"`
}

type ExperimentalConfig struct {
	ConfigFile string `description:"Path to config file." yaml:"-"`
}

// Config loader options

const DefaultNamePrefix = "TINYAUTH_"

// OAuth/OIDC config

type Claims struct {
	Sub               string `json:"sub"`
	Name              string `json:"name"`
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
	Groups            any    `json:"groups"`
}

type OAuthServiceConfig struct {
	ClientID         string   `description:"OAuth client ID." yaml:"clientId"`
	ClientSecret     string   `description:"OAuth client secret." yaml:"clientSecret"`
	ClientSecretFile string   `description:"Path to the file containing the OAuth client secret." yaml:"clientSecretFile"`
	Scopes           []string `description:"OAuth scopes." yaml:"scopes"`
	RedirectURL      string   `description:"OAuth redirect URL." yaml:"redirectUrl"`
	AuthURL          string   `description:"OAuth authorization URL." yaml:"authUrl"`
	TokenURL         string   `description:"OAuth token URL." yaml:"tokenUrl"`
	UserinfoURL      string   `description:"OAuth userinfo URL." yaml:"userinfoUrl"`
	Insecure         bool     `description:"Allow insecure OAuth connections." yaml:"insecure"`
	Name             string   `description:"Provider name in UI." yaml:"name"`
}

type OIDCClientConfig struct {
	ID                  string   `description:"OIDC client ID." yaml:"-"`
	ClientID            string   `description:"OIDC client ID." yaml:"clientId"`
	ClientSecret        string   `description:"OIDC client secret." yaml:"clientSecret"`
	ClientSecretFile    string   `description:"Path to the file containing the OIDC client secret." yaml:"clientSecretFile"`
	TrustedRedirectURIs []string `description:"List of trusted redirect URIs." yaml:"trustedRedirectUris"`
	Name                string   `description:"Client name in UI." yaml:"name"`
}

var OverrideProviders = map[string]string{
	"google": "Google",
	"github": "GitHub",
}

// User/session related stuff

type User struct {
	Username   string
	Password   string
	TotpSecret string
	Attributes UserAttributes
}

type LdapUser struct {
	DN     string
	Groups []string
}

type UserSearch struct {
	Username string
	Type     string // local, ldap or unknown
}

type UserContext struct {
	Username    string
	Name        string
	Email       string
	IsLoggedIn  bool
	IsBasicAuth bool
	OAuth       bool
	Provider    string
	TotpPending bool
	OAuthGroups string
	TotpEnabled bool
	OAuthName   string
	OAuthSub    string
	LdapGroups  string
	Attributes  UserAttributes
}

// API responses and queries

type UnauthorizedQuery struct {
	Username string `url:"username"`
	Resource string `url:"resource"`
	GroupErr bool   `url:"groupErr"`
	IP       string `url:"ip"`
}

type RedirectQuery struct {
	RedirectURI string `url:"redirect_uri"`
}

// ACLs

type Apps struct {
	Apps map[string]App `description:"App ACLs configuration." yaml:"apps"`
}

type App struct {
	Config   AppConfig   `description:"App configuration." yaml:"config"`
	Users    AppUsers    `description:"User access configuration." yaml:"users"`
	OAuth    AppOAuth    `description:"OAuth access configuration." yaml:"oauth"`
	IP       AppIP       `description:"IP access configuration." yaml:"ip"`
	Response AppResponse `description:"Response customization." yaml:"response"`
	Path     AppPath     `description:"Path access configuration." yaml:"path"`
	LDAP     AppLDAP     `description:"LDAP access configuration." yaml:"ldap"`
}

type AppConfig struct {
	Domain string `description:"The domain of the app." yaml:"domain"`
}

type AppUsers struct {
	Allow string `description:"Comma-separated list of allowed users." yaml:"allow"`
	Block string `description:"Comma-separated list of blocked users." yaml:"block"`
}

type AppOAuth struct {
	Whitelist string `description:"Comma-separated list of allowed OAuth groups." yaml:"whitelist"`
	Groups    string `description:"Comma-separated list of required OAuth groups." yaml:"groups"`
}

type AppLDAP struct {
	Groups string `description:"Comma-separated list of required LDAP groups." yaml:"groups"`
}

type AppIP struct {
	Allow  []string `description:"List of allowed IPs or CIDR ranges." yaml:"allow"`
	Block  []string `description:"List of blocked IPs or CIDR ranges." yaml:"block"`
	Bypass []string `description:"List of IPs or CIDR ranges that bypass authentication." yaml:"bypass"`
}

type AppResponse struct {
	Headers   []string     `description:"Custom headers to add to the response." yaml:"headers"`
	BasicAuth AppBasicAuth `description:"Basic authentication for the app." yaml:"basicAuth"`
}

type AppBasicAuth struct {
	Username     string `description:"Basic auth username." yaml:"username"`
	Password     string `description:"Basic auth password." yaml:"password"`
	PasswordFile string `description:"Path to the file containing the basic auth password." yaml:"passwordFile"`
}

type AppPath struct {
	Allow string `description:"Comma-separated list of allowed paths." yaml:"allow"`
	Block string `description:"Comma-separated list of blocked paths." yaml:"block"`
}

// API server

var ApiServer = "https://api.tinyauth.app"
