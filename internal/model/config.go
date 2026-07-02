package model

import "os"

type RuntimeEnv int

const (
	RuntimeEnvUnknown RuntimeEnv = iota
	RuntimeEnvDocker
)

func DetectRuntimeEnv() RuntimeEnv {
	env := os.Getenv("RUNTIME_ENV")
	switch env {
	case "docker":
		return RuntimeEnvDocker
	default:
		return RuntimeEnvUnknown
	}
}

// Default configuration
func NewDefaultConfiguration(runtimeEnv RuntimeEnv) *Config {
	cfg := &Config{
		Database: DatabaseConfig{
			Driver: "sqlite",
			Path:   "./tinyauth.db",
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
			SubdomainsEnabled:  true,
			SessionExpiry:      86400, // 1 day
			SessionMaxLifetime: 0,     // disabled
			LoginTimeout:       300,   // 5 minutes
			LoginMaxRetries:    3,
			ACLs: ACLsConfig{
				Policy: "allow",
			},
			LockdownEnabled: true,
		},
		UI: UIConfig{
			Title:                 "Tinyauth",
			ForgotPasswordMessage: "You can change your password by changing the configuration.",
			BackgroundImage:       "/background.jpg",
			WarningsEnabled:       true,
		},
		LDAP: LDAPConfig{
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
		Tailscale: TailscaleConfig{
			Dir: "./tailscale_state",
		},
		LabelProvider: "auto",
	}

	// apply path overrides for docker runtime
	if runtimeEnv == RuntimeEnvDocker {
		cfg.Database.Path = "/data/tinyauth.db"
		cfg.Resources.Path = "/data/resources"
		cfg.OIDC.PrivateKeyPath = "/data/oidc/key.pem"
		cfg.OIDC.PublicKeyPath = "/data/oidc/key.pub"
		cfg.Tailscale.Dir = "/data/tailscale"
	}

	return cfg
}

type Config struct {
	AppURL    string          `description:"The base URL where the app is hosted." yaml:"appUrl,omitempty"`
	Database  DatabaseConfig  `description:"Database configuration." yaml:"database,omitempty"`
	Analytics AnalyticsConfig `description:"Analytics configuration." yaml:"analytics,omitempty"`
	Resources ResourcesConfig `description:"Resources configuration." yaml:"resources,omitempty"`
	Server    ServerConfig    `description:"Server configuration." yaml:"server,omitempty"`
	Auth      AuthConfig      `description:"Authentication configuration." yaml:"auth,omitempty"`
	Apps      map[string]App  `description:"Application ACLs configuration." yaml:"apps,omitempty"`
	OAuth     OAuthConfig     `description:"OAuth configuration." yaml:"oauth,omitempty"`
	OIDC      OIDCConfig      `description:"OIDC configuration." yaml:"oidc,omitempty"`
	UI        UIConfig        `description:"UI customization." yaml:"ui,omitempty"`
	LDAP      LDAPConfig      `description:"LDAP configuration." yaml:"ldap,omitempty"`
	// Experimental  ExperimentalConfig `description:"Experimental features, use with caution." yaml:"experimental,omitempty"`
	LabelProvider string          `description:"Label provider to use for ACLs (auto, docker, kubernetes or none to disable). auto detects the environment." yaml:"labelProvider,omitempty"`
	Log           LogConfig       `description:"Logging configuration." yaml:"log,omitempty"`
	Tailscale     TailscaleConfig `description:"Tailscale configuration." yaml:"tailscale,omitempty"`
	ConfigFile    string          `description:"Path to config file." yaml:"-"`
}

type DatabaseConfig struct {
	Driver string `description:"The database driver to use. Valid values: sqlite, postgres, memory." yaml:"driver,omitempty"`
	Path   string `description:"The path to the SQLite database file, or connection URL when driver is postgres." yaml:"path,omitempty"`
}

type AnalyticsConfig struct {
	Enabled bool `description:"Enable periodic version information collection." yaml:"enabled,omitempty"`
}

type ResourcesConfig struct {
	Enabled bool   `description:"Enable the resources server." yaml:"enabled,omitempty"`
	Path    string `description:"The directory where resources are stored." yaml:"path,omitempty"`
}

type ServerConfig struct {
	Port       int    `description:"The port on which the server listens." yaml:"port,omitempty"`
	Address    string `description:"The address on which the server listens." yaml:"address,omitempty"`
	SocketPath string `description:"The path to the Unix socket." yaml:"socketPath,omitempty"`
}

type AuthConfig struct {
	IP                 IPConfig                  `description:"IP whitelisting config options." yaml:"ip,omitempty"`
	Users              []string                  `description:"Comma-separated list of users (username:hashed_password)." yaml:"users,omitempty"`
	SubdomainsEnabled  bool                      `description:"Enable subdomains support." yaml:"subdomainsEnabled,omitempty"`
	UserAttributes     map[string]UserAttributes `description:"Map of per-user OIDC attributes (username -> attributes)." yaml:"userAttributes,omitempty"`
	UsersFile          string                    `description:"Path to the users file." yaml:"usersFile,omitempty"`
	SecureCookie       bool                      `description:"Enable secure cookies." yaml:"secureCookie,omitempty"`
	SessionExpiry      int                       `description:"Session expiry time in seconds." yaml:"sessionExpiry,omitempty"`
	SessionMaxLifetime int                       `description:"Maximum session lifetime in seconds." yaml:"sessionMaxLifetime,omitempty"`
	LoginTimeout       int                       `description:"Login timeout in seconds." yaml:"loginTimeout,omitempty"`
	LoginMaxRetries    int                       `description:"Maximum login retries." yaml:"loginMaxRetries,omitempty"`
	LockdownEnabled    bool                      `description:"Enable lockdown mode after maximum login retries. Lockdown mode limit is calculated automatically." yaml:"lockdownEnabled,omitempty"`
	TrustedProxies     []string                  `description:"Comma-separated list of trusted proxy addresses." yaml:"trustedProxies,omitempty"`
	ACLs               ACLsConfig                `description:"ACLs configuration." yaml:"acls,omitempty"`
}

type UserAttributes struct {
	Name        string       `description:"Full name of the user." yaml:"name,omitempty"`
	GivenName   string       `description:"Given (first) name of the user." yaml:"givenName,omitempty"`
	FamilyName  string       `description:"Family (last) name of the user." yaml:"familyName,omitempty"`
	MiddleName  string       `description:"Middle name of the user." yaml:"middleName,omitempty"`
	Nickname    string       `description:"Nickname of the user." yaml:"nickname,omitempty"`
	Profile     string       `description:"URL of the user's profile page." yaml:"profile,omitempty"`
	Picture     string       `description:"URL of the user's profile picture." yaml:"picture,omitempty"`
	Website     string       `description:"URL of the user's website." yaml:"website,omitempty"`
	Email       string       `description:"Email address of the user." yaml:"email,omitempty"`
	Gender      string       `description:"Gender of the user." yaml:"gender,omitempty"`
	Birthdate   string       `description:"Birthdate of the user (YYYY-MM-DD)." yaml:"birthdate,omitempty"`
	Zoneinfo    string       `description:"Time zone of the user (e.g. Europe/Athens)." yaml:"zoneinfo,omitempty"`
	Locale      string       `description:"Locale of the user (e.g. en-US)." yaml:"locale,omitempty"`
	PhoneNumber string       `description:"Phone number of the user." yaml:"phoneNumber,omitempty"`
	Address     AddressClaim `description:"Address of the user." yaml:"address,omitempty"`
}

type AddressClaim struct {
	Formatted     string `description:"Full mailing address, formatted for display." yaml:"formatted,omitempty" json:"formatted,omitempty"`
	StreetAddress string `description:"Street address." yaml:"streetAddress,omitempty" json:"street_address,omitempty"`
	Locality      string `description:"City or locality." yaml:"locality,omitempty" json:"locality,omitempty"`
	Region        string `description:"State, province, or region." yaml:"region,omitempty" json:"region,omitempty"`
	PostalCode    string `description:"Zip or postal code." yaml:"postalCode,omitempty" json:"postal_code,omitempty"`
	Country       string `description:"Country." yaml:"country,omitempty" json:"country,omitempty"`
}

type IPConfig struct {
	Allow  []string `description:"List of allowed IPs or CIDR ranges." yaml:"allow,omitempty"`
	Block  []string `description:"List of blocked IPs or CIDR ranges." yaml:"block,omitempty"`
	Bypass []string `description:"List of IPs or CIDR ranges that bypass authentication entirely." yaml:"bypass,omitempty"`
}

type OAuthConfig struct {
	Whitelist     []string                      `description:"Comma-separated list of allowed OAuth domains." yaml:"whitelist,omitempty"`
	WhitelistFile string                        `description:"Path to the OAuth whitelist file." yaml:"whitelistFile,omitempty"`
	AutoRedirect  string                        `description:"The OAuth provider to use for automatic redirection." yaml:"autoRedirect,omitempty"`
	Providers     map[string]OAuthServiceConfig `description:"OAuth providers configuration." yaml:"providers,omitempty"`
}

type OIDCConfig struct {
	PrivateKeyPath string                      `description:"Path to the private key file, including file name." yaml:"privateKeyPath,omitempty"`
	PublicKeyPath  string                      `description:"Path to the public key file, including file name." yaml:"publicKeyPath,omitempty"`
	Clients        map[string]OIDCClientConfig `description:"OIDC clients configuration." yaml:"clients,omitempty"`
}

type UIConfig struct {
	Title                 string `description:"The title of the UI." yaml:"title,omitempty"`
	ForgotPasswordMessage string `description:"Message displayed on the forgot password page." yaml:"forgotPasswordMessage,omitempty"`
	BackgroundImage       string `description:"Path to the background image." yaml:"backgroundImage,omitempty"`
	WarningsEnabled       bool   `description:"Enable UI warnings." yaml:"warningsEnabled,omitempty"`
}

type LDAPConfig struct {
	Address          string `description:"LDAP server address." yaml:"address,omitempty"`
	BindDN           string `description:"Bind DN for LDAP authentication." yaml:"bindDn,omitempty"`
	BindPassword     string `description:"Bind password for LDAP authentication." yaml:"bindPassword,omitempty"`
	BindPasswordFile string `description:"Path to the Bind password." yaml:"bindPasswordFile,omitempty"`
	BaseDN           string `description:"Base DN for LDAP searches." yaml:"baseDn,omitempty"`
	Insecure         bool   `description:"Allow insecure LDAP connections." yaml:"insecure,omitempty"`
	SearchFilter     string `description:"LDAP search filter." yaml:"searchFilter,omitempty"`
	AuthCert         string `description:"Certificate for mTLS authentication." yaml:"authCert,omitempty"`
	AuthKey          string `description:"Certificate key for mTLS authentication." yaml:"authKey,omitempty"`
	GroupCacheTTL    int    `description:"Cache duration for LDAP group membership in seconds." yaml:"groupCacheTTL,omitempty"`
}

type LogConfig struct {
	Level   string     `description:"Log level (trace, debug, info, warn, error)." yaml:"level,omitempty"`
	Json    bool       `description:"Enable JSON formatted logs." yaml:"json,omitempty"`
	Streams LogStreams `description:"Configuration for specific log streams." yaml:"streams,omitempty"`
}

type LogStreams struct {
	HTTP  LogStreamConfig `description:"HTTP request logging." yaml:"http,omitempty"`
	App   LogStreamConfig `description:"Application logging." yaml:"app,omitempty"`
	Audit LogStreamConfig `description:"Audit logging." yaml:"audit,omitempty"`
}

type LogStreamConfig struct {
	Enabled bool   `description:"Enable this log stream." yaml:"enabled,omitempty"`
	Level   string `description:"Log level for this stream. Use global if empty." yaml:"level,omitempty"`
}

// no experimental features
type ExperimentalConfig struct{}

type TailscaleConfig struct {
	Enabled   bool   `description:"Enable Tailscale integration." yaml:"enabled,omitempty"`
	Dir       string `description:"Tailscale state directory." yaml:"dir,omitempty"`
	Hostname  string `description:"Tailscale hostname." yaml:"hostname,omitempty"`
	AuthKey   string `description:"Tailscale auth key." yaml:"authKey,omitempty"`
	Ephemeral bool   `description:"Use ephemeral Tailscale node." yaml:"ephemeral,omitempty"`
	Funnel    bool   `description:"Enable Tailscale Funnel." yaml:"funnel,omitempty"`
	Listen    bool   `description:"Listen on the Tailscale address instead of standard address." yaml:"listen,omitempty"`
}

// OAuth/OIDC config

type OAuthServiceConfig struct {
	ClientID         string   `description:"OAuth client ID." yaml:"clientId,omitempty"`
	ClientSecret     string   `description:"OAuth client secret." yaml:"clientSecret,omitempty"`
	ClientSecretFile string   `description:"Path to the file containing the OAuth client secret." yaml:"clientSecretFile,omitempty"`
	Whitelist        []string `description:"Comma-separated list of allowed OAuth domains for this provider." yaml:"whitelist,omitempty"`
	WhitelistFile    string   `description:"Path to the OAuth whitelist file for this provider." yaml:"whitelistFile,omitempty"`
	Scopes           []string `description:"OAuth scopes." yaml:"scopes,omitempty"`
	RedirectURL      string   `description:"OAuth redirect URL." yaml:"redirectUrl,omitempty"`
	AuthURL          string   `description:"OAuth authorization URL." yaml:"authUrl,omitempty"`
	TokenURL         string   `description:"OAuth token URL." yaml:"tokenUrl,omitempty"`
	UserinfoURL      string   `description:"OAuth userinfo URL." yaml:"userinfoUrl,omitempty"`
	Insecure         bool     `description:"Allow insecure OAuth connections." yaml:"insecure,omitempty"`
	Name             string   `description:"Provider name in UI." yaml:"name,omitempty"`
}

type OIDCClientConfig struct {
	ID                  string   `description:"OIDC client ID." yaml:"-"`
	ClientID            string   `description:"OIDC client ID." yaml:"clientId,omitempty"`
	ClientSecret        string   `description:"OIDC client secret." yaml:"clientSecret,omitempty"`
	ClientSecretFile    string   `description:"Path to the file containing the OIDC client secret." yaml:"clientSecretFile,omitempty"`
	TrustedRedirectURIs []string `description:"List of trusted redirect URIs." yaml:"trustedRedirectUris,omitempty"`
	Name                string   `description:"Client name in UI." yaml:"name,omitempty"`
}

type ACLsConfig struct {
	Policy string `description:"ACL policy for allow-by-default or deny-by-default, available options are allow and deny, default is allow." yaml:"policy,omitempty"`
}

// ACLs

type Apps struct {
	Apps map[string]App `description:"App ACLs configuration." yaml:"apps,omitempty"`
}

type App struct {
	Config   AppConfig   `description:"App configuration." yaml:"config,omitempty"`
	Users    AppUsers    `description:"User access configuration." yaml:"users,omitempty"`
	OAuth    AppOAuth    `description:"OAuth access configuration." yaml:"oauth,omitempty"`
	IP       AppIP       `description:"IP access configuration." yaml:"ip,omitempty"`
	Response AppResponse `description:"Response customization." yaml:"response,omitempty"`
	Path     AppPath     `description:"Path access configuration." yaml:"path,omitempty"`
	LDAP     AppLDAP     `description:"LDAP access configuration." yaml:"ldap,omitempty"`
}

type AppConfig struct {
	Domain string `description:"The domain of the app." yaml:"domain,omitempty"`
}

type AppUsers struct {
	Allow string `description:"Comma-separated list of allowed users." yaml:"allow,omitempty"`
	Block string `description:"Comma-separated list of blocked users." yaml:"block,omitempty"`
}

type AppOAuth struct {
	Whitelist string `description:"Comma-separated list of allowed OAuth groups." yaml:"whitelist,omitempty"`
	Groups    string `description:"Comma-separated list of required OAuth groups." yaml:"groups,omitempty"`
}

type AppLDAP struct {
	Groups string `description:"Comma-separated list of required LDAP groups." yaml:"groups,omitempty"`
}

type AppIP struct {
	Allow  []string `description:"List of allowed IPs or CIDR ranges." yaml:"allow,omitempty"`
	Block  []string `description:"List of blocked IPs or CIDR ranges." yaml:"block,omitempty"`
	Bypass []string `description:"List of IPs or CIDR ranges that bypass authentication." yaml:"bypass,omitempty"`
}

type AppResponse struct {
	Headers   []string     `description:"Custom headers to add to the response." yaml:"headers,omitempty"`
	BasicAuth AppBasicAuth `description:"Basic authentication for the app." yaml:"basicAuth,omitempty"`
}

type AppBasicAuth struct {
	Username     string `description:"Basic auth username." yaml:"username,omitempty"`
	Password     string `description:"Basic auth password." yaml:"password,omitempty"`
	PasswordFile string `description:"Path to the file containing the basic auth password." yaml:"passwordFile,omitempty"`
}

type AppPath struct {
	Allow string `description:"Comma-separated list of allowed paths." yaml:"allow,omitempty"`
	Block string `description:"Comma-separated list of blocked paths." yaml:"block,omitempty"`
}
