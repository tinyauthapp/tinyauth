package model

type UserSearchType int

const (
	UserLocal UserSearchType = iota
	UserLDAP
)

func (t UserSearchType) String() string {
	switch t {
	case UserLocal:
		return "local"
	case UserLDAP:
		return "ldap"
	}
	return "unknown"
}

type LDAPUser struct {
	DN     string
	Groups []string
}

type LocalUser struct {
	Username   string
	Password   string
	TOTPSecret string
	Attributes UserAttributes
}

type UserSearch struct {
	Username string
	Email    string // used for LDAP, we can't throw it to LDAPUser because it would need another cache or an LDAP lookup every time
	Type     UserSearchType
}
