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
	Name   string
	Email  string
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
	Type     UserSearchType
}
