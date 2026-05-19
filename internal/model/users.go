package model

type UserSearchType int

const (
	UserLocal UserSearchType = iota
	UserLDAP
)

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
