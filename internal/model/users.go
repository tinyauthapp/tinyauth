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
	Type     UserSearchType
}
