package model

import (
	"time"

	"github.com/0xTatsu/mvtn-api/auth/jwt"
)

const (
	RoleUser = "user"
)

type Account struct {
	ID        int64     `json:"id"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	LastLogin time.Time `json:"last_login,omitempty"`

	Email  string   `json:"email"`
	Active bool     `sql:",notnull" json:"active"`
	Roles  []string `pg:",array" json:"roles,omitempty"`
}

// CanLogin returns true if user is allowed to login.
func (a *Account) CanLogin() bool {
	return a.Active
}

// Claims returns the account's claims to be signed
func (a *Account) Claims() jwt.AccessClaims {
	return jwt.AccessClaims{
		ID:    a.ID,
		Roles: a.Roles,
	}
}
