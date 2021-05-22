package model

import (
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/0xTatsu/mvtn-api/jwt"
)

const (
	RoleUser = "user"
)

type Account struct {
	ID       int64    `json:"id"`
	Password string   `json:"-"`
	Email    string   `json:"email"`
	Active   bool     `json:"active"`
	Roles    []string `json:"roles,omitempty" pg:",array"`

	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`

	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	LastLogin time.Time `json:"last_login,omitempty"`
}

// CanLogin returns true if user is allowed to login.
func (a *Account) CanLogin() bool {
	return a.Active
}

func (a *Account) IsValidPassword(password string) bool {
	if err := bcrypt.CompareHashAndPassword([]byte(a.Password), []byte(password)); err != nil {
		return false
	}

	return true
}

// Claims returns the account's claims to be signed
func (a *Account) Claims() jwt.AccessClaims {
	return jwt.AccessClaims{
		ID:    a.ID,
		Roles: a.Roles,
	}
}
