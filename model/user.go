package model

import (
	"time"

	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/0xTatsu/g-api/jwt"
)

const (
	RoleUser = "user"
)

type User struct {
	ID        uint           `json:"id" gorm:"primaryKey"`
	CreatedAt time.Time      `json:"-"`
	UpdatedAt time.Time      `json:"-"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`

	Password  string         `json:"-"`
	Name      string         `json:"name"`
	Email     string         `json:"email" gorm:"uniqueIndex;not null"`
	Active    bool           `json:"active"`
	Roles     pq.StringArray `json:"roles" gorm:"type:text[]"`
	Birthday  *time.Time     `json:"birthday"`
	LastLogin time.Time      `json:"last_login"`

	AccessToken  string `json:"access_token" gorm:"-"`
	RefreshToken string `json:"refresh_token" gorm:"-"`
}

// CanLogin returns true if user is allowed to login.
func (a *User) CanLogin() bool {
	return a.Active && !a.DeletedAt.Valid
}

func (a *User) IsValidPassword(password string) bool {
	if err := bcrypt.CompareHashAndPassword([]byte(a.Password), []byte(password)); err != nil {
		return false
	}

	return true
}

// AccessClaims returns the user's claims to be signed
func (a *User) AccessClaims() jwt.AccessClaims {
	return jwt.AccessClaims{
		ID:    a.ID,
		Roles: a.Roles,
	}
}
