package jwt

import (
	"errors"
	"fmt"

	"github.com/dgrijalva/jwt-go"
)

// StandardClaims https://tools.ietf.org/html/rfc7519#section-4.1
type StandardClaims struct {
	Audience  string `json:"aud,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	JwtID     string `json:"jti,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
	Subject   string `json:"sub,omitempty"`
}

// AccessClaims represent the claims parsed from JWT access token.
type AccessClaims struct {
	ID    uint     `json:"id,omitempty"`
	Sub   string   `json:"sub,omitempty"`
	Roles []string `json:"roles,omitempty"`
	StandardClaims
}

var (
	ErrIDInvalid   = errors.New("id is invalid")
	ErrRoleInvalid = errors.New("roles is invalid")
)

// ParseClaims parses JWT claims into AccessClaims.
func (c *AccessClaims) ParseClaims(claims jwt.MapClaims) error {
	id, exist := claims["id"]
	if !exist {
		return fmt.Errorf("access claims: %w", ErrIDInvalid)
	}
	c.ID = uint(id.(float64))

	// sub, exist := claims["sub"]
	// if !exist {
	// 	return errors.New("could not parse claim sub")
	// }
	// c.Sub = sub.(string)

	rl, exist := claims["roles"]
	if !exist {
		return fmt.Errorf("access claims: %w", ErrRoleInvalid)
	}

	var roles []string
	if rl != nil {
		for _, v := range rl.([]interface{}) {
			roles = append(roles, v.(string))
		}
	}
	c.Roles = roles

	return nil
}

// RefreshClaims represents the claims parsed from JWT refresh token.
type RefreshClaims struct {
	ID uint `json:"id,omitempty"`
	StandardClaims
}

// ParseClaims parses the JWT claims into RefreshClaims.
func (c *RefreshClaims) ParseClaims(claims jwt.MapClaims) error {
	id, exist := claims["id"]
	if !exist {
		return fmt.Errorf("refresh claims: %w", ErrIDInvalid)
	}
	c.ID = uint(id.(float64))

	return nil
}
