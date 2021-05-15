package jwt

import (
	"errors"

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

// AppClaims represent the claims parsed from JWT access token.
type AppClaims struct {
	ID    int      `json:"id,omitempty"`
	Sub   string   `json:"sub,omitempty"`
	Roles []string `json:"roles,omitempty"`
	StandardClaims
}

// ParseClaims parses JWT claims into AppClaims.
func (c *AppClaims) ParseClaims(claims jwt.MapClaims) error {
	id, ok := claims["id"]
	if !ok {
		return errors.New("could not parse claim id")
	}
	c.ID = int(id.(float64))

	sub, ok := claims["sub"]
	if !ok {
		return errors.New("could not parse claim sub")
	}
	c.Sub = sub.(string)

	rl, ok := claims["roles"]
	if !ok {
		return errors.New("could not parse claims roles")
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
	ID    int    `json:"id,omitempty"`
	Token string `json:"token,omitempty"`
	StandardClaims
}

// ParseClaims parses the JWT claims into RefreshClaims.
func (c *RefreshClaims) ParseClaims(claims jwt.MapClaims) error {
	token, ok := claims["token"]
	if !ok {
		return errors.New("could not parse claim token")
	}
	c.Token = token.(string)
	return nil
}
