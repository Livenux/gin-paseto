package ginpaseto

import "time"

type Maker interface {
	// CreateToken create a new token for authentication data and time duration
	CreateToken(claims *Claims) (token string, err error)
	// VerifyToken check if the token is verified or not
	VerifyToken(token string) (*Claims, error)
	// RefreshToken refresh token on Claims.MaxRefreshAt before
	RefreshToken(claims *Claims, duration time.Duration) (token string, err error)
}
