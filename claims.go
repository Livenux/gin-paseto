package ginpaseto

import (
	"errors"
	"time"
)

var (
	ErrTokenExpired    = errors.New("token has expired")
	ErrTokenMaxRefresh = errors.New("token is expired max refresh time")
)

type Claims struct {
	Issuer       string    `json:"issuer,omitempty"`
	Subject      string    `json:"subject,omitempty"`
	Audience     string    `json:"audience,omitempty"`
	IssuedAt     time.Time `json:"issued_at"`
	ExpiredAt    time.Time `json:"expired_at"`
	MaxRefreshAt time.Time `json:"max_refresh_at"`
	Data         any       `json:"data"`
}

type ClaimsOption = func(c *Claims)

// WithClaimsOption options with issuer, subject audience
func WithClaimsOption(issuer, subject, audience string) ClaimsOption {
	return func(c *Claims) {
		c.Issuer = issuer
		c.Subject = subject
		c.Audience = audience
	}
}

// NewClaims create a new token payload with data and duration
func NewClaims(expired, maxRefresh time.Duration, opts ...ClaimsOption) *Claims {
	c := &Claims{
		IssuedAt:     time.Now().UTC(),
		ExpiredAt:    time.Now().UTC().Add(expired),
		MaxRefreshAt: time.Now().UTC().Add(maxRefresh),
	}

	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Valid checks token has expired
func (c *Claims) Valid() error {
	now := time.Now().UTC()
	if now.After(c.MaxRefreshAt) {
		return ErrTokenMaxRefresh
	}

	if now.After(c.ExpiredAt) {
		return ErrTokenExpired
	}

	return nil
}
