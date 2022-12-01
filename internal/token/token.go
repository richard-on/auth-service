// Package token implements interface, struct and methods used to work with JWT tokens
package token

import (
	"errors"
	"fmt"
	"github.com/getsentry/sentry-go"
	"github.com/golang-jwt/jwt/v4"
	"github.com/richard-on/auth-service/config"
	"github.com/rs/zerolog/log"
	"strings"
	"time"
)

// Token interface wraps custom methods used to work with JWT tokens.
type Token interface {
	Check() error
	Parse() (*jwt.MapClaims, error)
	GetRaw() string
}

// JwtToken is a wrapper for jwt.Token.
type JwtToken struct {
	Token *jwt.Token
	// TokenString string     // Raw token
}

// NewToken creates Token from jwt.MapClaims
func NewToken(claims *jwt.MapClaims, ttl int64) (Token, error) {
	if ttl <= 0 {
		sentry.CaptureException(ErrIncorrectTTL)
		ttl = config.TTL.Access
	}

	// Or we can use time.Now().Add(time.Second * time.Duration(expiryAfter)).UTC().Unix()
	(*claims)["exp"] = time.Now().UTC().Unix() + ttl

	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Our signed JWT token string
	var err error
	t.Raw, err = t.SignedString([]byte(config.Secret))
	if err != nil {
		return &JwtToken{}, errors.New("error creating a token")
	}

	return &JwtToken{
		Token: t,
	}, nil
}

// Check parses jwt.Token and returns nil if it is valid.
// This method is similar to Parse, except it doesn't return mapClaims.
func (t *JwtToken) Check() error {
	if len(strings.Split(t.Token.Raw, ".")) != 3 {
		return ErrInvalidToken
	}

	token, err := jwt.Parse(t.Token.Raw,
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, ErrIncorrectSigningMethod
			}

			return []byte(config.Secret), nil
		},
	)
	if err != nil {
		sentry.CaptureException(err)
		log.Error().Err(err)
		return err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return ErrInvalidToken
	}

	if expiresAt, ok := claims["exp"]; ok && int64(expiresAt.(float64)) < time.Now().UTC().Unix() {
		return ErrExpiredToken
	}

	return nil
}

// Parse parses jwt.Token and returns *jwt.MapClams for JSON decoding.
func (t *JwtToken) Parse() (*jwt.MapClaims, error) {
	token, err := jwt.Parse(t.Token.Raw,
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			return []byte(config.Secret), nil
		},
	)

	if err != nil {
		return nil, ErrParseToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !(ok && token.Valid) {
		return nil, ErrInvalidToken
	}

	if expiresAt, ok := claims["exp"]; ok && int64(expiresAt.(float64)) < time.Now().UTC().Unix() {
		return nil, ErrExpiredToken
	}

	return &claims, nil
}

// GetRaw returns raw jwt.Token.
func (t *JwtToken) GetRaw() string {
	return t.Token.Raw
}
