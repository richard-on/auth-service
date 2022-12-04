// Package token implements interface, struct and methods used to work with JWT tokens
package token

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"

	"github.com/richard-on/auth-service/config"
)

// EncryptedJWT is a wrapper for encrypted token and its key
type EncryptedJWT struct {
	EncryptedToken string
	Key            string
}

// NewEncryptedToken creates and encrypts a Token from user info, TTL and encryption key
func NewEncryptedToken(id, email, username string, ttl int64, key string) (EncryptedJWT, error) {
	if ttl <= 0 {
		ttl = config.TTL.Access
	}

	claims := &jwt.MapClaims{
		"id":       id,
		"email":    email,
		"username": username,
	}

	// Or we can use time.Now().Add(time.Second * time.Duration(expiryAfter)).UTC().Unix()
	(*claims)["exp"] = time.Now().UTC().Unix() + ttl

	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Our signed JWT token string
	var err error
	t.Raw, err = t.SignedString([]byte(config.Secret))
	if err != nil {
		return EncryptedJWT{}, errors.New("error creating a token")
	}

	encrypted, err := EncryptToken(t.Raw, key)
	if err != nil {
		return EncryptedJWT{}, errors.New("error encrypting a token")
	}

	return EncryptedJWT{
		EncryptedToken: encrypted,
	}, nil
}

// Check parses jwt.Token and returns nil if it is valid.
// This method is similar to Parse, except it doesn't return mapClaims.
func (t *EncryptedJWT) Check() error {

	if t.EncryptedToken == "" {
		return ErrNoToken
	}

	tokenRaw, err := DecryptToken(t.EncryptedToken, t.Key)
	if err != nil {
		return err
	}

	if len(strings.Split(tokenRaw, ".")) != 3 {
		return ErrInvalidToken
	}

	token, err := jwt.Parse(tokenRaw,
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
func (t *EncryptedJWT) Parse() (*jwt.MapClaims, error) {

	tokenRaw, err := DecryptToken(t.EncryptedToken, t.Key)
	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse(tokenRaw,
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
