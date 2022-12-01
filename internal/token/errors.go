package token

import (
	"fmt"
	"github.com/gofiber/fiber/v2"
)

// Error TokenError records failed token validation.
type Error struct {
	StatusCode int   // StatusCode is a value that server will return when this error happens.
	Err        error // Err is the underlying error.
}

func (e Error) Error() string {
	return fmt.Sprintf("code %d, %s", e.StatusCode, e.Err)
}

// ErrParseToken indicates that the token cannot be parsed. Returned status code is 500.
var ErrParseToken = Error{StatusCode: fiber.StatusInternalServerError, Err: fmt.Errorf("error parsing token")}

// ErrInvalidToken indicates that the token is invalid. Returned status code is 403.
var ErrInvalidToken = Error{StatusCode: fiber.StatusForbidden, Err: fmt.Errorf("invalid token")}

// ErrExpiredToken indicates that the token has expired. Returned status code is 403.
var ErrExpiredToken = Error{StatusCode: fiber.StatusForbidden, Err: fmt.Errorf("token has expired")}

// ErrIncorrectSigningMethod indicates that the token was signed using incorrect method. Returned status code is 403.
//
// Tokens should be signed with jwt.SigningMethodHMAC.
var ErrIncorrectSigningMethod = Error{
	StatusCode: fiber.StatusForbidden,
	Err:        fmt.Errorf("incorrect signing method"),
}

var ErrIncorrectTTL = Error{StatusCode: fiber.StatusContinue, Err: fmt.Errorf("TTL is less or equal to zero")}
