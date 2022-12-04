package token

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var ErrNoToken = status.Error(codes.PermissionDenied, "token is empty")

// ErrParseToken indicates that the token cannot be parsed. Returned status code is 500.
var ErrParseToken = status.Error(codes.PermissionDenied, "token cannot be parsed")

// ErrInvalidToken indicates that the token is invalid. Returned status code is 403.
var ErrInvalidToken = status.Error(codes.PermissionDenied, "invalid token")

// ErrExpiredToken indicates that the token has expired. Returned status code is 403.
var ErrExpiredToken = status.Error(codes.PermissionDenied, "expired token")

// ErrIncorrectSigningMethod indicates that the token was signed using incorrect method. Returned status code is 403.
//
// Tokens should be signed with jwt.SigningMethodHMAC.
var ErrIncorrectSigningMethod = status.Error(codes.PermissionDenied, "incorrect signing method")

var ErrIncorrectTTL = status.Error(codes.InvalidArgument, "TTL is less than or equal to 0")
