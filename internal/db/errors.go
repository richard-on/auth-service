package db

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrInvalidLogin indicates that a login did not pass regex check and can't be used.
var ErrInvalidLogin = status.Error(codes.Canceled, "this login is not valid. Logins must be 5-20 char long")

// ErrUserAlreadyExists indicates that a user with this login already exists.
var ErrUserAlreadyExists = status.Error(codes.AlreadyExists, "user with this login already exists")

// ErrBadCredentials indicates that a user with this login does not exist or that password hashes do not match.
var ErrBadCredentials = status.Error(codes.Unauthenticated, "invalid username or password")
