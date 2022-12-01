package db

import "errors"

// ErrInvalidLogin indicates that a login did not pass regex check and can't be used.
var ErrInvalidLogin = errors.New("this login is not valid. Logins must be 5-20 char long ")

// ErrUserAlreadyExists indicates that a user with this login already exists.
var ErrUserAlreadyExists = errors.New("user with this login already exists")

// ErrBadCredentials indicates that a user with this login does not exist or that password hashes do not match.
var ErrBadCredentials = errors.New("invalid login or password")
