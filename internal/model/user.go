package model

import (
	"time"
)

// User represents clients who are authorized to use the service.
type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	LastLogin time.Time `json:"lastLogin"`
}
