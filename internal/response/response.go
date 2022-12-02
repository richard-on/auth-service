package response

import (
	"time"
)

type LoginSuccess struct {
	Email     string    `json:"email,omitempty"`
	Username  string    `json:"username,omitempty"`
	LastLogin time.Time `json:"lastLogin"`
}

type RegistrationSuccess struct {
	Email    string `json:"email,omitempty"`
	Username string `json:"username,omitempty"`
}

type ValidateSuccess struct {
	Username string `json:"username"`
}

type InfoSuccess struct {
	Email     string    `json:"email,omitempty"`
	Username  string    `json:"username,omitempty"`
	LastLogin time.Time `json:"lastLogin"`
}

type LogoutSuccess struct {
}

type Error struct {
	Error string `json:"error"`
}
