package request

import "net/mail"

type Login struct {
	Email    mail.Address `json:"email,omitempty"`
	Username string       `json:"username,omitempty"`
	Password string       `json:"password"`
}

type Registration struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
}
