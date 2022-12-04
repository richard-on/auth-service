package response

type LoginSuccess struct {
	Email     string `json:"email,omitempty"`
	Username  string `json:"username,omitempty"`
	LastLogin string `json:"lastLogin,omitempty"`
}

type RegistrationSuccess struct {
	Email    string `json:"email,omitempty"`
	Username string `json:"username,omitempty"`
}

type ValidateSuccess struct {
	Email    string `json:"email,omitempty"`
	Username string `json:"username,omitempty"`
}

type InfoSuccess struct {
	Email     string `json:"email,omitempty"`
	Username  string `json:"username,omitempty"`
	LastLogin string `json:"lastLogin,omitempty"`
}

type LogoutSuccess struct {
	Message string `json:"message,omitempty"`
}

type Error struct {
	Error string `json:"error"`
}
