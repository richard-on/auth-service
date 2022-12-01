package response

type LoginResponse struct {
	Username     string `json:"username"`
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type ValidateResponse struct {
	Username string `json:"username"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type LogoutResponse struct {
}
