// Package handlers contains handlers for all Auth API endpoints.
package handlers

import (
	"database/sql"
	"encoding/base64"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	_ "github.com/lib/pq"
	"github.com/richard-on/auth-service/config"
	"github.com/richard-on/auth-service/internal/db"
	"github.com/richard-on/auth-service/internal/model"
	"github.com/richard-on/auth-service/internal/request"
	"github.com/richard-on/auth-service/internal/response"
	"github.com/richard-on/auth-service/internal/token"
	"github.com/richard-on/auth-service/pkg/authService"
	"github.com/richard-on/auth-service/pkg/cookie"
	"github.com/richard-on/auth-service/pkg/logger"
	"strings"
)

type AuthHandler struct {
	Router      fiber.Router
	AuthService authService.AuthServiceClient
	log         logger.Logger
}

func NewAuthHandler(router fiber.Router, authService authService.AuthServiceClient) *AuthHandler {
	return &AuthHandler{
		Router:      router,
		AuthService: authService,
		log:         logger.NewLogger(config.DefaultWriter, config.LogInfo.Level, "auth-handler"),
	}
}

// Login handles GET-request on /login endpoint. It checks login and password and sets access and refresh cookie.
//
// Login accepts both Basic auth and login info in request body. If no Authorization header was found in request header,
// body will be checked for login and password.
//
// @Summary      Login
// @Tags         Auth
// @Description  Login to an account
// @ID           login-account
// @Accept       json
// @Produce      json
// @Param        input    body      request.LoginRequest  true  "Account info"
// @Success      200      {object}  response.LoginResponse
// @Failure      403,500  {object}  response.ErrorResponse
// @Router       /v1/login [post]
func (h *AuthHandler) Login(ctx *fiber.Ctx) error {
	dbConn, err := sql.Open("postgres", config.DbConnString)
	if err != nil {
		h.log.Fatal(err, "error while opening db connection")
	}
	defer func(dbConn *sql.DB) {
		err = dbConn.Close()
		if err != nil {
			h.log.Fatal(err, "error while closing db connection")
		}
	}(dbConn)

	userDb := db.NewDatabase(dbConn)

	var user model.User

	// Check if request header contains Authorization field
	authHeader := ctx.GetReqHeaders()["Authorization"]
	if authHeader == "" {
		// If no Authorization info was found in header, expect login info in request body as required by v1.0
		if err = ctx.BodyParser(&user); err != nil {
			h.log.Debugf("body parsing error: %v", err)
			return ctx.Status(fiber.StatusBadRequest).JSON(response.Error{Error: err.Error()})
		}

	} else {
		// If Authorization info was found in header, assume it is v1.1
		authStr := strings.Split(authHeader, " ")

		// Only support Basic authentication
		if authStr[0] != "Basic" {
			h.log.Debug(ErrUnsupportedAuthMethod)

			return ctx.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": ErrUnsupportedAuthMethod.Error(),
			})
		}

		// Decode base64 auth info
		decoded, err := base64.StdEncoding.DecodeString(authStr[1])
		if err != nil {
			h.log.Error(err, "error decoding base64-encoded auth info")

			return ctx.Status(fiber.StatusInternalServerError).JSON(response.Error{Error: err.Error()})
		}

		// Split user credentials
		userCredentials := strings.Split(string(decoded), ":")

		// Check that userCredentials contains only 2 elements (login and password)
		if len(userCredentials) != 2 {
			h.log.Debug(ErrIncorrectCredentialsFormat)

			return ctx.Status(fiber.StatusForbidden).JSON(response.Error{
				Error: ErrIncorrectCredentialsFormat.Error(),
			})
		}

		user.Username = userCredentials[0]
		user.Password = userCredentials[1]
	}

	// Searching for user in DB
	err = userDb.GetUser(&user)
	if err != nil {
		h.log.Debug(err)

		return ctx.Status(fiber.StatusForbidden).JSON(response.Error{Error: err.Error()})
	}

	accessToken, err := token.NewToken(&jwt.MapClaims{
		"username": user.Username,
	}, config.TTL.Access)

	if err != nil {
		h.log.Error(err, "error while creating access token")

		return ctx.Status(fiber.StatusInternalServerError).JSON(response.Error{Error: err.Error()})
	}

	refreshToken, err := token.NewToken(&jwt.MapClaims{
		"username": user.Username,
	}, config.TTL.Refresh)

	if err != nil {
		h.log.Error(err, "error while creating refresh token")

		return ctx.Status(fiber.StatusInternalServerError).JSON(response.Error{Error: err.Error()})
	}

	// Access token cookie
	cookie.SetCookie(ctx, "accessToken", accessToken.GetRaw(), config.TTL.Access)

	// Refresh token cookie
	cookie.SetCookie(ctx, "refreshToken", refreshToken.GetRaw(), config.TTL.Refresh)

	// If there's redirect_uri param then sending redirect command
	if redirectURI := ctx.Query("redirect_uri"); redirectURI != "" {
		return ctx.Redirect(redirectURI)
	}

	return ctx.Status(fiber.StatusOK).JSON(response.LoginSuccess{
		Username:  user.Username,
		LastLogin: user.LastLogin,
	})
}

// Validate
// @Summary      Validate
// @Tags         Auth
// @Description  This route validates tokens and returns user info
// @ID           validate
// @Produce      json
// @Success      200          {object}  response.ValidateResponse
// @Failure      401,403,500  {object}  response.ErrorResponse
// @Router       /auth/v1/validate [post]
func (h *AuthHandler) Validate(ctx *fiber.Ctx) error {
	validateRequest := &authService.ValidateRequest{
		AccessToken:  ctx.Cookies("accessToken"),
		RefreshToken: ctx.Cookies("refreshToken"),
	}

	validateResponse, err := h.AuthService.Validate(ctx.Context(), validateRequest)
	if err != nil {
		h.log.Error(err, "validation error")

		return ctx.Status(fiber.StatusForbidden).JSON(response.Error{Error: err.Error()})
	}

	// Getting access and refresh tokens TTL
	accessTokenTTL := config.TTL.Access
	refreshTokenTTL := config.TTL.Refresh

	switch validateResponse.TokenStatus {
	case authService.ValidateResponse_UPDATE_ALL:
		cookie.SetCookie(ctx, "accessToken", validateResponse.AccessToken, accessTokenTTL)
		cookie.SetCookie(ctx, "refreshToken", validateResponse.RefreshToken, refreshTokenTTL)
	case authService.ValidateResponse_UPDATE_ACCESS:
		cookie.SetCookie(ctx, "accessToken", validateResponse.AccessToken, accessTokenTTL)
	case authService.ValidateResponse_UPDATE_REFRESH:
		cookie.SetCookie(ctx, "refreshToken", validateResponse.RefreshToken, refreshTokenTTL)
	case authService.ValidateResponse_OK:
		break
	default:
		cookie.SetCookie(ctx, "accessToken", validateResponse.AccessToken, accessTokenTTL)
		cookie.SetCookie(ctx, "refreshToken", validateResponse.RefreshToken, refreshTokenTTL)
	}

	return ctx.Status(fiber.StatusOK).JSON(response.ValidateSuccess{Username: validateResponse.Username})
}

// Logout
// @Summary      Logout
// @Tags         Auth
// @Description  Logout from account
// @ID           logout-account
// @Produce      json
// @Success      200      {string}  ok
// @Failure      401,500  {object}  response.ErrorResponse
// @Router       /auth/v1/logout [post]
func (h *AuthHandler) Logout(ctx *fiber.Ctx) error {
	validateRequest := &authService.ValidateRequest{
		AccessToken:  ctx.Cookies("accessToken"),
		RefreshToken: ctx.Cookies("refreshToken"),
	}

	_, err := h.AuthService.Validate(ctx.Context(), validateRequest)
	if err != nil {
		h.log.Error(err, "validation error")

		return ctx.Status(fiber.StatusForbidden).JSON(response.Error{Error: err.Error()})
	}

	// Removing accessToken cookie
	cookie.DeleteCookie(ctx, "accessToken")

	// Removing refreshToken cookie
	cookie.DeleteCookie(ctx, "refreshToken")

	// If there's redirect_uri param then sending redirect command
	if redirectURI := ctx.Query("redirect_uri"); redirectURI != "" {
		return ctx.Redirect(redirectURI)
	}

	return ctx.SendStatus(fiber.StatusOK)
}

// Info
// @Summary      Info
// @Tags         Auth
// @Description  Get login
// @ID           info
// @Produce      json
// @Success      200      {string}  ok
// @Failure      403,500  {object}  response.ErrorResponse
// @Router       /auth/v1/i [get]
func (h *AuthHandler) Info(ctx *fiber.Ctx) error {
	validateRequest := &authService.ValidateRequest{
		AccessToken:  ctx.Cookies("accessToken"),
		RefreshToken: ctx.Cookies("refreshToken"),
	}

	validateResponse, err := h.AuthService.Validate(ctx.Context(), validateRequest)
	if err != nil {
		h.log.Debug(err, "validation error")

		return ctx.Status(fiber.StatusForbidden).JSON(response.Error{Error: err.Error()})
	}

	dbConn, err := sql.Open("postgres", config.DbConnString)
	if err != nil {
		h.log.Fatal(err, "error while opening db connection")
	}
	defer func(dbConn *sql.DB) {
		err = dbConn.Close()
		if err != nil {
			h.log.Fatal(err, "error while closing db connection")
		}
	}(dbConn)

	userDb := db.NewDatabase(dbConn)

	var user model.User
	user.Username = validateResponse.Username

	err = userDb.GetUser(&user)
	if err != nil {
		h.log.Debug(err)

		return ctx.Status(fiber.StatusForbidden).JSON(response.Error{Error: err.Error()})
	}

	return ctx.Status(fiber.StatusOK).JSON(response.InfoSuccess{
		Email:     user.Email,
		Username:  user.Username,
		LastLogin: user.LastLogin,
	})
}

// Registration endpoint
// @Summary      Registration
// @Tags         Auth
// @Description  Register a new user
// @ID           registration
// @Accept       json
// @Produce      json
// @Param        input    body      request.RegistrationRequest  true  "Account info"
// @Success      200      {object}  response.RegistrationResponse
// @Failure      403,500  {object}  response.ErrorResponse
// @Router       /auth/v1/reg [post]
func (h *AuthHandler) Registration(ctx *fiber.Ctx) error {
	validateRequest := &authService.ValidateRequest{
		AccessToken:  ctx.Cookies("accessToken"),
		RefreshToken: ctx.Cookies("refreshToken"),
	}

	_, err := h.AuthService.Validate(ctx.Context(), validateRequest)
	if err == nil {
		h.log.Debug(ErrAlreadyLogged)

		return ctx.Status(fiber.StatusForbidden).JSON(response.Error{Error: ErrAlreadyLogged.Error()})
	}

	dbConn, err := sql.Open("postgres", config.DbConnString)
	if err != nil {
		h.log.Fatal(err, "error while opening db connection")
	}
	defer func(dbConn *sql.DB) {
		err = dbConn.Close()
		if err != nil {
			h.log.Fatal(err, "error while closing db connection")
		}
	}(dbConn)

	userDb := db.NewDatabase(dbConn)

	var regRequest request.Registration
	var user model.User

	if err = ctx.BodyParser(&regRequest); err != nil {
		h.log.Debugf("body parsing error: %v", err)
		return ctx.Status(fiber.StatusBadRequest).JSON(response.Error{Error: err.Error()})
	}

	user.Username = regRequest.Username
	user.Password = regRequest.Password
	user.Email = regRequest.Email

	err = userDb.AddUser(&user)
	if err != nil {
		h.log.Debug(err)

		return ctx.Status(fiber.StatusForbidden).JSON(response.Error{Error: err.Error()})
	}

	accessToken, err := token.NewToken(&jwt.MapClaims{
		"login": user.Username,
	}, config.TTL.Access)

	if err != nil {
		h.log.Error(err, "error while creating access token")

		return ctx.Status(fiber.StatusInternalServerError).JSON(response.Error{Error: err.Error()})
	}

	refreshToken, err := token.NewToken(&jwt.MapClaims{
		"login": user.Username,
	}, config.TTL.Refresh)

	if err != nil {
		h.log.Error(err, "error while creating refresh token")

		return ctx.Status(fiber.StatusInternalServerError).JSON(response.Error{Error: err.Error()})
	}

	// Access token cookie
	cookie.SetCookie(ctx, "accessToken", accessToken.GetRaw(), config.TTL.Access)

	// Refresh token cookie
	cookie.SetCookie(ctx, "refreshToken", refreshToken.GetRaw(), config.TTL.Refresh)

	// If there's redirect_uri param then sending redirect command
	if redirectURI := ctx.Query("redirect_uri"); redirectURI != "" {
		return ctx.Redirect(redirectURI)
	}

	return ctx.Status(fiber.StatusOK).JSON(response.RegistrationSuccess{
		Username: user.Username,
		Email:    user.Email,
	})
}
