// Package handlers contains handlers for all Auth API endpoints.
package handlers

import (
	"encoding/base64"
	"github.com/gofiber/fiber/v2"
	_ "github.com/lib/pq"
	"github.com/richard-on/auth-service/config"
	"github.com/richard-on/auth-service/internal/cookie"
	"github.com/richard-on/auth-service/internal/model"
	"github.com/richard-on/auth-service/pkg/authService"
	"github.com/richard-on/auth-service/pkg/logger"
	"github.com/richard-on/auth-service/pkg/response"
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

// Registration endpoint
// @Summary      Registration endpoint
// @Tags         Auth
// @Description  Register a new user
// @ID           registration
// @Accept       json
// @Produce      json
// @Param        input                body      authService.RegisterRequest  true  "Register request"
// @Success      200                  {object}  response.RegistrationSuccess
// @Failure      303,400,403,409,500  {object}  response.Error
// @Router       /reg [post]
func (h *AuthHandler) Registration(ctx *fiber.Ctx) error {
	validateRequest := &authService.ValidateRequest{
		AccessToken:  ctx.Cookies("accessToken"),
		RefreshToken: ctx.Cookies("refreshToken"),
	}

	_, err := h.AuthService.Validate(ctx.Context(), validateRequest)
	if err == nil { // if NO error, which means user is logged in
		h.log.Debug(ErrAlreadyLogged)

		return ctx.Status(fiber.StatusSeeOther).JSON(response.Error{Error: ErrAlreadyLogged.Error()})
	}

	regRequest := &authService.RegisterRequest{}

	if err = ctx.BodyParser(regRequest); err != nil {
		h.log.Debugf("body parsing error: %v", err)
		return ctx.Status(fiber.StatusBadRequest).JSON(response.Error{Error: err.Error()})
	}

	regResponse, err := h.AuthService.Register(ctx.Context(), regRequest)
	if err != nil {
		h.log.Debug(err)
		return authService.HandleGrpcError(ctx, err)
	}

	// Access token cookie
	cookie.SetCookie(ctx, "accessToken", regResponse.AccessToken, config.TTL.Access)

	// Refresh token cookie
	cookie.SetCookie(ctx, "refreshToken", regResponse.RefreshToken, config.TTL.Refresh)

	// If there's redirect_uri param then sending redirect command
	if redirectURI := ctx.Query("redirect_uri"); redirectURI != "" {
		return ctx.Redirect(redirectURI)
	}

	return ctx.Status(fiber.StatusOK).JSON(response.RegistrationSuccess{
		Email:    regResponse.Email,
		Username: regResponse.Username,
	})
}

// Login handles GET-request on /login endpoint.
//
// Login accepts both Basic auth and login info in request body. If no Authorization header was found in request header,
// body will be checked for login and password.
//
// @Summary      Login endpoint
// @Tags         Auth
// @Description  Login to an account
// @ID           login-account
// @Accept       json
// @Produce      json
// @Param        input            body      authService.LoginRequest  true  "username and password"
// @Success      200              {object}  response.LoginSuccess
// @Failure      400,401,500,501  {object}  response.Error
// @Router       /login [post]
func (h *AuthHandler) Login(ctx *fiber.Ctx) error {

	var user model.User

	// Check if request header contains Authorization field
	authHeader := ctx.GetReqHeaders()["Authorization"]
	if authHeader == "" {
		// If no Authorization info was found in header, expect login info in request body as required by v1.0
		if err := ctx.BodyParser(&user); err != nil {
			h.log.Debugf("body parsing error: %v", err)
			return ctx.Status(fiber.StatusBadRequest).JSON(response.Error{Error: err.Error()})
		}

	} else {
		// If Authorization info was found in header, assume it is v1.1
		authStr := strings.Split(authHeader, " ")

		// Only support Basic authentication
		if authStr[0] != "Basic" {
			h.log.Debug(ErrUnsupportedAuthMethod)

			return ctx.Status(fiber.StatusNotImplemented).JSON(response.Error{Error: ErrUnsupportedAuthMethod.Error()})
		}

		// Decode base64 auth info
		decoded, err := base64.StdEncoding.DecodeString(authStr[1])
		if err != nil {
			h.log.Error(err, "error decoding base64-encoded auth info")

			return ctx.Status(fiber.StatusUnauthorized).JSON(response.Error{Error: err.Error()})
		}

		// Split user credentials
		userCredentials := strings.Split(string(decoded), ":")

		// Check that userCredentials contains only 2 elements (username and password)
		if len(userCredentials) != 2 {
			h.log.Debug(ErrIncorrectCredentialsFormat)

			return ctx.Status(fiber.StatusUnauthorized).JSON(response.Error{
				Error: ErrIncorrectCredentialsFormat.Error(),
			})
		}

		user.Username = userCredentials[0]
		user.Password = userCredentials[1]
	}

	loginRequest := &authService.LoginRequest{
		Username: user.Username,
		Password: user.Password,
	}

	loginResponse, err := h.AuthService.Login(ctx.Context(), loginRequest)
	if err != nil {
		h.log.Debug(err)
		return authService.HandleGrpcError(ctx, err)
	}

	// Access token cookie
	cookie.SetCookie(ctx, "accessToken", loginResponse.AccessToken, config.TTL.Access)

	// Refresh token cookie
	cookie.SetCookie(ctx, "refreshToken", loginResponse.RefreshToken, config.TTL.Refresh)

	// If there's redirect_uri param then sending redirect command
	if redirectURI := ctx.Query("redirect_uri"); redirectURI != "" {
		return ctx.Redirect(redirectURI)
	}

	return ctx.Status(fiber.StatusOK).JSON(response.LoginSuccess{
		Email:     loginResponse.Email,
		Username:  loginResponse.Username,
		LastLogin: loginResponse.LastLogin,
	})
}

// Validate is a validation endpoint
// @Summary      Validation endpoint
// @Tags         Auth
// @Description  This route validates tokens and returns user info
// @ID           validate
// @Produce      json
// @Success      200              {object}  response.ValidateSuccess
// @Failure      400,401,403,500  {object}  response.Error
// @Router       /validate [post]
func (h *AuthHandler) Validate(ctx *fiber.Ctx) error {
	validateRequest := &authService.ValidateRequest{
		AccessToken:  ctx.Cookies("accessToken"),
		RefreshToken: ctx.Cookies("refreshToken"),
	}

	validateResponse, err := h.AuthService.Validate(ctx.Context(), validateRequest)
	if err != nil {
		h.log.Error(err, "validation error")
		return authService.HandleGrpcError(ctx, err)
	}

	// Getting access and refresh tokens TTL
	accessTokenTTL := config.TTL.Access
	refreshTokenTTL := config.TTL.Refresh

	switch validateResponse.TokenStatus {
	case authService.ValidateResponse_UPDATE:
		cookie.SetCookie(ctx, "accessToken", validateResponse.AccessToken, accessTokenTTL)
		cookie.SetCookie(ctx, "refreshToken", validateResponse.RefreshToken, refreshTokenTTL)
	case authService.ValidateResponse_OK:
		break
	default:
		cookie.SetCookie(ctx, "accessToken", validateResponse.AccessToken, accessTokenTTL)
		cookie.SetCookie(ctx, "refreshToken", validateResponse.RefreshToken, refreshTokenTTL)
	}

	// If there's redirect_uri param then sending redirect command
	if redirectURI := ctx.Query("redirect_uri"); redirectURI != "" {
		return ctx.Status(fiber.StatusOK).Redirect(redirectURI)
	}

	return ctx.Status(fiber.StatusOK).JSON(response.ValidateSuccess{
		Email:    validateResponse.Email,
		Username: validateResponse.Username,
	})
}

// Info endpoint
// @Summary      Info endpoint
// @Tags         Auth
// @Description  Get user details
// @ID           info
// @Produce      json
// @Success      200              {string}  ok
// @Failure      400,401,403,500  {object}  response.Error
// @Router       /i [get]
func (h *AuthHandler) Info(ctx *fiber.Ctx) error {

	infoRequest := &authService.ValidateRequest{
		AccessToken:  ctx.Cookies("accessToken"),
		RefreshToken: ctx.Cookies("refreshToken"),
	}

	infoResponse, err := h.AuthService.Info(ctx.Context(), infoRequest)
	if err != nil {
		h.log.Debug(err, "validation error")

		return authService.HandleGrpcError(ctx, err)
	}

	return ctx.Status(fiber.StatusOK).JSON(authService.InfoResponse{
		Id:        infoResponse.Id,
		Username:  infoResponse.Username,
		Email:     infoResponse.Email,
		LastLogin: infoResponse.LastLogin,
	})
}

// Logout endpoint
// @Summary      Logout endpoint
// @Tags         Auth
// @Description  Logout from account
// @ID           logout-account
// @Produce      json
// @Success      200  {string}  ok
// @Failure      500  {string}  Internal  Server  Error
// @Router       /logout [post]
func (h *AuthHandler) Logout(ctx *fiber.Ctx) error {
	validateRequest := &authService.ValidateRequest{
		AccessToken:  ctx.Cookies("accessToken"),
		RefreshToken: ctx.Cookies("refreshToken"),
	}

	_, err := h.AuthService.Validate(ctx.Context(), validateRequest)
	if err != nil {
		h.log.Error(err, "validation error")

		return ctx.Status(fiber.StatusOK).JSON(response.LogoutSuccess{
			Message: "you were not logged in",
		})
	}

	// Removing accessToken cookie
	cookie.DeleteCookie(ctx, "accessToken")

	// Removing refreshToken cookie
	cookie.DeleteCookie(ctx, "refreshToken")

	// If there's redirect_uri param then sending redirect command
	if redirectURI := ctx.Query("redirect_uri"); redirectURI != "" {
		return ctx.Redirect(redirectURI)
	}

	return ctx.Status(fiber.StatusOK).JSON(response.LogoutSuccess{
		Message: "logout success",
	})
}
