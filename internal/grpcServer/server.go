package grpcServer

import (
	"context"
	"github.com/richard-on/auth-service/config"
	"github.com/richard-on/auth-service/internal/db"
	"github.com/richard-on/auth-service/internal/model"
	"github.com/richard-on/auth-service/internal/token"
	"github.com/richard-on/auth-service/pkg/authService"
	"github.com/richard-on/auth-service/pkg/logger"
	"github.com/rs/xid"
	"time"
)

//rpc VerifyRegistration(VerifyRequest) returns (VerifyResponse) {}

type GRPCServer struct {
	authService.UnimplementedAuthServiceServer
	log logger.Logger
	db  *db.DB
}

func (s *GRPCServer) Register(_ context.Context, req *authService.RegisterRequest) (*authService.RegisterResponse, error) {
	user := model.User{
		ID:       xid.New().String(),
		Email:    req.GetEmail(),
		Username: req.GetUsername(),
		Password: req.GetPassword(),
	}

	err := s.db.AddUser(&user)
	if err != nil {
		s.log.Debug(err)

		return &authService.RegisterResponse{}, err
	}

	accessToken, err := token.NewEncryptedToken(user.ID, user.Email, user.Username, config.TTL.Access, config.AES)
	if err != nil {
		s.log.Error(err, "error while creating access token")

		return &authService.RegisterResponse{}, err
	}

	refreshToken, err := token.NewEncryptedToken(user.ID, user.Email, user.Username, config.TTL.Refresh, config.AES)
	if err != nil {
		s.log.Error(err, "error while creating refresh token")

		return &authService.RegisterResponse{}, err
	}

	return &authService.RegisterResponse{
		Id:           user.ID,
		Username:     user.Username,
		Email:        user.Email,
		AccessToken:  accessToken.EncryptedToken,
		RefreshToken: refreshToken.EncryptedToken,
	}, nil
}

func (s *GRPCServer) Login(_ context.Context, req *authService.LoginRequest) (*authService.LoginResponse, error) {
	var user model.User

	user.Username = req.Username
	user.Password = req.Password

	err := s.db.GetUser(&user)
	if err != nil {
		s.log.Debug(err)

		return &authService.LoginResponse{}, err
	}

	accessToken, err := token.NewEncryptedToken(user.ID, user.Email, user.Username, config.TTL.Access, config.AES)
	if err != nil {
		s.log.Error(err, "error while creating access token")

		return &authService.LoginResponse{}, err
	}

	refreshToken, err := token.NewEncryptedToken(user.ID, user.Email, user.Username, config.TTL.Refresh, config.AES)
	if err != nil {
		s.log.Error(err, "error while creating refresh token")

		return &authService.LoginResponse{}, err
	}

	return &authService.LoginResponse{
		Id:           user.ID,
		Username:     user.Username,
		Email:        user.Email,
		LastLogin:    user.LastLogin.String(),
		AccessToken:  accessToken.EncryptedToken,
		RefreshToken: refreshToken.EncryptedToken,
	}, nil
}

// Validate checks access and refresh tokens.
func (s *GRPCServer) Validate(_ context.Context, req *authService.ValidateRequest) (*authService.ValidateResponse, error) {
	accessToken := token.EncryptedJWT{
		EncryptedToken: req.AccessToken,
		Key:            config.AES,
	}
	refreshToken := token.EncryptedJWT{
		EncryptedToken: req.RefreshToken,
		Key:            config.AES,
	}

	if err := accessToken.Check(); err != nil {
		s.log.Debug("access token is invalid")

		if err = refreshToken.Check(); err != nil {
			s.log.Debug("refresh token is invalid")

			return &authService.ValidateResponse{}, err
		}

		refreshTokenClaims, err := refreshToken.Parse()
		if err != nil {
			s.log.Error(err, "error while parsing refresh token")

			return &authService.ValidateResponse{}, err
		}

		updatedAccessToken, err := token.NewEncryptedToken(
			(*refreshTokenClaims)["id"].(string),
			(*refreshTokenClaims)["email"].(string),
			(*refreshTokenClaims)["username"].(string),
			config.TTL.Access,
			config.AES,
		)
		if err != nil {
			s.log.Error(err, "error while creating new access token")

			return &authService.ValidateResponse{}, err
		}

		updatedRefreshToken, err := token.NewEncryptedToken(
			(*refreshTokenClaims)["id"].(string),
			(*refreshTokenClaims)["email"].(string),
			(*refreshTokenClaims)["username"].(string),
			config.TTL.Refresh,
			config.AES,
		)
		if err != nil {
			s.log.Error(err, "error while creating new refresh token")

			return &authService.ValidateResponse{}, err
		}

		return &authService.ValidateResponse{
			TokenStatus:  authService.ValidateResponse_UPDATE,
			Id:           (*refreshTokenClaims)["id"].(string),
			AccessToken:  updatedAccessToken.EncryptedToken,
			RefreshToken: updatedRefreshToken.EncryptedToken,
		}, nil
	}

	accessTokenClaims, err := accessToken.Parse()
	if err != nil {
		s.log.Error(err, "error while parsing access token")

		return &authService.ValidateResponse{}, err
	}

	return &authService.ValidateResponse{
		TokenStatus:  authService.ValidateResponse_OK,
		Id:           (*accessTokenClaims)["id"].(string),
		AccessToken:  accessToken.EncryptedToken,
		RefreshToken: refreshToken.EncryptedToken,
	}, nil
}

func (s *GRPCServer) Info(_ context.Context, req *authService.ValidateRequest) (*authService.InfoResponse, error) {
	accessToken := token.EncryptedJWT{
		EncryptedToken: req.AccessToken,
		Key:            config.AES,
	}
	refreshToken := token.EncryptedJWT{
		EncryptedToken: req.RefreshToken,
		Key:            config.AES,
	}

	if err := accessToken.Check(); err != nil {
		s.log.Debug("access token is invalid")

		if err = refreshToken.Check(); err != nil {
			s.log.Debug("refresh token is invalid")

			return &authService.InfoResponse{}, err
		}

		refreshTokenClaims, err := refreshToken.Parse()
		if err != nil {
			s.log.Error(err, "error while parsing refresh token")

			return &authService.InfoResponse{}, err
		}

		return &authService.InfoResponse{
			Id:        (*refreshTokenClaims)["id"].(string),
			Username:  (*refreshTokenClaims)["email"].(string),
			Email:     (*refreshTokenClaims)["username"].(string),
			LastLogin: time.Unix(int64((*refreshTokenClaims)["exp"].(float64))-config.TTL.Refresh, 0).String(),
		}, nil
	}

	accessTokenClaims, err := accessToken.Parse()
	if err != nil {
		s.log.Error(err, "error while parsing access token")

		return &authService.InfoResponse{}, err
	}

	return &authService.InfoResponse{
		Id:        (*accessTokenClaims)["id"].(string),
		Username:  (*accessTokenClaims)["username"].(string),
		Email:     (*accessTokenClaims)["email"].(string),
		LastLogin: time.Unix(int64((*accessTokenClaims)["exp"].(float64))-config.TTL.Access, 0).String(),
	}, nil
}
