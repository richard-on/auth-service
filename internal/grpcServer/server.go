package grpcServer

import (
	"context"

	"github.com/golang-jwt/jwt/v4"

	"github.com/richard-on/auth-service/config"
	"github.com/richard-on/auth-service/internal/token"
	"github.com/richard-on/auth-service/pkg/authService"
	"github.com/richard-on/auth-service/pkg/logger"
)

type GRPCServer struct {
	authService.UnimplementedAuthServiceServer
	log logger.Logger
}

// Validate checks access and refresh tokens.
func (s *GRPCServer) Validate(_ context.Context, req *authService.ValidateRequest) (*authService.ValidateResponse, error) {
	accessToken := token.JwtToken{
		Token: &jwt.Token{Raw: req.GetAccessToken()},
	}
	refreshToken := token.JwtToken{
		Token: &jwt.Token{Raw: req.GetRefreshToken()},
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

		updatedAccessToken, err := token.NewToken(&jwt.MapClaims{
			"username": (*refreshTokenClaims)["username"],
		}, config.TTL.Access)
		if err != nil {
			s.log.Error(err, "error while creating new access token")

			return &authService.ValidateResponse{}, err
		}

		updatedRefreshToken, err := token.NewToken(&jwt.MapClaims{
			"username": (*refreshTokenClaims)["username"],
		}, config.TTL.Refresh)
		if err != nil {
			s.log.Error(err, "error while creating new refresh token")

			return &authService.ValidateResponse{}, err
		}

		return &authService.ValidateResponse{
			TokenStatus:  authService.ValidateResponse_UPDATE_ALL,
			Username:     (*refreshTokenClaims)["username"].(string),
			AccessToken:  updatedAccessToken.GetRaw(),
			RefreshToken: updatedRefreshToken.GetRaw(),
		}, nil
	}

	accessTokenClaims, err := accessToken.Parse()
	if err != nil {
		s.log.Error(err, "error while parsing access token")

		return &authService.ValidateResponse{}, err
	}

	return &authService.ValidateResponse{
		TokenStatus:  authService.ValidateResponse_OK,
		Username:     (*accessTokenClaims)["username"].(string),
		AccessToken:  accessToken.GetRaw(),
		RefreshToken: refreshToken.GetRaw(),
	}, nil
}
