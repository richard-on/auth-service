package handlers

import (
	"errors"
	"github.com/gofiber/fiber/v2"
	"github.com/richard-on/auth-service/pkg/response"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func HandleGrpcError(ctx *fiber.Ctx, err error) error {
	if e, ok := status.FromError(err); ok {
		switch e.Code() {
		case codes.AlreadyExists:
			return ctx.Status(fiber.StatusConflict).JSON(response.Error{Error: e.Message()})
		case codes.Unauthenticated:
			return ctx.Status(fiber.StatusUnauthorized).JSON(response.Error{Error: e.Message()})
		case codes.PermissionDenied:
			return ctx.Status(fiber.StatusForbidden).JSON(response.Error{Error: e.Message()})
		case codes.InvalidArgument:
			return ctx.Status(fiber.StatusOK).JSON(response.Error{Error: e.Message()})
		case codes.Canceled:
			return ctx.Status(fiber.StatusBadRequest).JSON(response.Error{Error: e.Message()})

		default:
			return ctx.Status(fiber.StatusInternalServerError).JSON(response.Error{Error: e.Message()})
		}
	}

	return err
}

// ErrUnsupportedAuthMethod indicates that an authentication method provided in request header is not supported
var ErrUnsupportedAuthMethod = errors.New("unsupported authentication method")

// ErrIncorrectCredentialsFormat indicates that credentials passed in request header are in wrong format
var ErrIncorrectCredentialsFormat = errors.New("incorrect user credentials format")

var ErrAlreadyLogged = errors.New("you are already logged into the system. Logout first")
