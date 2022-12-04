package routes

import (
	"github.com/gofiber/fiber/v2"

	"github.com/richard-on/auth-service/pkg/authService"
	"github.com/richard-on/auth-service/pkg/server/handlers"
)

func AuthRouter(app fiber.Router, authClient authService.AuthServiceClient) {

	handler := handlers.NewAuthHandler(app, authClient)

	app.Post("/login", handler.Login)

	app.Post("/validate", handler.Validate)

	app.Post("/logout", handler.Logout)

	app.Post("/reg", handler.Registration)

	app.Get("/i", handler.Info)

}
