package server

import (
	"github.com/gofiber/fiber/v2/middleware/cors"
	"time"

	"github.com/ansrivas/fiberprometheus/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/pprof"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/swagger"

	"github.com/richard-on/auth-service/config"
	_ "github.com/richard-on/auth-service/docs"
	"github.com/richard-on/auth-service/pkg/logger"
)

type Server struct {
	app *fiber.App
	log logger.Logger
}

func NewApp() Server {
	log := logger.NewLogger(config.DefaultWriter,
		config.LogInfo.Level,
		"auth-server")

	//engine := html.New("./public", ".html")

	app := fiber.New(fiber.Config{
		Prefork: config.FiberPrefork,
		//ServerHeader:  "auth.richardhere.dev",
		CaseSensitive: false,
		//Views:         engine,
		ReadTimeout: time.Second * 30,
		ErrorHandler: func(ctx *fiber.Ctx, err error) error {

			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}

			err = ctx.SendStatus(code)
			if err != nil {
				// In case the SendFile fails
				return ctx.Status(fiber.StatusInternalServerError).SendString("Internal Server Error")
			}

			return nil
		},
	})

	prometheus := fiberprometheus.New("auth.richardhere.dev")
	prometheus.RegisterAt(app, "/metrics")

	app.Use(
		//csrf.New(),
		cors.New(cors.ConfigDefault),
		recover.New(),
		pprof.New(
			pprof.Config{Next: func(c *fiber.Ctx) bool {
				return config.Env != "dev"
			}}),
		prometheus.Middleware,
		logger.Middleware(
			logger.NewLogger(config.DefaultWriter,
				config.LogInfo.Level,
				"auth-httpserver"), nil,
		),
	)

	// Registering Swagger API
	app.Get("/swagger/*", swagger.HandlerDefault)

	app.Static("/", "./public")

	return Server{
		app: app,
		log: log,
	}
}
