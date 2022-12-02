package server

import (
	"context"
	"github.com/gofiber/fiber/v2"
	"github.com/richard-on/auth-service/pkg/authService"
	"github.com/richard-on/auth-service/pkg/server/routes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func (s *Server) Run() {
	// Waiting for quit signal on exit
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT)

	// Middleware for /auth/v1
	v1 := s.app.Group("/v1", func(c *fiber.Ctx) error {
		c.Set("Version", "v1.0")
		return c.Next()
	})

	cwt, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(cwt, ":4000",
		grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		s.log.Fatal(err, "failed to connect to gRPC")
	}

	defer func(conn *grpc.ClientConn) {
		err = conn.Close()
		if err != nil {
			s.log.Fatal(err, "failed to close gRPC connection")
		}
	}(conn)

	// Registering endpoints
	authClient := authService.NewAuthServiceClient(conn)
	routes.AuthRouter(v1, authClient)

	go func() {
		if err = s.app.Listen(":80"); err != nil {
			s.log.Fatalf(err, "error while listening at port 80")
		}
	}()

	<-quit

	err = s.app.Shutdown()
	if err != nil {
		s.log.Fatalf(err, "could not shutdown server")
	}
	s.log.Info("server shutdown success")
}
