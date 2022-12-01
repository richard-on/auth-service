package grpcServer

import (
	"context"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"

	"github.com/richard-on/auth-service/config"
	"github.com/richard-on/auth-service/pkg/authService"
	"github.com/richard-on/auth-service/pkg/logger"
)

// Run starts a gRPC server for JWTValidationService. It retrieves host and port from environment variables.
func Run() {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)

	_, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	log := logger.NewLogger(config.DefaultWriter,
		config.LogInfo.Level,
		"auth-grpc-setup")

	log.Info("starting gRPC server")

	listener, err := net.Listen("tcp", ":4000")
	if err != nil {
		log.Fatalf(err, "error while listening tcp")
	}

	// Creating new gRPC server handlers
	s := grpc.NewServer()
	gRPCServer := &GRPCServer{}

	authService.RegisterAuthServiceServer(s, gRPCServer)

	// Starting gRPC server
	go func() {
		if err = s.Serve(listener); err == nil {
			log.Fatalf(err, "error while serving")
		}
	}()

	<-quit

	s.GracefulStop()
	log.Info("gRPC server shutdown success")
}
