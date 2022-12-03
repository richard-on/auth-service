package config

import (
	"fmt"
	"os"
	"strconv"

	"github.com/rs/zerolog"

	"github.com/richard-on/auth-service/pkg/logger"
)

var LogInfo struct {
	Output        string
	Level         zerolog.Level
	File          string
	ConsoleWriter bool
}

var SentryInfo struct {
	DSN string
	TSR float64
}

var DbInfo struct {
	Name     string
	Host     string
	Port     string
	User     string
	Password string
	SslMode  string
}
var DbConnString string

var TTL struct {
	Access  int64
	Refresh int64
}

var Env string
var GoDotEnv bool
var FiberPrefork bool
var MaxCPU int
var Secret string
var AES string
var Host string
var SecureCookie bool

func Init(log logger.Logger) {
	var err error

	Env = os.Getenv("ENV")

	Secret = os.Getenv("SECRET")

	AES = os.Getenv("AES")

	Host = os.Getenv("HOST")

	SecureCookie, err = strconv.ParseBool(os.Getenv("SECURE_COOKIE"))
	if err != nil {
		log.Infof("SECURE_COOKIE init: %v", err)
	}

	GoDotEnv, err = strconv.ParseBool(os.Getenv("GODOTENV"))
	if err != nil {
		log.Infof("GODOTENV init: %v", err)
	}

	FiberPrefork, err = strconv.ParseBool(os.Getenv("FIBER_PREFORK"))
	if err != nil {
		log.Infof("FIBER_PREFORK init: %v", err)
	}

	MaxCPU, err = strconv.Atoi(os.Getenv("MAX_CPU"))
	if err != nil {
		log.Infof("MAX_CPU init: %v", err)
	}

	LogInfo.Output = os.Getenv("LOG_OUTPUT")

	LogInfo.Level, err = zerolog.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		log.Infof("LOG_LEVEL init: %v", err)
	}

	LogInfo.File = os.Getenv("LOG_FILE")

	LogInfo.ConsoleWriter, err = strconv.ParseBool(os.Getenv("LOG_CW"))
	if err != nil {
		log.Infof("LOG_CW init: %v", err)
	}

	SentryInfo.DSN = os.Getenv("SENTRY_DSN")

	SentryInfo.TSR, err = strconv.ParseFloat(os.Getenv("SENTRY_TSR"), 64)
	if err != nil {
		log.Infof("SENTRY_TSR init: %v", err)
	}

	DbInfo.Name = os.Getenv("DB_NAME")
	DbInfo.Host = os.Getenv("DB_HOST")
	DbInfo.Port = os.Getenv("DB_PORT")
	DbInfo.User = os.Getenv("DB_USER")
	DbInfo.Password = os.Getenv("DB_PASSWORD")
	DbInfo.SslMode = os.Getenv("DB_SSLMODE")

	DbConnString = fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		DbInfo.Host, DbInfo.Port, DbInfo.User, DbInfo.Password, DbInfo.Name, DbInfo.SslMode)

	TTL.Access, err = strconv.ParseInt(os.Getenv("TTL_ACCESS"), 10, 64)
	if err != nil {
		log.Infof("TTL_ACCESS init: %v", err)
	}

	TTL.Refresh, err = strconv.ParseInt(os.Getenv("TTL_REFRESH"), 10, 64)
	if err != nil {
		log.Infof("TTL_REFRESH init: %v", err)
	}
}
