package logger

import (
	"fmt"
	"io"
	"os"

	"github.com/getsentry/sentry-go"
	"github.com/rs/zerolog"
)

type Logger struct {
	log zerolog.Logger
}

func NewLogger(out io.Writer, level zerolog.Level, service string) Logger {

	if level <= zerolog.DebugLevel {
		return Logger{log: zerolog.New(out).
			Level(level).
			With().
			CallerWithSkipFrameCount(3).
			Timestamp().
			Int("pid", os.Getpid()).
			Str("service", service).
			Logger(),
		}
	}

	return Logger{log: zerolog.New(out).
		Level(level).
		With().
		Timestamp().
		Int("pid", os.Getpid()).
		Str("service", service).
		Logger(),
	}
}

func (l Logger) Println(v ...interface{}) {
	l.log.Print(fmt.Sprint(v...))
}

func (l Logger) Printf(format string, v ...interface{}) {
	l.log.Printf(format, v...)
}

func (l Logger) Debug(i ...interface{}) {
	l.log.Debug().Msgf(fmt.Sprint(i...))
}

func (l Logger) Debugf(format string, i ...interface{}) {
	l.log.Debug().Msgf(format, i...)
}

func (l Logger) Info(i ...interface{}) {
	l.log.Info().Msgf(fmt.Sprint(i...))
}

func (l Logger) Infof(format string, i ...interface{}) {
	l.log.Info().Msgf(format, i...)
}

func (l Logger) Error(err error, msg string) {
	l.log.Error().Err(err).Msg(msg)
	sentry.CaptureException(err)
}

func (l Logger) Errorf(err error, format string, i ...interface{}) {
	l.log.Error().Err(err).Msgf(format, i...)
	sentry.CaptureException(err)
}

func (l Logger) Fatal(err error, msg string) {
	l.log.Fatal().Err(err).Msg(msg)
	sentry.CaptureException(err)
}

func (l Logger) Fatalf(err error, format string, i ...interface{}) {
	l.log.Fatal().Err(err).Msgf(format, i...)
	sentry.CaptureException(err)
}
