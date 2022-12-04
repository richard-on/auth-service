package config

import (
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
)

var DefaultWriter = NewWriter()

func NewWriter() io.Writer {

	var out io.Writer

	switch LogInfo.Output {
	case "stdout":
		out = os.Stdout
	case "stderr":
		out = os.Stderr
	case "file":
		file, err := os.OpenFile("logs/"+LogInfo.File, os.O_RDWR|os.O_CREATE, 0666)
		if err != nil {
			panic(err)
		}

		out = file

	default:
		out = os.Stdout
	}

	if LogInfo.ConsoleWriter {
		return zerolog.ConsoleWriter{Out: out, TimeFormat: time.RFC1123}
	}

	return out
}
