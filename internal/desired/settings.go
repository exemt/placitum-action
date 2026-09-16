package desired

import (
	"fmt"
	"hash"
	"log/slog"

	"github.com/exemt/placitum-shared/loglevel"
)

type Settings struct {
	LogLevel string `json:"log_level"`

	level slog.Level
}

func (s *Settings) validate() error {
	if s == nil {
		return nil
	}

	level, err := loglevel.Parse(s.LogLevel)
	if err != nil {
		return fmt.Errorf("settings.log_level: %w", err)
	}

	s.level = level

	return nil
}

func writeSettings(sum hash.Hash, s *Settings) {
	if s == nil {
		return
	}

	_, _ = sum.Write([]byte("settings"))
	_, _ = sum.Write([]byte{0})
	_, _ = sum.Write([]byte("log_level"))
	_, _ = sum.Write([]byte{0})
	_, _ = sum.Write([]byte(s.LogLevel))
	_, _ = sum.Write([]byte{0})
}

func (s *Settings) apply(level *slog.LevelVar, log *slog.Logger) {
	if s == nil || level == nil {
		return
	}

	if level.Level() == s.level {
		return
	}

	level.Set(s.level)
	log.Info("log level applied", "level", loglevel.String(s.level))
}
