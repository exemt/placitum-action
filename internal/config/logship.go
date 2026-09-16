package config

import (
	"os"
	"strings"
)

func LogShip() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("WAF_LOG_SHIP"))) {
	case "off", "0", "no", "false":
		return false
	default:
		return true
	}
}

func LogWriter(fallback string) string {
	if v := strings.TrimSpace(os.Getenv("WAF_LOG_WRITER")); v != "" {
		return v
	}

	if name, err := os.Hostname(); err == nil && name != "" {
		return name
	}

	return fallback
}
