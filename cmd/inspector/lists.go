package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/exemt/placitum-action/internal/policy"
	"github.com/exemt/placitum-shared/netinfo"
)

type geoWriter interface {
	Write(ctx context.Context, write, addr string) ([]string, error)
}

type listWriter interface {
	AddMany(name string, values []string, ttl time.Duration, reason string) error
}

func writeLists(ctx context.Context, geo geoWriter, lists listWriter, log *slog.Logger,
	rid, addr string, writes []policy.Write) error {

	if addr == "" {
		return nil
	}

	var failed error

	for _, w := range writes {
		values := []string{addr}

		if netinfo.Networked(w.Subject) {
			got, err := geo.Write(ctx, w.Subject, addr)
			if err != nil {
				if failed == nil {
					failed = err
				}

				continue
			}

			if len(got) == 0 {
				log.Warn("list write skipped: coder knows nothing about the address",
					"rid", rid, "set", w.List, "write", w.Subject, "addr", addr)

				continue
			}

			values = got
		}

		if err := lists.AddMany(w.List, values, w.TTL, w.Reason); err != nil {
			log.Warn("list publish failed", "rid", rid, "set", w.List, "error", err.Error())
		}
	}

	return failed
}
