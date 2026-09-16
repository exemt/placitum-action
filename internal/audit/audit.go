package audit

import (
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-action/internal/protocol"
)

const (
	Stream   = "WAF_AUDIT"
	Kind     = "inspector"
	MaxBytes = 256 << 20
	MaxAge   = 24 * time.Hour
)

const Version = 1

const (
	SeverityInfo     = "info"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

const (
	TargetURI  = "uri"
	TargetArgs = "args"
	TargetBody = "body"
	TargetConn = "conn"
)

type Finding struct {
	Code       string   `json:"code"`
	Severity   string   `json:"severity"`
	Target     string   `json:"target"`
	Offset     *int64   `json:"offset,omitempty"`
	Length     *int64   `json:"length,omitempty"`
	Rule       string   `json:"rule,omitempty"`
	Confidence *float64 `json:"confidence,omitempty"`
	Evidence   string   `json:"evidence,omitempty"`
}

type Details struct {
	EngineMS float64
	Findings []Finding
	Engine   map[string]any
}

type Event struct {
	V         int    `json:"v"`
	Kind      string `json:"kind"`
	TS        string `json:"ts"`
	Ray       string `json:"ray"`
	Node      string `json:"node"`
	Phase     string `json:"phase"`
	Inspector string `json:"inspector"`
	Profile   string `json:"profile"`

	Verdict string `json:"verdict"`
	Score   *int   `json:"score,omitempty"`

	EngineMS float64 `json:"engine_ms"`

	Findings []Finding      `json:"findings"`
	Engine   map[string]any `json:"engine,omitempty"`
}

func Build(req *protocol.Request, reply *protocol.Reply, det Details) Event {
	ev := Event{
		V:        Version,
		Kind:     Kind,
		TS:       time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		EngineMS: det.EngineMS,
		Findings: det.Findings,
		Engine:   det.Engine,
	}

	if ev.Findings == nil {
		ev.Findings = []Finding{}
	}

	if req != nil {
		ev.Ray = req.Ray
		ev.Node = req.Node
		ev.Phase = req.Phase
		ev.Inspector = req.Inspector
		ev.Profile = req.Route.Profile
	}

	if reply != nil {
		ev.Verdict = reply.Verdict
		ev.Score = reply.Score

		if ev.Inspector == "" {
			ev.Inspector = reply.Inspector
		}
	}

	return ev
}

func Ensure(nc *nats.Conn) error {
	if nc == nil {
		return fmt.Errorf("nats connection is nil")
	}

	js, err := nc.JetStream()
	if err != nil {
		return err
	}

	_, err = js.AddStream(&nats.StreamConfig{
		Name:       Stream,
		Subjects:   []string{"waf.audit.>"},
		Storage:    nats.FileStorage,
		Retention:  nats.LimitsPolicy,
		MaxAge:     MaxAge,
		MaxBytes:   MaxBytes,
		Discard:    nats.DiscardOld,
		Duplicates: 2 * time.Minute,
	})
	if err == nil || errors.Is(err, nats.ErrStreamNameAlreadyInUse) {
		return nil
	}

	return err
}
