package main

import (
	"context"
	"log/slog"
	"runtime/debug"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-action/internal/audit"
	"github.com/exemt/placitum-action/internal/body"
	"github.com/exemt/placitum-action/internal/config"
	"github.com/exemt/placitum-action/internal/livelist"
	"github.com/exemt/placitum-action/internal/policy"
	"github.com/exemt/placitum-action/internal/protocol"
	"github.com/exemt/placitum-action/internal/queue"
	"github.com/exemt/placitum-shared/dataset"
	"github.com/exemt/placitum-shared/netinfo"
)

const (
	codeOK                 = "ACTION_OK"
	codeMalformedRequest   = "ACTION_MALFORMED_REQUEST"
	codeUnsupportedVersion = "ACTION_UNSUPPORTED_VERSION"
	codeUnknownProfile     = "ACTION_UNKNOWN_PROFILE"
	codeProfileOff         = "ACTION_PROFILE_OFF"
	codeIdle               = "ACTION_IDLE"
	codeInternalError      = "ACTION_INTERNAL_ERROR"
	codeStoreError         = "ACTION_STORE_ERROR"
	codeGeoUnavailable     = "ACTION_GEO_UNAVAILABLE"
)

type handler struct {
	cfg      *config.Config
	log      *slog.Logger
	nc       *nats.Conn
	audit    *audit.Sink
	store    *policy.Store
	pool     *queue.Pool
	loader   *body.Loader
	mirror   *livelist.Mirror
	lists    *dataset.Publisher
	resolver *netinfo.Resolver
}

func (h *handler) receive(msg *nats.Msg) {
	defer h.recoverInto(msg.Reply, "")

	req, err := protocol.Parse(msg.Data)
	if err != nil {
		h.log.Warn("message rejected", "error", err.Error(), "bytes", len(msg.Data))
		h.send(msg.Reply, h.fallback(msg.Data, codeMalformedRequest), nil, audit.Details{})

		return
	}

	if !h.cfg.Supports(req.V) {
		h.send(msg.Reply, h.plain(req, codeUnsupportedVersion), req, audit.Details{})

		return
	}

	if req.Release != nil {
		h.log.Debug("release ignored", "rid", req.RID, "reason", req.Release.Reason)

		return
	}

	if req.Phase != protocol.PhaseRequest {
		h.send(msg.Reply, h.plain(req, codeIdle), req, audit.Details{})

		return
	}

	h.pool.Submit(&queue.Task{Req: req, Reply: msg.Reply})
}

func (h *handler) evaluate(t *queue.Task, budget time.Duration, shed string) {
	defer h.recoverInto(t.Reply, t.Req.RID)

	if shed != "" {
		reply := protocol.ShedReply(t.Req, shed)
		det := audit.Details{Engine: map[string]any{"shed": shed}}

		asks := h.overloadOnShed(t, shed, reply, det)

		h.log.Warn("shed", "rid", t.Req.RID, "reason", shed,
			"budget_ms", budget.Milliseconds(), "asks", asks)
		h.send(t.Reply, reply, t.Req, det)

		return
	}

	reply, det := h.inspect(t.Req, t.Fill, budget)
	h.send(t.Reply, reply, t.Req, det)
}

func (h *handler) inspect(req *protocol.Request, fill int, budget time.Duration) (*protocol.Reply, audit.Details) {
	snap := h.store.Current()

	p, ok := snap.Profile(req.Route.Profile)
	if !ok {
		h.log.Warn("unknown profile", "rid", req.RID, "profile", req.Route.Profile)

		return protocol.ErrorReply(req, codeUnknownProfile), audit.Details{}
	}

	if p.Mode == policy.ModeOff {
		return h.plain(req, codeProfileOff), audit.Details{}
	}

	started := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	var (
		src *source
		ev  *policy.Evaluator
	)

	if len(p.Conditions) > 0 {
		src = newSource(ctx, req, h.loader)
		ev = policy.NewEvaluator(src, h.mirror, p.Conditions)
	}

	actions, writes, matched := p.Collect(ev, req.HTTP.Method, req.HTTP.URI)

	if req.Phase == protocol.PhaseRequest {
		moreActions, moreWrites, moreNames := p.CollectOverload(fill, false)
		actions = append(actions, moreActions...)
		writes = append(writes, moreWrites...)
		matched = append(matched, moreNames...)
	}

	engine := map[string]any{
		"profile": p.Name,
		"mode":    p.Mode,
		"rules":   matched,
		"actions": len(actions),
	}

	if len(writes) != 0 {
		engine["lists"] = len(writes)
	}

	if ev != nil {
		if len(ev.Evaluated()) > 0 {
			engine["conditions"] = ev.Evaluated()
		}

		if len(ev.Notes) > 0 {
			engine["notes"] = ev.Notes
		}
	}

	det := audit.Details{
		EngineMS: float64(time.Since(started).Microseconds()) / 1000,
		Engine:   engine,
	}

	if src != nil && src.Fault {
		h.log.Warn("store failed", "rid", req.RID, "profile", p.Name, "detail", src.Why)
		engine["store"] = src.Why

		return protocol.ErrorReply(req, codeStoreError), det
	}

	if err := h.publish(ctx, writes, req); err != nil {
		h.log.Error("geo unavailable for a list write", "rid", req.RID,
			"profile", p.Name, "error", err.Error())

		engine["geo"] = err.Error()

		return protocol.ErrorReply(req, codeGeoUnavailable), det
	}

	reply := h.plain(req, codeOK)
	reply.Actions = actions

	h.log.Info("told",
		"rid", req.RID,
		"inspector", req.Inspector,
		"wave", req.Wave,
		"method", req.HTTP.Method,
		"uri", req.HTTP.URI,
		"profile", p.Name,
		"rules", matched,
		"actions", len(actions),
		"lists", len(writes),
	)

	return reply, det
}

func (h *handler) publish(ctx context.Context, writes []policy.Write, req *protocol.Request) error {
	if len(writes) == 0 || h.lists == nil {
		return nil
	}

	return writeLists(ctx, h.resolver, h.lists, h.log, req.RID, req.Conn.ClientIP, writes)
}

func (h *handler) plain(req *protocol.Request, code string) *protocol.Reply {
	reply := protocol.NewReply(req, protocol.VerdictAllow)
	reply.Reason = &protocol.Reason{Code: code}

	return reply
}

func (h *handler) fallback(payload []byte, code string) *protocol.Reply {
	return protocol.FallbackReply(protocol.SniffRID(payload), h.cfg.Name, code)
}

func (h *handler) send(subject string, reply *protocol.Reply, req *protocol.Request,
	det audit.Details) {

	if subject == "" {
		h.log.Error("no reply subject in message", "rid", reply.RID)

		return
	}

	payload, err := reply.Marshal()
	if err != nil {
		h.log.Error("reply marshal failed", "rid", reply.RID, "error", err.Error())

		payload, err = protocol.FallbackReply(reply.RID, reply.Inspector,
			codeInternalError).Marshal()
		if err != nil {
			return
		}
	}

	if err := h.nc.Publish(subject, payload); err != nil {
		h.log.Error("respond failed", "rid", reply.RID, "error", err.Error())
	}

	if err := h.audit.Add(req, reply, det); err != nil {
		h.log.Warn("audit publish failed", "rid", reply.RID, "error", err.Error())
	}
}

func (h *handler) recoverInto(subject, rid string) {
	r := recover()
	if r == nil {
		return
	}

	h.log.Error("handler panicked", "rid", rid, "panic", r, "stack", string(debug.Stack()))

	if subject == "" {
		return
	}

	h.send(subject, protocol.FallbackReply(rid, h.cfg.Name, codeInternalError),
		nil, audit.Details{})
}

func (h *handler) overloadOnShed(t *queue.Task, shed string, reply *protocol.Reply,
	det audit.Details) int {

	if shed != queue.ReasonQueueLimit || t.Req.Phase != protocol.PhaseRequest {
		return 0
	}

	p, ok := h.store.Current().Profile(t.Req.Route.Profile)
	if !ok || p.Mode == policy.ModeOff {
		return 0
	}

	actions, writes, names := p.CollectOverload(t.Fill, true)

	if len(names) == 0 {
		return 0
	}

	det.Engine["rules"] = names

	if err := h.publish(context.Background(), writes, t.Req); err != nil {
		h.log.Error("geo unavailable for a list write", "rid", t.Req.RID,
			"profile", p.Name, "error", err.Error())

		det.Engine["geo"] = err.Error()
	}

	reply.Actions = actions

	return len(actions)
}
