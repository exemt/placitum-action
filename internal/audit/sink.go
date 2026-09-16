package audit

import (
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-action/internal/protocol"
)

const KindBatch = "batch"

const (
	maxItems = 256
	maxSize  = 512 << 10

	flushEvery = 50 * time.Millisecond

	maxPending = 50000
)

type item struct {
	subject string
	body    []byte
}

type envelope struct {
	V     int               `json:"v"`
	Kind  string            `json:"kind"`
	Items []json.RawMessage `json:"items"`
}

type Sink struct {
	nc  *nats.Conn
	log *slog.Logger

	mu      sync.Mutex
	pending []item
	size    int
	dropped uint64

	wake chan struct{}
	done chan struct{}
	stop chan struct{}
	once sync.Once
}

func NewSink(nc *nats.Conn, log *slog.Logger) *Sink {
	s := &Sink{
		nc:   nc,
		log:  log,
		wake: make(chan struct{}, 1),
		done: make(chan struct{}),
		stop: make(chan struct{}),
	}

	go s.loop()

	return s
}

func (s *Sink) Add(req *protocol.Request, reply *protocol.Reply, det Details) error {
	if s == nil || s.nc == nil || req == nil || reply == nil {
		return nil
	}

	if req.AuditSubject == nil || *req.AuditSubject == "" {
		return nil
	}

	body, err := json.Marshal(Build(req, reply, det))
	if err != nil {
		return err
	}

	s.mu.Lock()

	s.pending = append(s.pending, item{subject: *req.AuditSubject, body: body})
	s.size += len(body) + 2

	if len(s.pending) > maxPending {
		cut := len(s.pending) - maxPending
		s.dropped += uint64(cut)
		s.pending = append(s.pending[:0], s.pending[cut:]...)
		s.size = sizeOf(s.pending)
	}

	full := len(s.pending) >= maxItems || s.size >= maxSize
	s.mu.Unlock()

	if full {
		s.kick()
	}

	return nil
}

func (s *Sink) kick() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Sink) loop() {
	defer close(s.done)

	tick := time.NewTicker(flushEvery)
	defer tick.Stop()

	for {
		select {
		case <-s.stop:
			s.flush()

			return

		case <-s.wake:
			s.flush()

		case <-tick.C:
			s.flush()
		}
	}
}

func (s *Sink) flush() {
	for {
		s.mu.Lock()

		if len(s.pending) == 0 {
			s.mu.Unlock()

			return
		}

		n := len(s.pending)
		if n > maxItems {
			n = maxItems
		}

		take := make([]item, n)
		copy(take, s.pending[:n])

		s.pending = append(s.pending[:0], s.pending[n:]...)
		s.size = sizeOf(s.pending)
		s.mu.Unlock()

		s.publish(take)
	}
}

func (s *Sink) publish(items []item) {
	if len(items) == 1 {
		s.send(items[0].subject, items[:1])

		return
	}

	order, bySubject := groupBySubject(items)

	for _, subject := range order {
		s.send(subject, bySubject[subject])
	}
}

func groupBySubject(items []item) ([]string, map[string][]item) {
	bySubject := make(map[string][]item, 1)
	order := make([]string, 0, 1)

	for _, it := range items {
		if _, ok := bySubject[it.subject]; !ok {
			order = append(order, it.subject)
		}

		bySubject[it.subject] = append(bySubject[it.subject], it)
	}

	return order, bySubject
}

func (s *Sink) send(subject string, items []item) {
	body, err := pack(items)
	if err == nil {
		err = s.nc.Publish(subject, body)
	}

	if err != nil && s.log != nil {
		s.log.Warn("inspector audit publish failed",
			"subject", subject, "events", len(items), "error", err.Error())
	}
}

func pack(items []item) ([]byte, error) {
	raw := make([]json.RawMessage, 0, len(items))

	for _, it := range items {
		raw = append(raw, json.RawMessage(it.body))
	}

	return json.Marshal(envelope{V: Version, Kind: KindBatch, Items: raw})
}

func sizeOf(items []item) int {
	n := 0

	for _, it := range items {
		n += len(it.body) + 2
	}

	return n
}

func (s *Sink) Close() {
	if s == nil {
		return
	}

	s.once.Do(func() {
		close(s.stop)
		<-s.done
	})
}
