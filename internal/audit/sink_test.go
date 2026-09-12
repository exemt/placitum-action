/*
 * Формат пачки инспектора. Тот же конверт, что у пачки агента, и та же
 * проверка: элемент обязан совпасть байт в байт с тем, что уехало бы
 * отдельным сообщением.
 */

package audit

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-action/internal/protocol"
)

func request(subject string) *protocol.Request {
	req := &protocol.Request{
		Ray:       "9b1c1f4e",
		Node:      "edge-01",
		Phase:     protocol.PhaseRequest,
		Inspector: "modsec",
	}

	if subject != "" {
		req.AuditSubject = &subject
	}

	return req
}

func TestPackKeepsEventsByteForByte(t *testing.T) {
	req := request("waf.audit.inspector.modsec")
	reply := protocol.NewReply(req, protocol.VerdictAllow)

	alone, err := json.Marshal(Build(req, reply, Details{}))
	if err != nil {
		t.Fatal(err)
	}

	body, err := pack([]item{{subject: "waf.audit.inspector.modsec", body: alone}})
	if err != nil {
		t.Fatal(err)
	}

	items, ok := Unpack(body)
	if !ok {
		t.Fatal("packed batch does not read back as a batch")
	}

	if len(items) != 1 || !bytes.Equal(items[0], alone) {
		t.Errorf("item = %s\nwant   = %s", items[0], alone)
	}
}

func TestPackEnvelopeIsABatch(t *testing.T) {
	body, err := pack([]item{
		{subject: "s", body: []byte(`{"kind":"inspector","ray":"r1"}`)},
		{subject: "s", body: []byte(`{"kind":"inspector","ray":"r2"}`)},
	})
	if err != nil {
		t.Fatal(err)
	}

	var env struct {
		V     int               `json:"v"`
		Kind  string            `json:"kind"`
		Items []json.RawMessage `json:"items"`
	}

	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatal(err)
	}

	if env.Kind != KindBatch || env.V != Version {
		t.Errorf("envelope = v%d/%q, want v%d/%q", env.V, env.Kind, Version, KindBatch)
	}

	if len(env.Items) != 2 {
		t.Errorf("items = %d, want 2", len(env.Items))
	}
}

// Одиночное событие пачкой не притворяется.
func TestUnpackRejectsPlainEvent(t *testing.T) {
	req := request("s")
	one, err := json.Marshal(Build(req, protocol.NewReply(req, protocol.VerdictAllow), Details{}))
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := Unpack(one); ok {
		t.Error("a plain event must not read as a batch")
	}
}

/*
 * Subject приезжает в сообщении и у разных запросов разный: события разных
 * веток не должны оказаться в одном сообщении, иначе половина уедет не туда.
 */
func TestGroupBySubjectSplitsAndKeepsOrder(t *testing.T) {
	order, bySubject := groupBySubject([]item{
		{subject: "waf.audit.inspector.modsec", body: []byte(`{"ray":"r1"}`)},
		{subject: "waf.audit.inspector.other", body: []byte(`{"ray":"r2"}`)},
		{subject: "waf.audit.inspector.modsec", body: []byte(`{"ray":"r3"}`)},
	})

	if len(order) != 2 || order[0] != "waf.audit.inspector.modsec" {
		t.Fatalf("order = %v, want modsec first", order)
	}

	if len(bySubject[order[0]]) != 2 || len(bySubject[order[1]]) != 1 {
		t.Errorf("groups = %d / %d, want 2 and 1",
			len(bySubject[order[0]]), len(bySubject[order[1]]))
	}
}

/*
 * Деталей не ждут -- ничего не копим. Это то же правило, что было у Publish:
 * решает поле сообщения, а не инспектор.
 */
func TestAddSkipsWhenNoAuditSubject(t *testing.T) {
	s := &Sink{nc: &nats.Conn{}}
	req := request("")

	if err := s.Add(req, protocol.NewReply(req, protocol.VerdictAllow), Details{}); err != nil {
		t.Fatal(err)
	}

	empty := ""
	req.AuditSubject = &empty

	if err := s.Add(req, protocol.NewReply(req, protocol.VerdictAllow), Details{}); err != nil {
		t.Fatal(err)
	}

	if len(s.pending) != 0 {
		t.Errorf("pending = %d, want none", len(s.pending))
	}
}

// Приёмник без соединения молчит, а не ошибается: инспектор без шины всё
// равно обязан отвечать модулю.
func TestAddWithoutConnIsSilent(t *testing.T) {
	var s *Sink
	req := request("s")

	if err := s.Add(req, protocol.NewReply(req, protocol.VerdictAllow), Details{}); err != nil {
		t.Fatalf("nil sink: %v", err)
	}

	if err := (&Sink{}).Add(req, protocol.NewReply(req, protocol.VerdictAllow), Details{}); err != nil {
		t.Fatalf("nil conn: %v", err)
	}
}

// Переполнение буфера режет голову и считается.
func TestAddDropsOldestAndCounts(t *testing.T) {
	s := &Sink{nc: &nats.Conn{}}
	req := request("waf.audit.inspector.modsec")
	reply := protocol.NewReply(req, protocol.VerdictAllow)

	for i := 0; i < maxPending+10; i++ {
		if err := s.Add(req, reply, Details{}); err != nil {
			t.Fatal(err)
		}
	}

	if len(s.pending) != maxPending {
		t.Fatalf("pending = %d, want %d", len(s.pending), maxPending)
	}

	if s.Dropped() != 10 {
		t.Errorf("dropped = %d, want 10", s.Dropped())
	}

	if s.size != sizeOf(s.pending) {
		t.Errorf("size = %d, want %d: the running size drifted from the buffer",
			s.size, sizeOf(s.pending))
	}
}
