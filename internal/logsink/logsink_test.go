package logsink

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

// Уровень едет в таблицу из той же строки, что и текст: без него access от
// error не отличить, а «покажи ошибки» -- первый вопрос к журналу.
func TestSeverityFromSlogLine(t *testing.T) {
	cases := map[string]string{
		`{"time":"2026-08-24T10:00:00Z","level":"INFO","msg":"connected"}`: "info",
		`{"time":"2026-08-24T10:00:00Z","level":"WARN","msg":"bus down"}`:  "warn",
		`{"time":"2026-08-24T10:00:00Z","level":"ERROR","msg":"boom"}`:     "error",
		`{"time":"2026-08-24T10:00:00Z","level":"DEBUG","msg":"tick"}`:     "debug",
		`{"time":"2026-08-24T10:00:00Z","level":"INFO+2","msg":"loud"}`:    "info",
		`{"time":"2026-08-24T10:00:00Z","msg":"no level at all"}`:          "",
	}

	for line, want := range cases {
		if got := severity([]byte(line)); got != want {
			t.Fatalf("severity(%s) = %q, ждали %q", line, got, want)
		}
	}
}

// Обработчик slog настоящий: разбор держится на том, каким его печатает
// стандартная библиотека, и проверять это подделкой строки бессмысленно.
func TestWriteTakesSlogLine(t *testing.T) {
	s := New("edge-01", "ip", nil)
	defer s.Close()

	log := slog.New(slog.NewJSONHandler(s, &slog.HandlerOptions{Level: slog.LevelDebug}))
	log.Warn("policy reload failed", "error", "no such file")

	lines := s.take()
	if len(lines) != 1 {
		t.Fatalf("строк: %d", len(lines))
	}

	if lines[0].Severity != "warn" {
		t.Fatalf("severity: %q", lines[0].Severity)
	}

	if lines[0].Service != "ip" {
		t.Fatalf("service: %q", lines[0].Service)
	}

	if !strings.Contains(lines[0].Text, `"msg":"policy reload failed"`) {
		t.Fatalf("text: %q", lines[0].Text)
	}

	if strings.HasSuffix(lines[0].Text, "\n") {
		t.Fatalf("перевод строки остался в тексте: %q", lines[0].Text)
	}

	if lines[0].TS.IsZero() {
		t.Fatal("нет отметки времени")
	}
}

// Конверт разбирает logger/internal/model.FromLog. Форма общая с агентом, и
// расхождение здесь означает молча пустую таблицу.
func TestBatchEnvelope(t *testing.T) {
	s := New("waf-ip-1", "ip", nil)
	defer s.Close()

	body, err := json.Marshal(batch{
		V:      Version,
		Kind:   Kind,
		Writer: s.writer,
		Lines:  []Line{{Service: "ip", Severity: "info", Text: "hello"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	var got struct {
		V      int    `json:"v"`
		Kind   string `json:"kind"`
		Writer string `json:"writer"`
		Lines  []struct {
			TS       string `json:"ts"`
			Service  string `json:"service"`
			Severity string `json:"severity"`
			Text     string `json:"text"`
		} `json:"lines"`
	}

	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}

	if got.V != 1 || got.Kind != "log" || got.Writer != "waf-ip-1" {
		t.Fatalf("конверт: %s", body)
	}

	if len(got.Lines) != 1 || got.Lines[0].Text != "hello" || got.Lines[0].Service != "ip" {
		t.Fatalf("строки: %s", body)
	}
}

// Шина недоступна дольше, чем помещается в буфер: выбрасываем голову. Свежая
// строка объясняет, что происходит сейчас.
func TestOverflowDropsHead(t *testing.T) {
	s := New("edge-01", "ip", nil)
	defer s.Close()

	for i := 0; i < maxPending+10; i++ {
		s.add(Line{Text: "line"})
	}

	if got := s.Dropped(); got != 10 {
		t.Fatalf("выброшено: %d", got)
	}

	s.mu.Lock()
	n := len(s.pending)
	s.mu.Unlock()

	if n != maxPending {
		t.Fatalf("в буфере: %d", n)
	}
}

// Без шины пачки не уезжают, но и не пропадают: строки старта -- ровно те,
// ради которых приёмник поднимается раньше подключения.
func TestFlushHoldsUntilAttach(t *testing.T) {
	s := New("edge-01", "ip", nil)
	defer s.Close()

	s.add(Line{Text: "before the bus"})
	s.flush()

	s.mu.Lock()
	n := len(s.pending)
	s.mu.Unlock()

	if n != 1 {
		t.Fatalf("строка потеряна до Attach: осталось %d", n)
	}
}

// Выключенный канал -- рабочее состояние: main не разводит ветками ни вывод,
// ни завершение.
func TestNilSinkIsUsable(t *testing.T) {
	var s *Sink

	out := &bytes.Buffer{}

	log := slog.New(slog.NewJSONHandler(s.Tee(out), nil))
	log.Info("still on stdout")

	s.Attach(nil)
	s.Close()

	if s.Dropped() != 0 || s.Failed() != 0 {
		t.Fatal("счётчики выключенного приёмника")
	}

	if !strings.Contains(out.String(), "still on stdout") {
		t.Fatalf("вывод: %q", out.String())
	}
}

// Имя писателя приезжает из окружения, а разделители шины в нём ломали бы
// subject молча.
func TestSubject(t *testing.T) {
	if got := Subject("edge-01"); got != "waf.log.edge-01" {
		t.Fatalf("subject: %q", got)
	}

	if got := Subject("host.example.com"); got != "waf.log.host.example.com" {
		t.Fatalf("точка -- обычный токен: %q", got)
	}

	if got := Subject("a b>c*"); got != "waf.log.a_b_c_" {
		t.Fatalf("subject: %q", got)
	}

	if got := Subject(""); got != "waf.log.unknown" {
		t.Fatalf("subject: %q", got)
	}
}

// take -- только для тестов: снять накопленное, не публикуя.
func (s *Sink) take() []Line {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := s.pending
	s.pending = nil
	s.size = 0

	return out
}
