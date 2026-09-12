/*
 * Пачка событий kind=inspector вместо сообщения на инспекцию.
 *
 * Инспектор пишет запись на каждую инспекцию, и при четырёх инспекторах в
 * наборе поток аудита выходит впятеро больше rps -- три четверти его создаёт
 * не агент, а вот эти публикации. Потребитель вставляет в ClickHouse партиями,
 * и партия из одного сообщения -- это партия из одной строки.
 *
 * Формат тот же, что у пачки агента (nginx/agent/internal/audit/sink.go):
 * конверт kind=batch, в items -- ровно те байты, которые уехали бы отдельными
 * сообщениями. Потребителю от этого не нужен новый разбор события.
 *
 * Subject берётся из сообщения модуля и у разных запросов разный, поэтому
 * пачка режется по нему: складывать событие в чужую ветку нельзя.
 */

package audit

import (
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-action/internal/protocol"
)

// KindBatch -- вид сообщения-пачки. Соседствует с Kind по потоку и субъекту:
// пачка едет туда же, куда ехало бы каждое её событие.
const KindBatch = "batch"

const (
	/*
	 * Границы пачки. События по килобайту, поэтому двести пятьдесят шесть
	 * штук -- заметно меньше max_payload шины, а полмегабайта закрывают
	 * случай движка, который пишет длинные находки.
	 */
	maxItems = 256
	maxSize  = 512 << 10

	/*
	 * Темп отправки при редком трафике. Пятьдесят миллисекунд задержки в
	 * журнале не видно, и они же не дают держать событие в памяти инспектора,
	 * пока не наберётся пачка.
	 */
	flushEvery = 50 * time.Millisecond

	/*
	 * Потолок буфера при недоступной шине. Дальше выбрасываем самые старые:
	 * инспектор, растущий без границы, меняет потерю аудита на потерю
	 * инспектора -- а его молчание модуль читает как перегрузку.
	 */
	maxPending = 50000
)

// item -- готовое событие и subject, на который оно едет.
type item struct {
	subject string
	body    []byte
}

// envelope -- конверт пачки. Node здесь нет: у событий инспектора он свой в
// каждом, а группирует их subject.
type envelope struct {
	V     int               `json:"v"`
	Kind  string            `json:"kind"`
	Items []json.RawMessage `json:"items"`
}

// Sink копит события и отправляет их пачками. Публикация идёт из своей
// горутины: обработчик не должен ждать шину после того, как ответил в inbox.
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

/*
 * Add кладёт событие в пачку.
 *
 * Молчит, когда деталей не ждут. Проверяется именно поле сообщения: инспектор
 * не решает сам, куда и надо ли писать, -- иначе выключить болтливый движок
 * оператор мог бы только пересборкой сервиса.
 */
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

	/*
	 * Шина недоступна дольше, чем помещается в буфер. Выбрасываем голову, а
	 * не хвост: свежее событие объясняет, что происходит сейчас. Потеря
	 * считается -- молча терять аудит нельзя.
	 */
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

// Dropped -- сколько событий выброшено переполнением буфера за всё время.
func (s *Sink) Dropped() uint64 {
	if s == nil {
		return 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.dropped
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

// groupBySubject раскладывает взятое по субъектам, сохраняя порядок первого
// появления: пачки должны уходить предсказуемо, а не в порядке обхода карты.
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

/*
 * pack собирает конверт пачки. Тела событий вкладываются как есть: повторный
 * разбор с пересборкой менял бы представление чисел и порядок полей, а с той
 * стороны это тот же байтовый поток, что и одиночное сообщение.
 */
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

// Close добивает накопленное и останавливает отправку. Вызывается после того,
// как встал пул: в очереди события уже отвеченных запросов.
func (s *Sink) Close() {
	if s == nil {
		return
	}

	s.once.Do(func() {
		close(s.stop)
		<-s.done
	})
}

// Unpack разбирает пачку на события. Живёт рядом с упаковкой, чтобы формат
// проверялся с обеих сторон одним тестом.
func Unpack(payload []byte) ([]json.RawMessage, bool) {
	var env envelope

	if err := json.Unmarshal(payload, &env); err != nil || env.Kind != KindBatch {
		return nil, false
	}

	return env.Items, true
}
