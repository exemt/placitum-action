/*
 * Журнал процесса в общий обменник: та же таблица waf.log, что и у строк nginx.
 *
 * У nginx дорога идёт через сокет ноды (nginx/agent/internal/nginxlog): писать
 * в syslog он умеет сам, а своего клиента шины у него нет. У инспектора всё
 * наоборот — шина подключена по построению, а агента ноды рядом может не быть
 * вовсе: инспектор живёт своим контейнером, масштабируется своей очередью и
 * переживает любую отдельную ноду. Поэтому здесь нет приёмника, есть только
 * вторая половина той же дороги: пачка kind=log в тот же WAF_LOG, откуда
 * логгер кладёт строки в waf.log.
 *
 * Копия, а не перенос. Строка по-прежнему уходит в stdout, и
 * `docker compose logs inspector-ip` остаётся первым местом, куда смотрят, —
 * в том числе когда лежит сам контур доставки. Шина здесь добавляет то, чего у
 * docker нет: один журнал на весь флот, окно по времени и подстрока по тексту.
 *
 * Пачка, а не сообщение на строку, и границы те же, что у агента: 500 строк,
 * 256 КБ, 200 мс. Инспектор в норме пишет редко, но «в норме» — это не тот
 * режим, ради которого журнал вообще собирают: на разборе он захлёбывается
 * предупреждениями, и как раз тогда пачка и нужна.
 *
 * Своей публикации ошибок здесь нет и быть не может: журнал, который пишет в
 * журнал о том, что не смог написать в журнал, — это петля. Потери едут
 * ошибками канала `log` в секции `io` кадра присутствия, там их и видно.
 */

package logsink

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-shared/flow"
)

const (
	Stream  = "WAF_LOG"
	Kind    = "log"
	Version = 1

	// maxText — потолок текста строки, тот же, что у агента и у логгера.
	// Строка журнала процесса — это одна запись slog, и запись в килобайты
	// длиной означает, что в неё положили тело, а не событие.
	maxText = 8 << 10

	// Границы пачки. Совпадают с nginxlog: одна форма на проводе — одна
	// настройка на контуре, и повод разойтись должен быть у канала свой.
	maxLines = 500
	maxSize  = 256 << 10

	// Темп отправки при редком журнале. Двести миллисекунд не видно в
	// расследовании и они же не дают держать строку в памяти процесса,
	// пока не наберётся пачка.
	flushEvery = 200 * time.Millisecond

	// Потолок буфера при недоступной шине. Дальше выбрасываем самые старые:
	// свежая строка объясняет, что происходит сейчас, и она нужнее той, что
	// не уехала минуту назад.
	maxPending = 20000

	MaxAge      = 24 * time.Hour
	StreamBytes = 128 << 20
)

// Subject — куда едет пачка. Тот же `waf.log.<писатель>`, что у агента:
// поток один, и различать в нём процессы по subject значило бы заводить
// consumer на каждый вид писателя.
func Subject(writer string) string {
	if writer == "" {
		writer = "unknown"
	}

	return "waf.log." + token(writer)
}

// Line — одна строка журнала, как её увидит обменник. Форма общая с агентом:
// логгер разбирает обе пачки одним model.FromLog.
type Line struct {
	TS       time.Time `json:"ts"`
	Service  string    `json:"service"`
	Severity string    `json:"severity,omitempty"`
	Text     string    `json:"text"`
}

// batch — то, что уезжает одним сообщением. Writer на конверте, а не на
// каждой строке: пачку собирает один процесс.
type batch struct {
	V      int    `json:"v"`
	Kind   string `json:"kind"`
	Writer string `json:"writer"`
	Lines  []Line `json:"lines"`
}

/*
 * Sink копит строки и отправляет их пачками. Публикация идёт из своей
 * горутины: slog не должен ждать шину на вызове log.Info.
 *
 * Nil-приёмник — рабочее состояние, а не ошибка: он значит «журнал только в
 * stdout», и все методы его переживают. Так выключение канала не расходится
 * по mains ветками if.
 */
type Sink struct {
	writer  string
	service string
	io      *flow.Counter

	mu      sync.Mutex
	nc      *nats.Conn
	pending []Line
	size    int
	dropped uint64
	failed  uint64

	wake chan struct{}
	done chan struct{}
	stop chan struct{}
	once sync.Once
}

/*
 * New поднимает приёмник до подключения к шине. Порядок именно такой: конфиг
 * читается раньше NATS, а строки о том, как читался конфиг, — ровно те,
 * которые нужнее всего. До Attach они копятся в буфере и уезжают первой же
 * пачкой.
 *
 * writer — кто записал (контейнер, нода), service — что за процесс. Обе
 * колонки waf.log ищутся точным совпадением, поэтому пустыми их не оставляем.
 */
func New(writer, service string, io *flow.Counter) *Sink {
	if writer == "" {
		writer = "unknown"
	}

	if service == "" {
		service = "unknown"
	}

	s := &Sink{
		writer:  writer,
		service: service,
		io:      io,
		wake:    make(chan struct{}, 1),
		done:    make(chan struct{}),
		stop:    make(chan struct{}),
	}

	go s.loop()

	return s
}

// Attach включает публикацию. До неё пачки не уезжают, но копятся.
func (s *Sink) Attach(nc *nats.Conn) {
	if s == nil || nc == nil {
		return
	}

	s.mu.Lock()
	s.nc = nc
	s.mu.Unlock()

	s.kick()
}

/*
 * Tee подмешивает приёмник к обычному выводу. Возвращает сам out, если
 * приёмника нет: в этом и смысл nil-приёмника — main не знает, включён канал
 * или нет, и строит обработчик slog одинаково.
 */
func (s *Sink) Tee(out io.Writer) io.Writer {
	if s == nil {
		return out
	}

	return io.MultiWriter(out, s)
}

/*
 * Write — io.Writer для обработчика slog: одна запись — один вызов.
 *
 * Строка едет в таблицу ровно той же, какой её напечатали в stdout. Это не
 * лень, а то же правило, что у nginx: в журнале хочется видеть то, что видно
 * в docker, а не его пересказ. Отдельная разметка полей здесь стоила бы
 * второго прохода кодирования на каждую запись и второй формы, которая
 * разошлась бы с первой на первом же добавленном поле.
 *
 * Не блокирует и не ошибается: slog держит на этом вызове свой мьютекс, и
 * ожидание здесь останавливало бы весь процесс.
 */
func (s *Sink) Write(p []byte) (int, error) {
	if s == nil {
		return len(p), nil
	}

	text := strings.TrimRight(string(p), "\x00\r\n")
	if text == "" {
		return len(p), nil
	}

	if len(text) > maxText {
		text = text[:maxText]
	}

	s.add(Line{
		TS:       time.Now().UTC(),
		Service:  s.service,
		Severity: severity(p),
		Text:     text,
	})

	return len(p), nil
}

// Writer — чем подписан журнал. Отдаётся наружу ради одной строки на старте:
// расхождение писателя с именем в кадре присутствия — ровно тот случай, когда
// строки в таблице есть, а найти их по ожидаемому имени нельзя.
func (s *Sink) Writer() string {
	if s == nil {
		return ""
	}

	return s.writer
}

// Dropped — сколько строк выброшено переполнением буфера за всё время.
func (s *Sink) Dropped() uint64 {
	if s == nil {
		return 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.dropped
}

// Failed — сколько строк потеряно сорванной публикацией.
func (s *Sink) Failed() uint64 {
	if s == nil {
		return 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.failed
}

// Close добивает накопленное и останавливает отправку.
func (s *Sink) Close() {
	if s == nil {
		return
	}

	s.once.Do(func() {
		close(s.stop)
		<-s.done
	})
}

func (s *Sink) add(line Line) {
	s.mu.Lock()

	s.pending = append(s.pending, line)
	s.size += len(line.Text) + 64

	var cut int

	if len(s.pending) > maxPending {
		cut = len(s.pending) - maxPending
		s.dropped += uint64(cut)
		s.pending = append(s.pending[:0], s.pending[cut:]...)
	}

	full := len(s.pending) >= maxLines || s.size >= maxSize
	s.mu.Unlock()

	// Потеря — ошибка канала, а не строка в журнале: писать о ней тем же
	// логгером значит замкнуть переполнение само на себя.
	if cut > 0 && s.io != nil {
		s.io.AddN(cut, 0, 0, true, 0)
	}

	if full {
		s.kick()
	}
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

		// Шины ещё нет: держим накопленное, а не выбрасываем. Потолок
		// буфера тут и решает, сколько ждать не жалко.
		if s.nc == nil || len(s.pending) == 0 {
			s.mu.Unlock()

			return
		}

		n := len(s.pending)
		if n > maxLines {
			n = maxLines
		}

		lines := make([]Line, n)
		copy(lines, s.pending[:n])

		s.pending = append(s.pending[:0], s.pending[n:]...)
		s.size = 0

		for _, l := range s.pending {
			s.size += len(l.Text) + 64
		}

		nc := s.nc
		s.mu.Unlock()

		s.publish(nc, lines)
	}
}

func (s *Sink) publish(nc *nats.Conn, lines []Line) {
	start := time.Now()

	body, err := json.Marshal(batch{
		V:      Version,
		Kind:   Kind,
		Writer: s.writer,
		Lines:  lines,
	})
	if err == nil {
		err = nc.Publish(Subject(s.writer), body)
	}

	if err != nil {
		s.mu.Lock()
		s.failed += uint64(len(lines))
		s.mu.Unlock()
	}

	if s.io != nil {
		s.io.AddN(len(lines), 0, uint64(len(body)), err != nil, time.Since(start))
	}
}

/*
 * Ensure создаёт поток логов, если его ещё нет. Конфиг совпадает с
 * nginx/agent/internal/nginxlog и tests/streams/streams.sh: поток заводит тот
 * писатель, который пришёл первым, и на контуре без единой поднятой ноды им
 * оказывается инспектор.
 *
 * Публикация в несуществующий поток — тишина, а не ошибка: core-сообщение
 * просто некому запомнить. Отсюда и вызов на старте, а не надежда на соседа.
 */
func Ensure(nc *nats.Conn) error {
	if nc == nil {
		return fmt.Errorf("logsink: nats connection is nil")
	}

	js, err := nc.JetStream()
	if err != nil {
		return err
	}

	_, err = js.AddStream(&nats.StreamConfig{
		Name:      Stream,
		Subjects:  []string{"waf.log.>"},
		Storage:   nats.FileStorage,
		Retention: nats.LimitsPolicy,
		MaxAge:    MaxAge,
		MaxBytes:  StreamBytes,
		Discard:   nats.DiscardOld,
	})
	if err == nil || errors.Is(err, nats.ErrStreamNameAlreadyInUse) {
		return nil
	}

	return err
}

// levelKey — поле уровня в строке, которую печатает slog.NewJSONHandler.
var levelKey = []byte(`"level":"`)

/*
 * severity вынимает уровень из уже напечатанной строки.
 *
 * Разбор собственного вывода — цена того, что форматирует его стандартный
 * обработчик: наружу он не отдаёт ни готовую строку, ни запись, и выбор здесь
 * между этим разбором и вторым кодированием каждой записи ради одного поля.
 * Не нашлось — уровень остаётся пустым: severity в waf.log необязательна, а
 * терять из-за неё строку нельзя.
 */
func severity(p []byte) string {
	at := bytes.Index(p, levelKey)
	if at < 0 {
		return ""
	}

	rest := p[at+len(levelKey):]

	end := bytes.IndexByte(rest, '"')
	if end <= 0 {
		return ""
	}

	name := string(rest[:end])

	// INFO+2 — это тоже info: в колонке закрытый набор syslog-имён, и
	// смещение уровня в нём места не имеет.
	if cut := strings.IndexAny(name, "+-"); cut > 0 {
		name = name[:cut]
	}

	return strings.ToLower(name)
}

// token убирает из имени писателя то, что шина считает разделителем. Точка
// остаётся: `waf.log.>` ловит её как обычный токен, а имя хоста с доменом —
// законный писатель.
func token(s string) string {
	return strings.NewReplacer(">", "_", "*", "_", " ", "_", "\t", "_").Replace(s)
}
