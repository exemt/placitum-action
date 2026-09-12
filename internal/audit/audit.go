/*
 * Событие kind=inspector в WAF_AUDIT. Пишется после ответа в inbox: промах
 * потока не двигает дедлайн волны. Схема -- docs/messages/inspector-audit.schema.ts.
 *
 * Subject приезжает в поле audit_subject сообщения модуля, а не зашит здесь:
 * куда складывать подробности -- часть топологии контура. audit_subject: null
 * означает, что деталей с этого инспектора не ждут.
 *
 * Про сам запрос -- адрес, маршрут, размеры, кто промолчал -- знает модуль, и
 * всё это лежит в его kind=request. Здесь лежит ровно то, чего у модуля нет и
 * взяться не может: что именно сработало внутри движка. Склейка -- по ray.
 */

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

// Version -- версия конверта аудита, своя. Провод модуля и поток аудита живут
// разными жизнями: форма находки может устояться раньше, чем форма сообщения,
// и наоборот.
const Version = 1

// Шкала серьёзности общая на всех инспекторов -- ровно затем, чтобы находки
// разных движков сортировались в одном списке.
const (
	SeverityInfo     = "info"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Где нашли. TargetConn -- свойства соединения, а не содержимое запроса.
const (
	TargetURI  = "uri"
	TargetArgs = "args"
	TargetBody = "body"
	TargetConn = "conn"
)

// Finding -- одна находка. Форма одна на всех инспекторов: правило CRS,
// совпадение списка, класс уязвимости, тип персональных данных.
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

// Details -- то, что знает только сам движок. Остальное событие собирается из
// запроса и ответа, чтобы score события не разошёлся со score ответа.
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

	// Пустой массив, а не null: "инспектор отработал и не нашёл ничего" -- это
	// осмысленный результат, и выглядеть он должен как результат.
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

// Ensure создаёт поток, если его ещё нет. Конфиг совпадает с deploy/t/streams.sh:
// иначе AddStream на уже существующем потоке с другими лимитами не проходит.
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
