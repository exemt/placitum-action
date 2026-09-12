/*
 * Запись исходов в активные наборы -- через keeper (docs/keeper.md).
 *
 * Событие -- запрос с ответом на waf.sets.<набор>.event: keeper пишет запись
 * в обменник, применяет в памяти, издаёт дельту и отвечает. Инспектор зовёт
 * запись после вердикта, и ждать ответа keeper в его рабочем цикле незачем:
 * бан нужен следующим запросам и соседним нодам, а не этому. Поэтому запрос
 * уходит в фоне, отказ (full, store_unavailable) -- строка в логе.
 */

package dataset

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
)

// Version -- версия кадра события.
const Version = 3

const (
	OpAdd    = "add"
	OpRemove = "remove"

	requestTimeout = 5 * time.Second
)

type Event struct {
	V     int    `json:"v"`
	Set   string `json:"set"`
	Op    string `json:"op"`
	Value string `json:"value,omitempty"`
	// Values -- пачка одной операции с общими сроком и поводом; keeper
	// принимает её целиком или никак (docs/keeper.md, «Пачка»).
	Values []string `json:"values,omitempty"`
	TTL    int      `json:"ttl,omitempty"`
	Origin string   `json:"origin"`
	Reason string   `json:"reason,omitempty"`
}

type Reply struct {
	OK    bool   `json:"ok"`
	Seq   uint64 `json:"seq,omitempty"`
	Error string `json:"error,omitempty"`
	Limit int    `json:"limit,omitempty"`
}

type Publisher struct {
	nc     *nats.Conn
	origin string
	log    *slog.Logger
}

func New(nc *nats.Conn, origin string) *Publisher {
	if origin == "" {
		origin = "action"
	}

	return &Publisher{nc: nc, origin: origin, log: slog.Default()}
}

// Add кладёт значение в набор на срок. TTL обязателен: keeper отвергает add
// без него. Набор адресуется именем: waf.sets.<имя>.
func (p *Publisher) Add(name, value string, ttl time.Duration, reason string) error {
	if ttl <= 0 {
		return fmt.Errorf("dataset add without ttl")
	}

	return p.send(&Event{
		Op:     OpAdd,
		Set:    name,
		Value:  value,
		TTL:    int(ttl.Seconds()),
		Reason: reason,
	})
}

/*
 * AddMany кладёт пачку значений одним кадром: один запрос, один ответ, одно
 * окно секвенсора, одна дельта зеркалам -- и либо вся пачка, либо никак. Так
 * уезжают анонсы, накрывающие адрес, и состав системы: сотни префиксов по
 * одному значили бы ждать окно на каждом.
 */
func (p *Publisher) AddMany(name string, values []string, ttl time.Duration, reason string) error {
	if ttl <= 0 {
		return fmt.Errorf("dataset add without ttl")
	}

	switch len(values) {
	case 0:
		return nil

	case 1:
		return p.Add(name, values[0], ttl, reason)
	}

	return p.send(&Event{
		Op:     OpAdd,
		Set:    name,
		Values: values,
		TTL:    int(ttl.Seconds()),
		Reason: reason,
	})
}

func (p *Publisher) Remove(name, value, reason string) error {
	return p.send(&Event{
		Op:     OpRemove,
		Set:    name,
		Value:  value,
		Reason: reason,
	})
}

// check -- у события есть набор и хоть одно значение: одиночное либо пачка.
func (ev *Event) check() error {
	if ev.Set == "" || (ev.Value == "" && len(ev.Values) == 0) {
		return fmt.Errorf("dataset event needs set and value")
	}

	return nil
}

// first -- значение для строки журнала: одиночное либо первое из пачки.
func (ev *Event) first() string {
	if ev.Value != "" || len(ev.Values) == 0 {
		return ev.Value
	}

	return ev.Values[0]
}

func (p *Publisher) send(ev *Event) error {
	if p == nil || p.nc == nil {
		return nil
	}

	if err := ev.check(); err != nil {
		return err
	}

	ev.V = Version
	ev.Origin = p.origin

	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}

	subject := "waf.sets." + ev.Set + ".event"
	count := max(len(ev.Values), 1)

	go func() {
		msg, err := p.nc.Request(subject, body, requestTimeout)
		if err != nil {
			p.log.Warn("list write failed: keeper unreachable",
				"set", ev.Set, "value", ev.first(), "count", count, "error", err.Error())

			return
		}

		var reply Reply
		if json.Unmarshal(msg.Data, &reply) == nil && !reply.OK {
			p.log.Warn("list write rejected",
				"set", ev.Set, "value", ev.first(), "count", count,
				"error", reply.Error, "limit", reply.Limit)
		}
	}()

	return nil
}
