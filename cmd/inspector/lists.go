/*
 * Записи правил профиля в живые наборы.
 *
 * Адрес клиента пишется как есть. Анонсы (net -- эффективный, net_all -- все
 * накрывающие) и состав системы (asn) -- у кодера, синхронно, в бюджете
 * сообщения: модулю всё равно ждать инспектора, а «пусто на первом запросе»
 * -- это молча несостоявшийся бан. Сама запись уходит keeper в фоне, одним
 * кадром на строку: и адрес, и сотни префиксов системы -- вся пачка или никак.
 *
 * Ошибка -- только от кодера: строка требует анонс или состав системы, а кодер
 * молчит либо его нет. Запись не состоится, и молча пропустить её нельзя --
 * бан, которого не было, выглядит как бан, -- поэтому вызывающий отвечает
 * error, а что делать с запросом, решает waf_exception маршрута. Так же
 * отвечают капча и остальные отправители. Строки, которым кодер не нужен,
 * пишутся всё равно: адрес от него не зависит.
 */

package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/exemt/placitum-action/internal/policy"
	"github.com/exemt/placitum-shared/netinfo"
)

/*
 * Кодер и наборы -- за интерфейсами, чтобы путь записи проверялся без шины и
 * без gRPC. Боевые реализации -- netinfo.Resolver и dataset.Publisher; обе
 * nil-безопасны: nil-кодер отвечает «недоступен», nil-набор молчит.
 */
type geoWriter interface {
	Write(ctx context.Context, write, addr string) ([]string, error)
}

type listWriter interface {
	AddMany(name string, values []string, ttl time.Duration, reason string) error
}

func writeLists(ctx context.Context, geo geoWriter, lists listWriter, log *slog.Logger,
	rid, addr string, writes []policy.Write) error {

	// Сообщение пробы приходит без адреса: писать некого.
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
