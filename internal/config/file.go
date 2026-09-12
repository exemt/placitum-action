/*
 * inspector.conf — nginx-подобный файл инспектора.
 *
 *   queue_max 16;
 *   queue_full drop;
 *   queue_expand off;
 *
 *   redis {
 *       url       redis://redis:6379;
 *       internal  redis://redis-internal:6379;
 *   }
 *
 * Незнакомая директива или ключ — ошибка старта: опечатка не должна молча
 * оставить умолчание. Отсутствующий файл — не ошибка, остаются значения из
 * кода и env.
 *
 * Блок redis — одна форма адресов на весь контур, так же он пишется в
 * agent.conf у краёв. url — общий обменник: объекты запроса (тела, заголовки,
 * строка запроса), которые модуль кладёт по локатору, читают инспекторы и
 * забирает агент. internal — внутренний Redis контура: всё остальное (блобы
 * поколений, корзины, роастеры, состояние keeper). Окружение перекрывает
 * файл: REDIS_URL — url, REDIS_INTERNAL_URL — internal. Ключ, которого
 * инспектор не читает, — ошибка старта (noExchangeRedis, noInternalRedis).
 *
 * Файл один на все копии этого пакета (одинаковый у всех Go-инспекторов).
 */

package config

import (
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"unicode"
)

const (
	QueueFullDrop = "drop"
	QueueFullWait = "wait"

	QueueExpandOff = "off"
	QueueExpandAsk = "ask"
)

// InternalFromExchange — источник адреса внутреннего Redis, когда его не
// задали ни окружением, ни файлом: процесс пишет своё состояние в обменник.
// Рабочий режим одного Redis, но на контуре с двумя это забытый адрес.
const InternalFromExchange = "exchange"

type queueFile struct {
	Max    *int
	Full   string
	Expand string

	// RedisURL, RedisInternal — ключи url и internal блока redis.
	RedisURL      string
	RedisInternal string
}

func confPath(envName string) string {
	if v, ok := os.LookupEnv(envName); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}

	for _, candidate := range []string{"inspector.conf", "/app/inspector.conf"} {
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate
		}
	}

	return ""
}

func loadQueueFile(path string) (queueFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return queueFile{}, fmt.Errorf("%s: %w", path, err)
	}

	return parseQueueFile(path, string(raw))
}

func parseQueueFile(name, src string) (queueFile, error) {
	var out queueFile
	seen := map[string]bool{}
	block, opened := "", 0

	for i, line := range strings.Split(src, "\n") {
		n := i + 1

		text := confText(line)
		if text == "" {
			continue
		}

		if block != "" {
			if text == "}" {
				block = ""
				continue
			}

			if err := parseRedisKey(&out, seen, text); err != nil {
				return queueFile{}, fmt.Errorf("%s:%d: %w", name, n, err)
			}

			continue
		}

		if text == "}" {
			return queueFile{}, fmt.Errorf("%s:%d: unexpected }", name, n)
		}

		if head, ok := strings.CutSuffix(text, "{"); ok {
			head = strings.TrimSpace(head)
			if head != "redis" {
				return queueFile{}, fmt.Errorf("%s:%d: unknown block %q", name, n, head)
			}

			if seen[head] {
				return queueFile{}, fmt.Errorf("%s:%d: %s block is set twice", name, n, head)
			}

			seen[head] = true
			block, opened = head, n

			continue
		}

		stmt, err := requireSemicolon(text)
		if err != nil {
			return queueFile{}, fmt.Errorf("%s:%d: %w", name, n, err)
		}

		key, value, err := splitDirective(stmt)
		if err != nil {
			return queueFile{}, fmt.Errorf("%s:%d: %w", name, n, err)
		}

		if seen[key] {
			return queueFile{}, fmt.Errorf("%s:%d: %s is set twice", name, n, key)
		}

		seen[key] = true

		switch key {
		case "queue_max":
			v, err := strconv.Atoi(value)
			if err != nil || v < 1 {
				return queueFile{}, fmt.Errorf("%s:%d: queue_max must be a positive integer, got %q",
					name, n, value)
			}

			out.Max = &v

		case "queue_full":
			switch value {
			case QueueFullDrop, QueueFullWait:
				out.Full = value
			default:
				return queueFile{}, fmt.Errorf("%s:%d: queue_full must be drop or wait, got %q",
					name, n, value)
			}

		case "queue_expand":
			switch value {
			case QueueExpandOff, QueueExpandAsk:
				out.Expand = value
			default:
				return queueFile{}, fmt.Errorf("%s:%d: queue_expand must be off or ask, got %q",
					name, n, value)
			}

		default:
			return queueFile{}, fmt.Errorf("%s:%d: unknown directive %q", name, n, key)
		}
	}

	if block != "" {
		return queueFile{}, fmt.Errorf("%s:%d: %s block is not closed", name, opened, block)
	}

	return out, nil
}

// parseRedisKey — одна строка внутри блока redis: url или internal.
func parseRedisKey(out *queueFile, seen map[string]bool, text string) error {
	stmt, err := requireSemicolon(text)
	if err != nil {
		return err
	}

	key, value, err := splitDirective(stmt)
	if err != nil {
		return err
	}

	id := "redis." + key
	if seen[id] {
		return fmt.Errorf("redis %s is set twice", key)
	}

	seen[id] = true

	if key != "url" && key != "internal" {
		return fmt.Errorf("unknown key %q in the redis block, want url or internal", key)
	}

	if !isRedisURL(value) {
		return fmt.Errorf("redis %s must be redis://host:port[/db] or rediss://..., got %q", key, value)
	}

	if key == "url" {
		out.RedisURL = value
	} else {
		out.RedisInternal = value
	}

	return nil
}

func isRedisURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return false
	}

	return u.Scheme == "redis" || u.Scheme == "rediss"
}

// exchangeRedis — адрес общего обменника: REDIS_URL, затем url блока redis.
func exchangeRedis(file queueFile) string {
	if v, ok := os.LookupEnv("REDIS_URL"); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}

	return file.RedisURL
}

/*
 * internalRedis выбирает адрес внутреннего Redis контура и называет, откуда
 * он взят: окружение REDIS_INTERNAL_URL, затем internal блока redis файла
 * path, затем обменник exchange -- откат на один Redis, как до разделения.
 * Пустой exchange откат выключает: процесс без обменника (ip) остаётся без
 * адреса.
 */
func internalRedis(path string, file queueFile, exchange string) (string, string) {
	if v, ok := os.LookupEnv("REDIS_INTERNAL_URL"); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v), "REDIS_INTERNAL_URL"
	}

	if file.RedisInternal != "" {
		return file.RedisInternal, path
	}

	if exchange != "" {
		return exchange, InternalFromExchange
	}

	return "", ""
}

/*
 * noInternalRedis и noExchangeRedis -- для инспекторов, которые в этот Redis
 * не ходят: адрес, который никто не читает, та же опечатка, что незнакомый
 * ключ.
 */
func noInternalRedis(path string, file queueFile) error {
	if file.RedisInternal != "" {
		return fmt.Errorf("%s: redis internal: this inspector keeps no state in Redis, remove the key", path)
	}

	return nil
}

func noExchangeRedis(path string, file queueFile) error {
	if file.RedisURL != "" {
		return fmt.Errorf("%s: redis url: this inspector does not read the exchange, remove the key", path)
	}

	return nil
}

/*
 * LogInternalRedis пишет при старте, куда процесс ходит за блобами и своим
 * состоянием и откуда взят адрес. Откат на обменник и отсутствие адреса --
 * предупреждения: служебные ключи в обменнике едят память, из которой живут
 * тела запросов, а без адреса состояние не общее у реплик. Пароль из адреса
 * в журнал не попадает.
 */
func LogInternalRedis(log *slog.Logger, addr, from string) {
	const hint = "set internal in the redis block of inspector.conf or REDIS_INTERNAL_URL"

	switch from {
	case "":
		log.Warn("internal redis is not configured", "detail", hint)
	case InternalFromExchange:
		log.Warn("internal redis falls back to the exchange",
			"url", redactURL(addr), "from", from, "detail", hint)
	default:
		log.Info("internal redis", "url", redactURL(addr), "from", from)
	}
}

func redactURL(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return "<unparsable>"
	}

	return u.Redacted()
}

// confText — строка без комментария и пробелов по краям.
func confText(line string) string {
	if i := strings.Index(line, "#"); i >= 0 {
		line = line[:i]
	}

	return strings.TrimSpace(line)
}

func requireSemicolon(text string) (string, error) {
	if !strings.HasSuffix(text, ";") {
		return "", fmt.Errorf("missing semicolon")
	}

	return strings.TrimSpace(strings.TrimSuffix(text, ";")), nil
}

func splitDirective(stmt string) (string, string, error) {
	stmt = strings.TrimSpace(stmt)
	if stmt == "" {
		return "", "", fmt.Errorf("empty directive")
	}

	key, rest, ok := strings.Cut(stmt, " ")
	if !ok {
		return "", "", fmt.Errorf("directive %q has no value", stmt)
	}

	if !isConfName(key) {
		return "", "", fmt.Errorf("invalid directive name %q", key)
	}

	value := strings.TrimSpace(rest)
	if value == "" || strings.ContainsAny(value, " \t") {
		return "", "", fmt.Errorf("directive %s expects one value", key)
	}

	return key, value, nil
}

func isConfName(s string) bool {
	if s == "" {
		return false
	}

	for _, r := range s {
		if r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}

	return true
}

func applyQueueFile(c *queueSettings, file queueFile) {
	if file.Max != nil {
		c.Max = *file.Max
	}

	if file.Full != "" {
		c.Full = file.Full
	}

	if file.Expand != "" {
		c.Expand = file.Expand
	}
}

type queueSettings struct {
	Max    int
	Full   string
	Expand string
}

func envOverride(name, current string) string {
	if v, ok := os.LookupEnv(name); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}

	return current
}
