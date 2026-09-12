/*
 * Конфигурация процесса из переменных окружения.
 *
 * Каталог профилей проверяется здесь: инспектор, который тихо молчит из-за
 * опечатки в пути, хуже не запустившегося. Содержимое каталога перечитывается
 * на ходу опросом отпечатка.
 */

package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/exemt/placitum-shared/loglevel"
)

type Config struct {
	Servers []string
	Subject string
	Name    string
	Queue   string

	ProfilesDir string
	// DataDir -- куда раскатка кладёт применённое поколение (internal/desired).
	// Пусто в окружении -- <ProfilesDir>.applied.
	DataDir string

	ReloadEvery time.Duration

	Workers     int
	QueueDepth  int
	QueueFull   string
	QueueExpand string
	ConfPath    string
	ReserveMS   int
	MinBudgetMS int

	Versions []int
	LogLevel slog.Level

	HeartbeatEvery time.Duration

	// RedisURL -- обменник объектов: заголовки и строка запроса для условий
	// профиля. Пусто -- условия по заголовкам, кукам и аргументам считают
	// объект недоступным; поля сообщения и vars работают и без него.
	RedisURL string
	// InternalURL -- внутренний Redis контура: оттуда зеркало наборов
	// читает пакеты и снапшоты keeper для условий по спискам. Источник
	// адреса -- в InternalFrom: REDIS_INTERNAL_URL, путь inspector.conf с
	// internal блока redis или REDIS_URL, если внутренний не назван.
	InternalURL  string
	InternalFrom string

	/*
	 * GeoAddr -- gRPC-адрес кодера гео внутри контура (host:port): у него
	 * берутся анонсы и состав системы для записей в набор с write: net |
	 * net_all | asn. Пусто -- такие записи отвечают error, адрес пишется как
	 * обычно. GeoTimeout -- сколько ждать кодер на промахе: ожидание
	 * синхронное и в бюджете сообщения. GeoNegMax -- потолок отрицательного
	 * кэша резолвера, 0 -- его умолчание.
	 */
	GeoAddr    string
	GeoTimeout time.Duration
	GeoNegMax  int
}

// RedisTimeout ограничивает чтение объекта обменника по локатору: поход за
// заголовками внутри бюджета волны, а не вместо него.
const RedisTimeout = 20 * time.Millisecond

func Load() (*Config, error) {
	c := &Config{
		Servers:     splitList(env("NATS_URL", "nats://127.0.0.1:4222")),
		Subject:     env("WAF_ACTION_SUBJECT", "waf.req.action"),
		Name:        env("WAF_ACTION_NAME", "action"),
		ProfilesDir: env("WAF_ACTION_PROFILES", "./profiles"),
		DataDir:     env("WAF_ACTION_DATA", ""),
		GeoAddr:     env("WAF_ACTION_GEO_ADDR", ""),
	}

	c.Queue = env("WAF_ACTION_QUEUE", c.Name)

	var err error

	if c.Workers, err = envInt("WAF_ACTION_WORKERS", runtime.GOMAXPROCS(0)); err != nil {
		return nil, err
	}

	q := queueSettings{
		/*
		 * 256, а не производная от числа воркеров: это число задаёт не только
		 * свою очередь, но и буфер подписки клиента NATS (queue_max + workers
		 * + 2), а буфер меряется темпом прихода на паузу, которую горутина
		 * доставки может пропустить, -- не тем, сколько воркеров за ней стоит.
		 * Прежние workers*8 давали 16 сообщений, это ~2 мс терпения на 10 000
		 * сообщений в секунду, и сообщения терялись молча на обычном дрожании.
		 */
		Max:    256,
		Full:   QueueFullDrop,
		Expand: QueueExpandOff,
	}

	var file queueFile

	c.ConfPath = confPath("WAF_ACTION_CONF")
	if c.ConfPath != "" {
		var ferr error
		if file, ferr = loadQueueFile(c.ConfPath); ferr != nil {
			return nil, ferr
		}

		applyQueueFile(&q, file)
	}

	// Зеркало наборов keeper: REDIS_INTERNAL_URL, затем internal блока redis в
	// inspector.conf, иначе обменник -- с предупреждением в журнале.
	c.RedisURL = exchangeRedis(file)
	c.InternalURL, c.InternalFrom = internalRedis(c.ConfPath, file, c.RedisURL)

	if q.Max, err = envIntIfSet("WAF_ACTION_QUEUE_DEPTH", q.Max); err != nil {
		return nil, err
	}

	c.QueueDepth = q.Max
	c.QueueFull = envOverride("WAF_ACTION_QUEUE_FULL", q.Full)
	c.QueueExpand = envOverride("WAF_ACTION_QUEUE_EXPAND", q.Expand)

	if c.ReserveMS, err = envInt("WAF_ACTION_RESERVE_MS", 1); err != nil {
		return nil, err
	}

	if c.MinBudgetMS, err = envInt("WAF_ACTION_MIN_BUDGET_MS", 1); err != nil {
		return nil, err
	}

	if c.Versions, err = envIntList("WAF_ACTION_VERSIONS", []int{2}); err != nil {
		return nil, err
	}

	if c.LogLevel, err = parseLevel(env("WAF_ACTION_LOG", "info")); err != nil {
		return nil, err
	}

	if c.HeartbeatEvery, err = envDuration("WAF_HEARTBEAT_EVERY", 4*time.Second); err != nil {
		return nil, err
	}

	if c.ReloadEvery, err = envDuration("WAF_ACTION_RELOAD_EVERY", time.Second); err != nil {
		return nil, err
	}

	if c.GeoTimeout, err = envDuration("WAF_ACTION_GEO_TIMEOUT", 500*time.Millisecond); err != nil {
		return nil, err
	}

	if c.GeoNegMax, err = envInt("WAF_ACTION_GEO_NEG_MAX", 0); err != nil {
		return nil, err
	}

	return c, c.validate()
}

func (c *Config) validate() error {
	if len(c.Servers) == 0 {
		return fmt.Errorf("NATS_URL is empty")
	}

	if c.Subject == "" || c.Name == "" || c.Queue == "" {
		return fmt.Errorf("subject, name and queue must not be empty")
	}

	if c.Workers < 1 {
		return fmt.Errorf("WAF_ACTION_WORKERS must be positive, got %d", c.Workers)
	}

	if c.QueueDepth < 1 {
		return fmt.Errorf("queue_max must be positive, got %d", c.QueueDepth)
	}

	switch c.QueueFull {
	case QueueFullDrop, QueueFullWait:
	default:
		return fmt.Errorf("queue_full must be drop or wait, got %q", c.QueueFull)
	}

	switch c.QueueExpand {
	case QueueExpandOff, QueueExpandAsk:
	default:
		return fmt.Errorf("queue_expand must be off or ask, got %q", c.QueueExpand)
	}

	if c.ReserveMS < 0 || c.MinBudgetMS < 0 {
		return fmt.Errorf("WAF_ACTION_RESERVE_MS and WAF_ACTION_MIN_BUDGET_MS must not be negative")
	}

	if len(c.Versions) == 0 {
		return fmt.Errorf("WAF_ACTION_VERSIONS is empty")
	}

	abs, err := filepath.Abs(c.ProfilesDir)
	if err != nil {
		return fmt.Errorf("WAF_ACTION_PROFILES: %w", err)
	}

	st, err := os.Stat(abs)
	if err != nil {
		return fmt.Errorf("WAF_ACTION_PROFILES: %w", err)
	}

	if !st.IsDir() {
		return fmt.Errorf("WAF_ACTION_PROFILES: %s is not a directory", abs)
	}

	c.ProfilesDir = abs

	if c.DataDir == "" {
		c.DataDir = abs + ".applied"
	}

	data, err := filepath.Abs(c.DataDir)
	if err != nil {
		return fmt.Errorf("WAF_ACTION_DATA: %w", err)
	}

	c.DataDir = data

	return nil
}

func (c *Config) Supports(v int) bool {
	for _, known := range c.Versions {
		if known == v {
			return true
		}
	}

	return false
}

func env(name, def string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}

	return def
}

func envInt(name string, def int) (int, error) {
	return envIntIfSet(name, def)
}

func envIntIfSet(name string, def int) (int, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return def, nil
	}

	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}

	return v, nil
}

func envIntList(name string, def []int) ([]int, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return def, nil
	}

	var out []int

	for _, part := range splitList(raw) {
		v, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}

		out = append(out, v)
	}

	return out, nil
}

func envDuration(name string, def time.Duration) (time.Duration, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return def, nil
	}

	d, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}

	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive", name)
	}

	return d, nil
}

func splitList(s string) []string {
	var out []string

	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}

	return out
}

/*
 * Стартовый порог журнала: словарь error_log nginx без emerg
 * (internal/loglevel). Поколение из KV переставляет порог живьём, переменная
 * действует до первого поколения с блоком settings.
 */
func parseLevel(s string) (slog.Level, error) {
	level, err := loglevel.Parse(s)
	if err != nil {
		return 0, fmt.Errorf("WAF_ACTION_LOG: %w", err)
	}

	return level, nil
}
