/*
 * Драйвер redis -- внешний обменник. Локатор приезжает с ключом
 * <node>:<rid>:<phase> у тела, с суффиксом :hdr у заголовков и :arg у строки
 * запроса; инспектор читает GET. Ключи позиционные, а не хеш содержимого: хеш
 * требовал бы полного прохода до начала записи.
 */

package body

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var ErrUnknownDriver = errors.New("unknown body store driver")

type RedisStore struct {
	client  *redis.Client
	timeout time.Duration
}

func NewRedisStore(url string, timeout time.Duration) (*RedisStore, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}

	/*
	 * Таймауты обязаны быть меньше дедлайна инспекции: блокирующий вызов без
	 * таймаута внутри обработчика -- одна из четырёх ошибок, которых
	 * docs/inspectors.md просит не допускать с самого начала.
	 */
	opt.ReadTimeout = timeout
	opt.WriteTimeout = timeout
	opt.DialTimeout = timeout

	return &RedisStore{client: redis.NewClient(opt), timeout: timeout}, nil
}

func (s *RedisStore) Get(ctx context.Context, driver, store, key string) ([]byte, error) {
	if driver != "redis" {
		return nil, ErrUnknownDriver
	}

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	return s.client.Get(ctx, key).Bytes()
}

/*
 * GetMany -- те же объекты одним MGET. У объектов одного запроса один обменник,
 * поэтому каждый лишний Get здесь -- это лишний round-trip внутри бюджета
 * волны, а не лишняя команда.
 *
 * Длина ответа равна длине запроса, порядок сохраняется. Отсутствующий ключ --
 * nil на своей позиции, а не ошибка: у остальных объектов запроса своя судьба,
 * и терять их из-за одного промаха нельзя.
 */
func (s *RedisStore) GetMany(ctx context.Context, driver, store string,
	keys []string) ([][]byte, error) {

	if driver != "redis" {
		return nil, ErrUnknownDriver
	}

	if len(keys) == 0 {
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	vals, err := s.client.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, err
	}

	if len(vals) != len(keys) {
		return nil, fmt.Errorf("mget returned %d values for %d keys",
			len(vals), len(keys))
	}

	out := make([][]byte, len(keys))

	for i, v := range vals {
		switch raw := v.(type) {
		case string:
			out[i] = []byte(raw)
		case []byte:
			out[i] = raw
		}
	}

	return out, nil
}

/*
 * Put существует только для пробы: в контуре в обменник пишет модуль, и никто
 * больше. Проба идёт тем же путём, что реальный запрос, а значит и содержимое
 * обязана положить туда же -- иначе она проверяла бы не тот путь.
 */
func (s *RedisStore) Put(ctx context.Context, key string, value []byte,
	ttl time.Duration) error {

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	return s.client.Set(ctx, key, value, ttl).Err()
}

func (s *RedisStore) Close() error { return s.client.Close() }

// Ping проверяет доступность хранилища при старте: ошибка конфигурации должна
// обнаруживаться здесь, а не на первом сообщении с локатором.
func (s *RedisStore) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	return s.client.Ping(ctx).Err()
}
