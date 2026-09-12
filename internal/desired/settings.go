/*
 * Настройки процесса из поколения.
 *
 * Профили -- файлы, они ложатся на диск и их читает загрузчик. Настройки --
 * свойства самого процесса из каталога инспекторов контроллера: файлом на
 * диск не ложатся, применяются к процессу напрямую и живут только в памяти.
 * Первая из них -- уровень журнала: его меняют под нагрузкой, и рестарт ради
 * него недопустим.
 *
 * Блок необязателен: поколение старого контроллера его не несёт, и тогда
 * процесс остаётся на стартовом значении из окружения. Канон хеша блок
 * включает ровно тогда, когда он есть в манифесте, -- иначе старое поколение
 * перестало бы сходиться с собственным config_hash.
 *
 * Канон совпадает с контроллером (docs/inspector-config-distribution.md):
 * после профилей -- "settings", NUL, "log_level", NUL, значение, NUL.
 */

package desired

import (
	"fmt"
	"hash"
	"log/slog"

	"github.com/exemt/placitum-shared/loglevel"
)

type Settings struct {
	LogLevel string `json:"log_level"`

	// level -- разобранное значение; заполняет Parse, читает apply.
	level slog.Level
}

/*
 * validate разбирает уровень. Чужое слово -- отказ всего поколения, как и
 * битый профиль: контроллер такого не шлёт (словарь прибит ограничением в
 * базе), значит в KV положили руками, и молча проглотить это нельзя.
 */
func (s *Settings) validate() error {
	if s == nil {
		return nil
	}

	level, err := loglevel.Parse(s.LogLevel)
	if err != nil {
		return fmt.Errorf("settings.log_level: %w", err)
	}

	s.level = level

	return nil
}

// writeSettings -- секция канона. Отсутствующий блок не пишет ничего.
func writeSettings(sum hash.Hash, s *Settings) {
	if s == nil {
		return
	}

	_, _ = sum.Write([]byte("settings"))
	_, _ = sum.Write([]byte{0})
	_, _ = sum.Write([]byte("log_level"))
	_, _ = sum.Write([]byte{0})
	_, _ = sum.Write([]byte(s.LogLevel))
	_, _ = sum.Write([]byte{0})
}

/*
 * apply переставляет живой порог. Сначала порог, потом строка о нём: строка
 * появляется ровно тогда, когда новый порог её пропускает, -- это и есть
 * подтверждение, что он вступил в силу.
 */
func (s *Settings) apply(level *slog.LevelVar, log *slog.Logger) {
	if s == nil || level == nil {
		return
	}

	if level.Level() == s.level {
		return
	}

	level.Set(s.level)
	log.Info("log level applied", "level", loglevel.String(s.level))
}
