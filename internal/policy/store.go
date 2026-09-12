/*
 * Снимок профилей с горячей перечиткой.
 *
 * Профили правят руками там, где контроллера нет: правка плюс опрос отпечатка
 * каталога -- и снимок заменён целиком. Битый каталог не заменяет живой:
 * прежний снимок продолжает работать, ошибка уходит в лог -- инспектор, который
 * из-за опечатки в правке начинает молчать, хуже неперечитавшего.
 *
 * Второй путь к снимку -- раскатка: ReloadFrom переключает store на каталог
 * применённого поколения (internal/desired), и дальше его же опрашивает Watch.
 */

package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type Snapshot struct {
	profiles map[string]*Profile
}

func (s *Snapshot) Profile(name string) (*Profile, bool) {
	p, ok := s.profiles[name]

	return p, ok
}

func (s *Snapshot) Names() []string { return Names(s.profiles) }

type Store struct {
	// mu держит dir и print: их пишут и Watch, и ReloadFrom из горутины
	// раскатки. Снимок отдаётся без блокировки.
	mu      sync.Mutex
	dir     string
	print   string
	log     *slog.Logger
	current atomic.Pointer[Snapshot]
	// onLoad зовётся на каждом новом снимке -- зеркалу наборов, чтобы
	// заказать наборы условий до первого запроса, а не на нём.
	onLoad atomic.Pointer[func(*Snapshot)]
}

func NewStore(dir string, log *slog.Logger) (*Store, error) {
	st := &Store{dir: dir, log: log}

	profiles, err := LoadDir(dir)
	if err != nil {
		return nil, err
	}

	st.current.Store(&Snapshot{profiles: profiles})
	st.print, _ = fingerprint(dir)

	return st, nil
}

func (s *Store) Current() *Snapshot { return s.current.Load() }

// OnLoad ставит обработчик нового снимка и сразу зовёт его на текущем: тот,
// кто подписался позже загрузки, не должен ждать следующей перечитки.
func (s *Store) OnLoad(fn func(*Snapshot)) {
	s.onLoad.Store(&fn)
	fn(s.Current())
}

// Datasets -- наборы всех профилей снимка, без повторов.
func (s *Snapshot) Datasets() []string {
	seen := map[string]bool{}

	var out []string

	for _, name := range s.Names() {
		for _, ds := range s.profiles[name].Datasets() {
			if !seen[ds] {
				seen[ds] = true
				out = append(out, ds)
			}
		}
	}

	return out
}

func (s *Store) swap(snap *Snapshot) {
	s.current.Store(snap)

	if fn := s.onLoad.Load(); fn != nil {
		(*fn)(snap)
	}
}

// Dir -- каталог, по которому сейчас читают. Нужен раскатке: она кладёт новое
// поколение рядом и переключает сюда.
func (s *Store) Dir() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.dir
}

/*
 * ReloadFrom переключает каталог и читает его целиком. Провал не трогает ни
 * действующий снимок, ни каталог: поколение, которое не разобралось, не должно
 * оставлять контур ни с половиной профилей, ни без них.
 */
func (s *Store) ReloadFrom(dir string) error {
	profiles, err := LoadDir(dir)
	if err != nil {
		return err
	}

	print, _ := fingerprint(dir)

	s.mu.Lock()
	s.dir = dir
	s.print = print
	s.mu.Unlock()

	s.swap(&Snapshot{profiles: profiles})

	return nil
}

// Watch опрашивает отпечаток каталога и перечитывает его на изменение.
func (s *Store) Watch(ctx context.Context, every time.Duration) {
	tick := time.NewTicker(every)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}

		dir := s.Dir()

		print, err := fingerprint(dir)
		if err != nil {
			s.log.Warn("profiles fingerprint failed", "error", err.Error())

			continue
		}

		s.mu.Lock()
		same := print == s.print && dir == s.dir
		s.mu.Unlock()

		if same {
			continue
		}

		profiles, err := LoadDir(dir)
		if err != nil {
			// Отпечаток всё равно обновляется: иначе битый каталог
			// перечитывался бы каждый тик и заливал лог одной ошибкой.
			s.setPrint(dir, print)
			s.log.Error("profiles reload failed, keeping the previous snapshot",
				"error", err.Error())

			continue
		}

		s.setPrint(dir, print)
		s.swap(&Snapshot{profiles: profiles})
		s.log.Info("profiles reloaded", "profiles", Names(profiles))
	}
}

// setPrint пишет отпечаток, только если каталог не сменили под ногами:
// перечитка старого каталога не должна забивать отпечаток нового.
func (s *Store) setPrint(dir, print string) {
	s.mu.Lock()
	if s.dir == dir {
		s.print = print
	}
	s.mu.Unlock()
}

// fingerprint -- имена, размеры и mtime файлов каталога одной строкой.
func fingerprint(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}

	names := make([]string, 0, len(entries))

	for _, e := range entries {
		if _, ok := profileName(e); ok {
			names = append(names, e.Name())
		}
	}

	sort.Strings(names)

	h := sha256.New()

	for _, name := range names {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			return "", err
		}

		fmt.Fprintf(h, "%s\x00%d\x00%d\x00", name, st.Size(), st.ModTime().UnixNano())
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
