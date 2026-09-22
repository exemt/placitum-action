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
	mu      sync.Mutex
	dir     string
	print   string
	log     *slog.Logger
	current atomic.Pointer[Snapshot]
	onLoad  atomic.Pointer[func(*Snapshot)]
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

func (s *Store) OnLoad(fn func(*Snapshot)) {
	s.onLoad.Store(&fn)
	fn(s.Current())
}

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

func (s *Store) Dir() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.dir
}

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

func (s *Store) setPrint(dir, print string) {
	s.mu.Lock()
	if s.dir == dir {
		s.print = print
	}
	s.mu.Unlock()
}

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

	// The static lists change with the profiles that name them, and a hand-edited list must reload
	// as well.
	if lists, err := os.ReadDir(filepath.Join(dir, ListsDir)); err == nil {
		for _, e := range lists {
			if !e.IsDir() {
				names = append(names, filepath.Join(ListsDir, e.Name()))
			}
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
