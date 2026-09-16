package desired

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/exemt/placitum-action/internal/policy"
)

const (
	Bucket         = "WAF_DESIRED"
	Key            = "policy/action"
	DefaultProfile = "default"

	ProfileFile = "profile.yaml"

	ApplyOK     = "ok"
	ApplyFailed = "apply_failed"

	treeDir = "profiles"
)

type File struct {
	Name string `json:"name"`
	Text string `json:"text"`
}

type Profile struct {
	Files []File `json:"files"`
}

type Manifest struct {
	V          int                `json:"v"`
	Rev        int                `json:"rev"`
	ConfigHash string             `json:"config_hash"`
	Profiles   map[string]Profile `json:"profiles"`
	Settings   *Settings          `json:"settings,omitempty"`
}

func Parse(raw []byte) (*Manifest, error) {
	var m Manifest

	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}

	if m.V != 1 {
		return nil, fmt.Errorf("manifest: unsupported v %d", m.V)
	}

	if m.Rev < 1 {
		return nil, fmt.Errorf("manifest: rev must be positive")
	}

	if _, ok := m.Profiles[DefaultProfile]; !ok {
		return nil, fmt.Errorf("manifest: profile %q is missing", DefaultProfile)
	}

	for name, profile := range m.Profiles {
		if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
			return nil, fmt.Errorf("manifest: bad profile name %q", name)
		}

		if len(profile.Files) != 1 || profile.Files[0].Name != ProfileFile {
			return nil, fmt.Errorf("manifest: profile %q must carry exactly one %s",
				name, ProfileFile)
		}
	}

	if err := m.Settings.validate(); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}

	got := HashWith(m.Profiles, m.Settings)

	if m.ConfigHash != "" && m.ConfigHash != got {
		return nil, fmt.Errorf("manifest: config_hash mismatch: got %s want %s",
			got, m.ConfigHash)
	}

	m.ConfigHash = got

	return &m, nil
}

func HashWith(profiles map[string]Profile, settings *Settings) string {
	names := make([]string, 0, len(profiles))

	for name := range profiles {
		names = append(names, name)
	}

	sort.Strings(names)

	sum := sha256.New()

	for _, name := range names {
		_, _ = sum.Write([]byte(name))
		_, _ = sum.Write([]byte{0})

		for _, file := range profiles[name].Files {
			_, _ = sum.Write([]byte(file.Name))
			_, _ = sum.Write([]byte{0})
			_, _ = sum.Write([]byte(file.Text))
			_, _ = sum.Write([]byte{0})
		}
	}

	writeSettings(sum, settings)

	return "sha256:" + hex.EncodeToString(sum.Sum(nil))
}

func (m *Manifest) Names() []string {
	names := make([]string, 0, len(m.Profiles))

	for name := range m.Profiles {
		names = append(names, name)
	}

	sort.Strings(names)

	return names
}

func Apply(store *policy.Store, dataDir string, m *Manifest) error {
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return fmt.Errorf("data dir: %w", err)
	}

	staging := filepath.Join(dataDir, ".next")
	prev := filepath.Join(dataDir, ".prev")
	live := filepath.Join(dataDir, treeDir)

	_ = os.RemoveAll(staging)

	if err := write(staging, m); err != nil {
		_ = os.RemoveAll(staging)

		return err
	}

	_ = os.RemoveAll(prev)

	lived := true

	if err := os.Rename(live, prev); err != nil {
		if !os.IsNotExist(err) {
			_ = os.RemoveAll(staging)

			return fmt.Errorf("park live: %w", err)
		}

		lived = false
	}

	if err := os.Rename(staging, live); err != nil {
		if lived {
			_ = os.Rename(prev, live)
		}

		_ = os.RemoveAll(staging)

		return fmt.Errorf("promote staging: %w", err)
	}

	if err := store.ReloadFrom(live); err != nil {
		_ = os.RemoveAll(live)

		if lived {
			if restore := os.Rename(prev, live); restore == nil {
				_ = store.ReloadFrom(live)
			}
		}

		return err
	}

	_ = os.RemoveAll(prev)

	return nil
}

func write(dir string, m *Manifest) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}

	for name, profile := range m.Profiles {
		if err := os.WriteFile(filepath.Join(dir, name+".yaml"),
			[]byte(profile.Files[0].Text), 0o600); err != nil {
			return err
		}
	}

	return nil
}

type Applied struct {
	mu    sync.RWMutex
	hash  string
	rev   int
	apply string
	names []string
}

func (a *Applied) Snapshot() (hash string, rev int, apply string, names []string) {
	if a == nil {
		return "", 0, "", nil
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	return a.hash, a.rev, a.apply, append([]string(nil), a.names...)
}

func (a *Applied) set(hash string, rev int, apply string, names []string) {
	a.mu.Lock()
	a.hash = hash
	a.rev = rev
	a.apply = apply
	a.names = append([]string(nil), names...)
	a.mu.Unlock()
}

func Watch(
	ctx context.Context,
	nc *nats.Conn,
	store *policy.Store,
	dataDir string,
	level *slog.LevelVar,
	log *slog.Logger,
) (*Applied, error) {
	applied := &Applied{}

	js, err := jetstream.New(nc)
	if err != nil {
		return nil, err
	}

	kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket:  Bucket,
		History: 5,
	})
	if err != nil {
		return nil, err
	}

	watcher, err := kv.Watch(ctx, Key)
	if err != nil {
		return nil, err
	}

	go func() {
		defer watcher.Stop()

		for {
			select {
			case <-ctx.Done():
				return

			case entry, ok := <-watcher.Updates():
				if !ok {
					return
				}

				if entry == nil {
					continue
				}

				switch entry.Operation() {
				case jetstream.KeyValueDelete, jetstream.KeyValuePurge:
					continue
				}

				m, err := Parse(entry.Value())
				if err != nil {
					log.Warn("desired rejected", "error", err.Error())

					continue
				}

				hash, rev, apply, names := applied.Snapshot()

				if apply == ApplyOK && hash == m.ConfigHash && rev == m.Rev {
					continue
				}

				if err := Apply(store, dataDir, m); err != nil {
					log.Error("desired apply failed",
						"rev", m.Rev,
						"hash", m.ConfigHash,
						"error", err.Error(),
					)
					applied.set(hash, rev, ApplyFailed, names)

					continue
				}

				applied.set(m.ConfigHash, m.Rev, ApplyOK, m.Names())

				m.Settings.apply(level, log)

				log.Info("desired applied",
					"rev", m.Rev,
					"hash", m.ConfigHash,
					"profiles", m.Names(),
				)
			}
		}
	}()

	return applied, nil
}

func Bootstrap(store *policy.Store, dataDir string, log *slog.Logger) bool {
	if dataDir == "" {
		return false
	}

	live := filepath.Join(dataDir, treeDir)

	if _, err := os.Stat(filepath.Join(live, DefaultProfile+".yaml")); err != nil {
		return false
	}

	if err := store.ReloadFrom(live); err != nil {
		log.Warn("applied generation is unusable, falling back to bootstrap profiles",
			"dir", live, "error", err.Error())

		return false
	}

	log.Info("applied generation restored", "dir", live)

	return true
}
