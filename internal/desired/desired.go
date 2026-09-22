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
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

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

	// BlobPrefix keys the bodies of static lists in the internal Redis, as the controller writes
	// them: waf.blob.<hex of sha256>.
	BlobPrefix = "waf.blob."

	treeDir = "profiles"

	blobTimeout = 15 * time.Second
	fetchRetry  = 30 * time.Second
)

var (
	listNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	listHashRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type File struct {
	Name string `json:"name"`
	Text string `json:"text"`
}

type Profile struct {
	Files []File `json:"files"`
}

// Manifest is a generation of action profiles. Lists names the static lists the conditions compare
// with: name -> sha256 of the body in the internal Redis (the manifest carries only the hash).
type Manifest struct {
	V          int                `json:"v"`
	Rev        int                `json:"rev"`
	ConfigHash string             `json:"config_hash"`
	Profiles   map[string]Profile `json:"profiles"`
	Lists      map[string]string  `json:"lists,omitempty"`
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

	for name, hash := range m.Lists {
		if !listNameRe.MatchString(name) {
			return nil, fmt.Errorf("manifest: bad list name %q", name)
		}

		if !listHashRe.MatchString(hash) {
			return nil, fmt.Errorf("manifest: list %q: bad hash %q", name, hash)
		}
	}

	if err := m.Settings.validate(); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}

	got := HashLists(m.Profiles, m.Lists, m.Settings)

	if m.ConfigHash != "" && m.ConfigHash != got {
		return nil, fmt.Errorf("manifest: config_hash mismatch: got %s want %s",
			got, m.ConfigHash)
	}

	m.ConfigHash = got

	return &m, nil
}

func HashWith(profiles map[string]Profile, settings *Settings) string {
	return HashLists(profiles, nil, settings)
}

// HashLists is the config_hash of a generation, the same as the controller counts it
// (hashActionProfiles): the profiles, then "list" NUL name NUL hash NUL per static list by name,
// then the settings. Without lists the hash is the one of the older generations.
func HashLists(profiles map[string]Profile, lists map[string]string, settings *Settings) string {
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

	listNames := make([]string, 0, len(lists))

	for name := range lists {
		listNames = append(listNames, name)
	}

	sort.Strings(listNames)

	for _, name := range listNames {
		for _, part := range []string{"list", name, lists[name]} {
			_, _ = sum.Write([]byte(part))
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

// BlobSource reads bodies from the internal Redis: nil for a missing key.
type BlobSource interface {
	Objects(ctx context.Context, keys []string) ([][]byte, error)
}

// FetchLists reads the bodies of the static lists of a generation and checks each against its
// hash.
func FetchLists(ctx context.Context, blobs BlobSource, m *Manifest) (map[string][]byte, error) {
	out := make(map[string][]byte, len(m.Lists))

	if len(m.Lists) == 0 {
		return out, nil
	}

	if blobs == nil {
		return nil, fmt.Errorf("the generation carries static lists, and the internal Redis is not configured")
	}

	names := make([]string, 0, len(m.Lists))

	for name := range m.Lists {
		names = append(names, name)
	}

	sort.Strings(names)

	keys := make([]string, len(names))

	for i, name := range names {
		keys[i] = BlobPrefix + strings.TrimPrefix(m.Lists[name], "sha256:")
	}

	ctx, cancel := context.WithTimeout(ctx, blobTimeout)
	defer cancel()

	bodies, err := blobs.Objects(ctx, keys)
	if err != nil {
		return nil, fmt.Errorf("redis: %w", err)
	}

	for i, name := range names {
		if i >= len(bodies) || bodies[i] == nil {
			return nil, fmt.Errorf("list %s: %s is missing", name, keys[i])
		}

		sum := sha256.Sum256(bodies[i])

		if "sha256:"+hex.EncodeToString(sum[:]) != m.Lists[name] {
			return nil, fmt.Errorf("list %s: %s hash mismatch", name, keys[i])
		}

		out[name] = bodies[i]
	}

	return out, nil
}

func Apply(store *policy.Store, dataDir string, m *Manifest, lists map[string][]byte) error {
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return fmt.Errorf("data dir: %w", err)
	}

	staging := filepath.Join(dataDir, ".next")
	prev := filepath.Join(dataDir, ".prev")
	live := filepath.Join(dataDir, treeDir)

	_ = os.RemoveAll(staging)

	if err := write(staging, m, lists); err != nil {
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

func write(dir string, m *Manifest, lists map[string][]byte) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}

	for name, profile := range m.Profiles {
		if err := os.WriteFile(filepath.Join(dir, name+".yaml"),
			[]byte(profile.Files[0].Text), 0o600); err != nil {
			return err
		}
	}

	if len(m.Lists) == 0 {
		return nil
	}

	if err := os.MkdirAll(filepath.Join(dir, policy.ListsDir), 0o750); err != nil {
		return err
	}

	for name := range m.Lists {
		body, ok := lists[name]
		if !ok {
			return fmt.Errorf("list %s: body is missing", name)
		}

		if err := os.WriteFile(filepath.Join(dir, policy.ListsDir, name+".txt"), body, 0o600); err != nil {
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
	blobs BlobSource,
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

		// A generation whose static lists could not be read is tried again: the bodies are in
		// the internal Redis before the manifest is, so a miss is Redis being away for a while.
		var (
			pending []byte
			retry   <-chan time.Time
		)

		for {
			select {
			case <-ctx.Done():
				return

			case <-retry:
				retry = nil

				if pending == nil {
					continue
				}

				if handle(ctx, pending, blobs, store, dataDir, applied, level, log) {
					retry = time.After(fetchRetry)
				} else {
					pending = nil
				}

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

				pending, retry = nil, nil
				raw := entry.Value()

				if handle(ctx, raw, blobs, store, dataDir, applied, level, log) {
					pending = raw
					retry = time.After(fetchRetry)
				}
			}
		}
	}()

	return applied, nil
}

func handle(
	ctx context.Context,
	raw []byte,
	blobs BlobSource,
	store *policy.Store,
	dataDir string,
	applied *Applied,
	level *slog.LevelVar,
	log *slog.Logger,
) (retry bool) {
	m, err := Parse(raw)
	if err != nil {
		log.Warn("desired rejected", "error", err.Error())

		return false
	}

	hash, rev, apply, names := applied.Snapshot()

	if apply == ApplyOK && hash == m.ConfigHash && rev == m.Rev {
		return false
	}

	lists, err := FetchLists(ctx, blobs, m)
	if err != nil {
		log.Error("desired lists failed",
			"rev", m.Rev, "retry_in", fetchRetry.String(), "error", err.Error())
		applied.set(hash, rev, ApplyFailed, names)

		return blobs != nil
	}

	if err := Apply(store, dataDir, m, lists); err != nil {
		log.Error("desired apply failed",
			"rev", m.Rev,
			"hash", m.ConfigHash,
			"error", err.Error(),
		)
		applied.set(hash, rev, ApplyFailed, names)

		return false
	}

	applied.set(m.ConfigHash, m.Rev, ApplyOK, m.Names())

	m.Settings.apply(level, log)

	log.Info("desired applied",
		"rev", m.Rev,
		"hash", m.ConfigHash,
		"profiles", m.Names(),
		"lists", len(m.Lists),
	)

	return false
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
