package desired

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/exemt/placitum-action/internal/policy"
)

const goodProfile = `mode: enforce
rules:
  - name: api-costs
    match:
      path_prefix: "/api"
    actions:
      - to: captcha
        do: note
        apply: ip
        value: 5
`

func manifestOf(t *testing.T, profiles map[string]Profile) []byte {
	t.Helper()

	raw, err := json.Marshal(Manifest{
		V: 1, Rev: 1, ConfigHash: Hash(profiles), Profiles: profiles,
	})
	if err != nil {
		t.Fatal(err)
	}

	return raw
}

func TestParseRejectsBadShapes(t *testing.T) {
	file := []File{{Name: ProfileFile, Text: goodProfile}}

	cases := map[string]map[string]Profile{
		"no default":   {"strict": {Files: file}},
		"path in name": {"default": {Files: file}, "../x": {Files: file}},
		"two files": {"default": {Files: []File{
			{Name: ProfileFile, Text: goodProfile},
			{Name: "extra.yaml", Text: goodProfile},
		}}},
		"wrong file name": {"default": {Files: []File{{Name: "x.yaml", Text: goodProfile}}}},
	}

	for name, profiles := range cases {
		if _, err := Parse(manifestOf(t, profiles)); err == nil {
			t.Errorf("%s: manifest accepted", name)
		}
	}
}

func TestApplySwitchesStoreAndSurvivesRestart(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	boot := t.TempDir()
	data := t.TempDir()

	if err := os.WriteFile(filepath.Join(boot, "default.yaml"),
		[]byte("mode: off\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := policy.NewStore(boot, log)
	if err != nil {
		t.Fatal(err)
	}

	m, err := Parse(manifestOf(t, map[string]Profile{
		"default": {Files: []File{{Name: ProfileFile, Text: goodProfile}}},
		"strict":  {Files: []File{{Name: ProfileFile, Text: goodProfile}}},
	}))
	if err != nil {
		t.Fatal(err)
	}

	if err := Apply(store, data, m); err != nil {
		t.Fatal(err)
	}

	p, ok := store.Current().Profile("strict")
	if !ok || len(p.Rules) != 1 {
		t.Fatalf("strict is not live after apply: ok=%v", ok)
	}

	// Рестарт: новый store на bootstrap-каталоге, Bootstrap возвращает поколение.
	restarted, err := policy.NewStore(boot, log)
	if err != nil {
		t.Fatal(err)
	}

	if !Bootstrap(restarted, data, log) {
		t.Fatal("bootstrap did not restore the applied generation")
	}

	if _, ok := restarted.Current().Profile("strict"); !ok {
		t.Fatal("strict is missing after restart")
	}
}

func TestApplyRollsBackOnBrokenGeneration(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	boot := t.TempDir()
	data := t.TempDir()

	if err := os.WriteFile(filepath.Join(boot, "default.yaml"),
		[]byte("mode: off\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := policy.NewStore(boot, log)
	if err != nil {
		t.Fatal(err)
	}

	good, err := Parse(manifestOf(t, map[string]Profile{
		"default": {Files: []File{{Name: ProfileFile, Text: goodProfile}}},
	}))
	if err != nil {
		t.Fatal(err)
	}

	if err := Apply(store, data, good); err != nil {
		t.Fatal(err)
	}

	// value вне процентов: загрузчик обязан отвергнуть поколение целиком.
	bad, err := Parse(manifestOf(t, map[string]Profile{
		"default": {Files: []File{{Name: ProfileFile, Text: `mode: enforce
rules:
  - name: broken
    match: {}
    actions:
      - to: captcha
        do: note
        apply: ip
        value: 500
`}}},
	}))
	if err != nil {
		t.Fatal(err)
	}

	if err := Apply(store, data, bad); err == nil {
		t.Fatal("broken generation applied")
	}

	// Живым осталось прежнее поколение -- и в снимке, и на диске.
	if _, ok := store.Current().Profile("default"); !ok {
		t.Fatal("default vanished after failed apply")
	}

	p, _ := store.Current().Profile("default")
	if len(p.Rules) != 1 || p.Rules[0].Name != "api-costs" {
		t.Fatal("snapshot is not the previous generation")
	}
}
