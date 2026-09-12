package desired

import (
	"encoding/json"
	"io"
	"log/slog"
	"testing"
)

/*
 * Канон блока настроек сверяется с контроллером тем же способом, что канон
 * профилей у modsec: одно дерево, одно прибитое число с обеих сторон
 * (controller/src/inspector-settings.test.ts). Разойдись они -- канал
 * навсегда остался бы в drift, и ни один тест этого не заметил бы.
 */
const (
	// sha256("default\0profile.yaml\0mode: off\n\0settings\0log_level\0warn\0")
	canonWithSettings = "sha256:b3dcfa221226d021d1fa1e7bf04536ebc4e4795adb2828b7d8c7a0e3e8118746"
	// sha256("default\0profile.yaml\0mode: off\n\0")
	canonWithout = "sha256:68835a28c97dfeb4b3a193e741d79d6d0f9bfb10027ac486f40668b632073340"
)

func canonProfiles() map[string]Profile {
	return map[string]Profile{
		"default": {Files: []File{{Name: ProfileFile, Text: "mode: off\n"}}},
	}
}

func TestSettingsCanonMatchesController(t *testing.T) {
	if got := HashWith(canonProfiles(), &Settings{LogLevel: "warn"}); got != canonWithSettings {
		t.Fatalf("canon diverged from the controller:\n got  %s\n want %s", got, canonWithSettings)
	}

	// Без блока канон прежний: старое поколение сходится со своим хешем.
	if got := Hash(canonProfiles()); got != canonWithout {
		t.Fatalf("legacy canon moved:\n got  %s\n want %s", got, canonWithout)
	}

	if HashWith(canonProfiles(), nil) != Hash(canonProfiles()) {
		t.Fatal("nil settings must hash like no settings")
	}
}

func TestParseCarriesSettingsAndRejectsForeignLevel(t *testing.T) {
	raw, err := json.Marshal(map[string]any{
		"v": 1, "rev": 1,
		"config_hash": canonWithSettings,
		"profiles":    canonProfiles(),
		"settings":    map[string]string{"log_level": "warn"},
	})
	if err != nil {
		t.Fatal(err)
	}

	m, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	if m.Settings == nil || m.Settings.LogLevel != "warn" || m.Settings.level != slog.LevelWarn {
		t.Fatalf("settings not carried: %+v", m.Settings)
	}

	// Контроллер такого не шлёт; в KV положили руками -- поколение отвергается.
	bad, _ := json.Marshal(map[string]any{
		"v": 1, "rev": 1,
		"profiles": canonProfiles(),
		"settings": map[string]string{"log_level": "emerg"},
	})

	if _, err := Parse(bad); err == nil {
		t.Fatal("foreign log level accepted")
	}

	// Старый контроллер: блока нет, хеш без него.
	old, _ := json.Marshal(map[string]any{
		"v": 1, "rev": 1,
		"config_hash": canonWithout,
		"profiles":    canonProfiles(),
	})

	if m, err := Parse(old); err != nil || m.Settings != nil {
		t.Fatalf("legacy manifest: err=%v settings=%+v", err, m.Settings)
	}
}

func TestSettingsApplySwitchesLevelVar(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	var level slog.LevelVar

	level.Set(slog.LevelInfo)

	s := &Settings{LogLevel: "error"}
	if err := s.validate(); err != nil {
		t.Fatal(err)
	}

	s.apply(&level, log)

	if level.Level() != slog.LevelError {
		t.Fatalf("level not applied: %v", level.Level())
	}

	// Нет блока -- порог не трогаем: старое поколение уровнем не управляет.
	var none *Settings

	none.apply(&level, log)

	if level.Level() != slog.LevelError {
		t.Fatalf("nil settings moved the level: %v", level.Level())
	}
}
