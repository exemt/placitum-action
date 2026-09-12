/*
 * LoadMany обязан быть неотличим от серии Load по исходу и отличаться от неё
 * только числом походов в обменник. Здесь проверяется ровно это: тот же Body на
 * тех же локаторах, один поход вместо трёх, и честный откат там, где батч
 * неприменим.
 */

package body

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/exemt/placitum-action/internal/protocol"
)

// fake -- обменник с обоими интерфейсами и счётчиками походов: без них тест
// проверял бы только исход, а весь смысл правки в числе round-trip.
type fake struct {
	data map[string][]byte

	gets    int
	batches int
	keys    [][]string

	err error
}

func newFake(pairs map[string]string) *fake {
	f := &fake{data: map[string][]byte{}}

	for k, v := range pairs {
		f.data[k] = []byte(v)
	}

	return f
}

func (f *fake) Get(ctx context.Context, driver, store, key string) ([]byte, error) {
	f.gets++

	if driver != "redis" {
		return nil, ErrUnknownDriver
	}

	if f.err != nil {
		return nil, f.err
	}

	raw, ok := f.data[key]
	if !ok {
		return nil, errMiss
	}

	return raw, nil
}

func (f *fake) GetMany(ctx context.Context, driver, store string, keys []string) (
	[][]byte, error) {

	f.batches++
	f.keys = append(f.keys, keys)

	if driver != "redis" {
		return nil, ErrUnknownDriver
	}

	if f.err != nil {
		return nil, f.err
	}

	out := make([][]byte, len(keys))

	for i, k := range keys {
		if raw, ok := f.data[k]; ok {
			out[i] = raw
		}
	}

	return out, nil
}

func (f *fake) Close() error { return nil }

/*
 * plain -- обменник без батча: проверяет откат на одиночные Get. Поле именованное,
 * а не встроенное: встраивание протащило бы наружу и GetMany, и проверять
 * пришлось бы не тот путь.
 */
type plain struct{ f *fake }

func (p plain) Get(ctx context.Context, driver, store, key string) ([]byte, error) {
	return p.f.Get(ctx, driver, store, key)
}

func (p plain) Close() error { return nil }

type constError string

func (e constError) Error() string { return string(e) }

const errMiss = constError("miss")

func loc(key, content string) *protocol.Locator {
	sum := sha256.Sum256([]byte(content))

	return &protocol.Locator{
		Store:  "hot",
		Driver: "redis",
		Key:    key,
		SHA256: hex.EncodeToString(sum[:]),
	}
}

func TestLoadManyTakesOneTrip(t *testing.T) {
	f := newFake(map[string]string{
		"n:1:req:hdr": `[["host","example.com"]]`,
		"n:1:req:arg": "a=1",
		"n:1:req":     "payload",
	})

	l := NewLoader(f, nil)

	got := l.LoadMany(context.Background(),
		loc("n:1:req:hdr", `[["host","example.com"]]`),
		loc("n:1:req:arg", "a=1"),
		loc("n:1:req", "payload"),
	)

	if f.batches != 1 || f.gets != 0 {
		t.Fatalf("batches = %d, gets = %d, want one batch and no single reads",
			f.batches, f.gets)
	}

	if len(f.keys[0]) != 3 {
		t.Fatalf("batched keys = %v, want all three in one call", f.keys[0])
	}

	want := []string{`[["host","example.com"]]`, "a=1", "payload"}

	for i, b := range got {
		if !b.Available() {
			t.Fatalf("object %d is unavailable: %q", i, b.Unavailable)
		}

		if string(b.Data) != want[i] {
			t.Errorf("object %d = %q, want %q", i, b.Data, want[i])
		}
	}
}

// Порядок ответа позиционный: вызывающий разбирает его по индексу, и
// перестановка здесь тихо подменила бы заголовки строкой запроса.
func TestLoadManyKeepsOrderWithGaps(t *testing.T) {
	f := newFake(map[string]string{
		"n:1:req:hdr": "H",
		"n:1:req":     "B",
	})

	l := NewLoader(f, nil)

	got := l.LoadMany(context.Background(),
		loc("n:1:req:hdr", "H"),
		nil,
		&protocol.Locator{Unavailable: "store_miss"},
		loc("n:1:req", "B"),
	)

	if len(got) != 4 {
		t.Fatalf("len = %d, want 4", len(got))
	}

	if string(got[0].Data) != "H" {
		t.Errorf("got[0] = %q, want H", got[0].Data)
	}

	if !got[1].Available() || len(got[1].Data) != 0 {
		t.Errorf("got[1] = %+v, want an empty available body", got[1])
	}

	if got[2].Unavailable != "store_miss" {
		t.Errorf("got[2].Unavailable = %q, want store_miss", got[2].Unavailable)
	}

	if string(got[3].Data) != "B" {
		t.Errorf("got[3] = %q, want B", got[3].Data)
	}
}

/*
 * Промах ключа в батче обязан выглядеть ровно так же, как redis.Nil у
 * одиночного Get: иначе правка меняет не число походов, а поведение.
 */
func TestLoadManyMissMatchesSingleGet(t *testing.T) {
	f := newFake(map[string]string{"n:1:req:hdr": "H"})
	l := NewLoader(f, nil)

	single := l.Load(context.Background(), loc("n:1:req", "B"))

	got := l.LoadMany(context.Background(),
		loc("n:1:req:hdr", "H"),
		loc("n:1:req", "B"),
	)

	if got[1].Unavailable != single.Unavailable {
		t.Errorf("batched miss = %q, single miss = %q; must match",
			got[1].Unavailable, single.Unavailable)
	}

	if got[1].Unavailable == "" {
		t.Error("a missing key must not read as an available object")
	}
}

// Отказ обменника относится ко всем объектам батча: половина ответа была бы хуже
// отсутствия ответа -- движок отработал бы по обрезанному входу и промолчал.
func TestLoadManyStoreErrorHitsEveryObject(t *testing.T) {
	f := newFake(map[string]string{"n:1:req:hdr": "H", "n:1:req": "B"})
	f.err = constError("connection refused")

	l := NewLoader(f, nil)

	got := l.LoadMany(context.Background(),
		loc("n:1:req:hdr", "H"),
		loc("n:1:req", "B"),
	)

	for i, b := range got {
		if b.Unavailable != unavailableStoreError {
			t.Errorf("object %d = %q, want %q", i, b.Unavailable, unavailableStoreError)
		}
	}
}

// Обменник без GetMany остаётся рабочим обменником.
func TestLoadManyFallsBackWithoutBatch(t *testing.T) {
	f := newFake(map[string]string{"n:1:req:hdr": "H", "n:1:req": "B"})
	l := NewLoader(plain{f}, nil)

	got := l.LoadMany(context.Background(),
		loc("n:1:req:hdr", "H"),
		loc("n:1:req", "B"),
	)

	if f.batches != 0 || f.gets != 2 {
		t.Fatalf("batches = %d, gets = %d, want the single-read fallback",
			f.batches, f.gets)
	}

	if string(got[0].Data) != "H" || string(got[1].Data) != "B" {
		t.Errorf("got = %q / %q, want H / B", got[0].Data, got[1].Data)
	}
}

// Один адресуемый объект батчить нечего: MGET на нём ничего не экономит.
func TestLoadManySingleKeyStaysSingleGet(t *testing.T) {
	f := newFake(map[string]string{"n:1:req": "B"})
	l := NewLoader(f, nil)

	got := l.LoadMany(context.Background(), nil, loc("n:1:req", "B"))

	if f.batches != 0 || f.gets != 1 {
		t.Fatalf("batches = %d, gets = %d, want one single read",
			f.batches, f.gets)
	}

	if string(got[1].Data) != "B" {
		t.Errorf("got[1] = %q, want B", got[1].Data)
	}
}

// Сверка контрольной суммы никуда не делась: батч меняет транспорт, не разбор.
func TestLoadManyStillChecksDigest(t *testing.T) {
	f := newFake(map[string]string{"n:1:req:hdr": "H", "n:1:req": "tampered"})
	l := NewLoader(f, nil)

	got := l.LoadMany(context.Background(),
		loc("n:1:req:hdr", "H"),
		loc("n:1:req", "B"),
	)

	if got[0].Unavailable != "" {
		t.Errorf("got[0] = %q, want an available object", got[0].Unavailable)
	}

	if got[1].Unavailable != unavailableDigestFail {
		t.Errorf("got[1] = %q, want %q", got[1].Unavailable, unavailableDigestFail)
	}
}

// Смешанные обменники в одном запросе -- редкая форма, но терять её нельзя:
// чужой драйвер уезжает на одиночный путь, свои остаются в батче.
func TestLoadManySplitsMixedDrivers(t *testing.T) {
	f := newFake(map[string]string{"n:1:req:hdr": "H", "n:1:req:arg": "a=1"})
	l := NewLoader(f, nil)

	other := loc("n:1:req", "B")
	other.Driver = "s3"

	got := l.LoadMany(context.Background(),
		loc("n:1:req:hdr", "H"),
		loc("n:1:req:arg", "a=1"),
		other,
	)

	if f.batches != 1 || len(f.keys[0]) != 2 {
		t.Fatalf("batches = %d, keys = %v, want the two redis objects batched",
			f.batches, f.keys)
	}

	if f.gets != 1 {
		t.Fatalf("gets = %d, want the foreign driver read on its own", f.gets)
	}

	if got[2].Unavailable != unavailableUnknownDrv {
		t.Errorf("got[2] = %q, want %q", got[2].Unavailable, unavailableUnknownDrv)
	}
}
