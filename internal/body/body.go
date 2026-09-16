package body

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/exemt/placitum-action/internal/protocol"
)

type Body struct {
	Data        []byte
	Truncated   bool
	Unavailable string
	Fault       bool
	SHA256      string
}

func (b Body) Available() bool { return b.Unavailable == "" }

func (b Body) Failed() bool { return b.Fault }

type Store interface {
	Get(ctx context.Context, driver, store, key string) ([]byte, error)
	Close() error
}

type MultiStore interface {
	GetMany(ctx context.Context, driver, store string, keys []string) ([][]byte, error)
}

type Keys interface {
	Key(kid string) ([]byte, error)
}

type Loader struct {
	store Store
	keys  Keys
}

func NewLoader(store Store, keys Keys) *Loader {
	return &Loader{store: store, keys: keys}
}

const (
	unavailableNoStore     = "store_unconfigured"
	unavailableStoreError  = "store_error"
	unavailableUnknownDrv  = "unknown_driver"
	unavailableDecryptFail = "decrypt_failed"
	unavailableDigestFail  = "digest_mismatch"
)

func (l *Loader) Load(ctx context.Context, loc *protocol.Locator) Body {
	switch {
	case loc == nil:
		return Body{}

	case loc.Unavailable != "":
		return Body{Unavailable: loc.Unavailable}

	case loc.Driver != "":
		if l.store == nil {
			return Body{Unavailable: unavailableNoStore, Fault: true}
		}

		raw, err := l.store.Get(ctx, loc.Driver, loc.Store, loc.Key)

		switch {
		case errors.Is(err, ErrUnknownDriver):
			return Body{Unavailable: unavailableUnknownDrv, Fault: true}
		case err != nil:
			return Body{Unavailable: unavailableStoreError, Fault: true}
		}

		return l.finish(loc, raw)
	}

	return Body{}
}

func (l *Loader) LoadMany(ctx context.Context, locs ...*protocol.Locator) []Body {
	out := make([]Body, len(locs))

	multi, ok := l.store.(MultiStore)
	if !ok {
		for i, loc := range locs {
			out[i] = l.Load(ctx, loc)
		}

		return out
	}

	var (
		keys    []string
		at      []int
		driver  string
		store   string
		batched bool
	)

	for i, loc := range locs {
		if loc == nil || loc.Unavailable != "" || loc.Driver == "" {
			out[i] = l.Load(ctx, loc)

			continue
		}

		if batched && (loc.Driver != driver || loc.Store != store) {
			out[i] = l.Load(ctx, loc)

			continue
		}

		driver, store, batched = loc.Driver, loc.Store, true
		keys = append(keys, loc.Key)
		at = append(at, i)
	}

	if len(keys) < 2 {
		for _, i := range at {
			out[i] = l.Load(ctx, locs[i])
		}

		return out
	}

	raws, err := multi.GetMany(ctx, driver, store, keys)

	switch {
	case errors.Is(err, ErrUnknownDriver):
		for _, i := range at {
			out[i] = Body{Unavailable: unavailableUnknownDrv, Fault: true}
		}

		return out

	case err != nil:
		for _, i := range at {
			out[i] = Body{Unavailable: unavailableStoreError, Fault: true}
		}

		return out
	}

	for n, i := range at {
		if raws[n] == nil {
			out[i] = Body{Unavailable: unavailableStoreError, Fault: true}

			continue
		}

		out[i] = l.finish(locs[i], raws[n])
	}

	return out
}

func (l *Loader) finish(loc *protocol.Locator, raw []byte) Body {
	if loc.Enc != nil {
		plain, err := l.decrypt(loc, raw)
		if err != nil {
			return Body{Unavailable: unavailableDecryptFail, Fault: true}
		}

		raw = plain
	}

	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])

	want := loc.SHA256
	if loc.ProcessedSHA256 != "" {
		want = loc.ProcessedSHA256
	} else if loc.Truncated {
		want = ""
	}

	if want != "" && want != digest {
		return Body{Unavailable: unavailableDigestFail, Fault: true}
	}

	return Body{Data: raw, Truncated: loc.Truncated, SHA256: digest}
}

func (l *Loader) decrypt(loc *protocol.Locator, raw []byte) ([]byte, error) {
	if l.keys == nil {
		return nil, fmt.Errorf("body is encrypted but no secret source is configured")
	}

	if loc.Enc.Alg != "aes-256-gcm" {
		return nil, fmt.Errorf("unsupported body encryption: %q", loc.Enc.Alg)
	}

	key, err := l.keys.Key(loc.Enc.KID)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce, err := base64.StdEncoding.DecodeString(loc.Enc.Nonce)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, nonce, raw, nil)
}
