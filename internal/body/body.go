/*
 * Получение объекта обменника по локатору -- единственное место инспектора,
 * которое обращается к внешнему хранилищу. Форма локатора одна на все три
 * объекта, поэтому и загрузчик один: тело, заголовки и строка запроса
 * достаются одним кодом.
 *
 * Главное правило: недоступный объект не решает за модуль -- но недоступность
 * бывает двух разных родов, и путать их нельзя.
 *
 * Её обнаружил модуль (причина приехала в локаторе) -- маршрут ею уже
 * распорядился классом body у waf_exception, и раз сообщение всё-таки дошло,
 * решение было "продолжать". Спорить не с чем: ответ обычный, с пометкой в
 * аудите.
 *
 * Её обнаружил инспектор (обменник не ответил, не расшифровалось, не сошёлся
 * хеш) -- о ней модуль не знает вовсе: он положил объект и считает его на
 * месте. Это сбой инспектора, и признаётся он вердиктом error; исход выбирает
 * waf_exception класса inspector. Такие исходы помечены Fault.
 */

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

// Body -- результат получения. Unavailable непустой означает, что тела нет и не
// будет; Fault говорит, чей это исход -- маршрута или наш.
type Body struct {
	Data        []byte
	Truncated   bool
	Unavailable string
	// Fault -- недоступность обнаружил сам инспектор. Ответить на неё как на
	// проверку нельзя: объект лежал, и то, что мы его не взяли, ничего не
	// говорит о запросе.
	Fault bool
	// SHA256 после расшифровки: подтверждает целостность и заодно даёт ключ
	// кеширования вердикта по содержимому.
	SHA256 string
}

func (b Body) Available() bool { return b.Unavailable == "" }

// Failed -- объект лежал, а мы его не взяли: это наш сбой, а не свойство
// запроса. Вызывающий отвечает на него вердиктом error.
func (b Body) Failed() bool { return b.Fault }

// Store -- внешнее хранилище тела. Реализация -- Redis.
type Store interface {
	Get(ctx context.Context, driver, store, key string) ([]byte, error)
	Close() error
}

/*
 * MultiStore -- обменник, умеющий отдать несколько объектов одним походом.
 * Отдельным интерфейсом, а не строкой в Store: драйвер без батча остаётся
 * рабочим обменником, LoadMany просто разложит запрос на одиночные Get.
 */
type MultiStore interface {
	GetMany(ctx context.Context, driver, store string, keys []string) ([][]byte, error)
}

// Keys отдаёт ключ расшифровки по kid. Ключ приходит из системы секретов
// инспектора, а не с провода: иначе шифрование тела не защищало бы ни от чего.
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

// Причины недоступности, которые инспектор проставляет сам: все они едут с
// Fault. Формат совпадает с тем, что присылает модуль, чтобы в audit они
// читались одинаково.
const (
	unavailableNoStore     = "store_unconfigured"
	unavailableStoreError  = "store_error"
	unavailableUnknownDrv  = "unknown_driver"
	unavailableDecryptFail = "decrypt_failed"
	unavailableDigestFail  = "digest_mismatch"
)

// Load обрабатывает все три формы локатора. Ошибка чтения из хранилища --
// тоже unavailable, а не отсутствие ответа.
func (l *Loader) Load(ctx context.Context, loc *protocol.Locator) Body {
	switch {
	case loc == nil:
		/*
		 * Объекта нет: инспектор не просил его в needs=, маршрут не снимает
		 * его в waf_capture, либо класть было нечего. Различать эти случаи
		 * здесь нечем и незачем -- содержимого нет во всех трёх.
		 */
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

/*
 * LoadMany достаёт объекты одного запроса одним походом в обменник. Порядок
 * ответа повторяет порядок локаторов, поэтому вызывающий разбирает его
 * позиционно.
 *
 * Один MGET, а не три Get: у объектов одного запроса один обменник, и каждый
 * лишний round-trip здесь стоит миллисекунд бюджета волны, а не команд Redis.
 *
 * Батчится только то, что лежит в одном драйвере и приехало без пометки
 * недоступности. Смешанные формы и обменник без батча разбираются тем же Load,
 * что и раньше: случай редкий, и специальный путь для него стоил бы дороже
 * лишнего похода.
 */
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

	// Один ключ батчить незачем: MGET на нём ничего не экономит, а поведение
	// одиночного Get уже описано и проверено.
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
			// Ключа в обменнике нет. Для одиночного Get это redis.Nil, то есть
			// ошибка чтения; исход здесь обязан быть тем же.
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

	/*
	 * Ожидаемая контрольная сумма -- processed_sha256, когда тело прошло через
	 * сервис трансформации, и sha256 в остальных случаях: модуль считает
	 * первую по тому, что реально положил в хранилище.
	 *
	 * У префикса сверять нечего. sha256 -- это сумма оригинала: она связывает
	 * событие с архивом, а в хранилище при waf_body_limit ... trim лежит
	 * только начало тела, и совпасть эти суммы не могут по построению. Сверка
	 * объявляла бы всякое усечённое тело недоступным, то есть маршрут с
	 * trim не проверялся бы вовсе -- и выглядело бы это как пропуск.
	 */
	want := loc.SHA256
	if loc.ProcessedSHA256 != "" {
		want = loc.ProcessedSHA256
	} else if loc.Truncated {
		want = ""
	}

	if want != "" && want != digest {
		return Body{Unavailable: unavailableDigestFail, Fault: true}
	}

	// truncated обрабатывается явно, а не как полное тело: молчаливая трактовка
	// префикса как целого -- источник ложных пропусков.
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
