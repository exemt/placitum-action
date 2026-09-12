/*
 * Формат сообщений между модулем и инспектором, версия схемы 2.
 *
 * Источник истины -- docs/messages/inspector.schema.json и
 * docs/verdict-protocol.md; расхождение с ними ловится тестами этого пакета, а
 * не на живом трафике.
 *
 * Содержимого запроса в сообщении нет. Заголовки, строка запроса и тело едут
 * локаторами в секции store: длину всех трёх задаёт клиент, а сообщение
 * публикуется по одному на каждого инспектора волны. За содержимым инспектор
 * идёт в обменник сам, и только за тем, что заявил в needs=.
 *
 * Правило совместимости из спецификации: незнакомые поля игнорируются, поэтому
 * типы описывают минимум, на который инспектор вправе рассчитывать, а не полный
 * список того, что может приехать по проводу.
 */

package protocol

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

const Version = 2

/* --- запрос на инспекцию --------------------------------------------------- */

type TLS struct {
	Version string `json:"version"`
	SNI     string `json:"sni"`
	JA4     string `json:"ja4"`
}

type Conn struct {
	ClientIP   string `json:"client_ip"`
	ClientPort int    `json:"client_port"`
	ServerIP   string `json:"server_ip"`
	ServerPort int    `json:"server_port"`
	TLS        *TLS   `json:"tls"`
}

// Header едет парой, а не полем объекта: порядок получения значим, а дубликаты
// имён (Set-Cookie, Forwarded) в объекте потерялись бы. По проводу пары не
// едут -- в этой форме лежит объект headers в обменнике.
type Header [2]string

func (h Header) Name() string  { return h[0] }
func (h Header) Value() string { return h[1] }

// HTTP -- то, что едет инлайном. Путь нужен каждому инспектору для
// сопоставления правил, поэтому он здесь; строка запроса -- в обменнике, а здесь
// от неё остаётся только длина. Ноль означает, что query не было: это видно
// даже когда запись выключена.
type HTTP struct {
	Method   string `json:"method"`
	Scheme   string `json:"scheme"`
	Host     string `json:"host"`
	URI      string `json:"uri"`
	ArgsSize int64  `json:"args_size"`
	Version  string `json:"version"`
}

type Response struct {
	Status     int      `json:"status"`
	Headers    []Header `json:"headers"`
	UpstreamMS int      `json:"upstream_ms"`
}

// Enc -- параметры шифрования тела. Ключ инспектор получает по kid из своей
// системы секретов, а не с провода.
type Enc struct {
	Alg   string `json:"alg"`
	KID   string `json:"kid"`
	Nonce string `json:"nonce"`
}

/*
 * Locator, docs/body-storage.md#локатор -- одна форма на все три объекта
 * обменника. Три взаимоисключающих состояния различаются присутствием полей:
 * nil (не клали), unavailable (объект есть, но недоступен), размещение в
 * обменнике.
 *
 * Size, SHA256, Complete, Truncated и Encoding заполнены только у тела: у
 * заголовков и строки запроса нет ни усечения, ни Content-Encoding.
 *
 * ProcessedSHA256, Transformed и Enc принадлежат трансформации и шифрованию, и
 * модуль их пока не пишет. Разбор для них есть заранее: молча пропустить
 * шифрованное тело хуже, чем не уметь его читать.
 */
type Locator struct {
	Store           string `json:"store"`
	Driver          string `json:"driver"`
	Key             string `json:"key"`
	Unavailable     string `json:"unavailable"`
	Size            int64  `json:"size"`
	DeclaredSize    int64  `json:"declared_size"`
	SHA256          string `json:"sha256"`
	ProcessedSHA256 string `json:"processed_sha256"`
	Transformed     bool   `json:"transformed"`
	Complete        bool   `json:"complete"`
	Truncated       bool   `json:"truncated"`
	Encoding        string `json:"encoding"`
	ExpiresAt       int64  `json:"expires_at"`
	Hint            string `json:"hint"`
	Enc             *Enc   `json:"enc"`
}

// Placed -- по локатору ещё можно что-то достать. Отсутствие адресации при
// доступном объекте не отказ: так выглядит body=meta, где просили длину с
// хешем, а содержимого не просили.
func (l *Locator) Placed() bool {
	return l != nil && l.Unavailable == "" && l.Driver != "" && l.Key != ""
}

/*
 * Store -- три объекта одной формы. nil означает одно из трёх: инспектор не
 * просил объект в needs=, маршрут не снимает его в waf_capture, либо класть
 * было нечего. Различать эти случаи незачем -- во всех трёх содержимого нет.
 */
type Store struct {
	Headers *Locator `json:"headers"`
	Args    *Locator `json:"args"`
	Body    *Locator `json:"body"`
}

type Route struct {
	ServerName string `json:"server_name"`
	Location   string `json:"location"`
	// Имя набора правил для этого маршрута. Для модуля непрозрачно, для этого
	// пакета тоже: он только читает его и передаёт дальше.
	Profile string `json:"profile"`
}

// ScoreState -- накопленный счёт фазы и порог отказа маршрута; DenyAt 0
// означает, что порог выключен.
type ScoreState struct {
	Total  int `json:"total"`
	DenyAt int `json:"deny_at"`
}

/*
 * Action -- просьба одного инспектора другому, docs/inspector-actions.md.
 *
 * В ответе поле To называет адресата; в доставленной записи prior его нет --
 * адресат тот, кто читает. Модуль просьбу не исполняет: он проверяет форму,
 * переносит её через фазы и ограничивает числом и размером.
 */
type Action struct {
	To string `json:"to,omitempty"`
	Do string `json:"do"`
	// Apply -- ось: о ком высказывание, а не какой рычаг у получателя дёрнуть.
	// Обязательна даже там, где допустима одна: умолчание означало бы, что
	// "про кого это сказано" иногда написано, а иногда угадано.
	Apply string `json:"apply"`
	// Phase -- только у управляющих DoActive, DoPassive, DoVote, DoOff: вызову
	// какой фазы адресата ставить режим (request, response, frame). Пусто --
	// всем вызовам имени: у имени на двух фазах вызова два.
	Phase string `json:"phase,omitempty"`
	Code  string `json:"code,omitempty"`
	Delta *int   `json:"delta,omitempty"`
	Value *int   `json:"value,omitempty"`
	// Counter -- только при do note: имя корзины получателя, селектор поверх
	// его правил приёма. Пусто -- корзину называет правило получателя.
	Counter string `json:"counter,omitempty"`
	// Marker -- только при DoMark, обязательно: метка события. Произвольная
	// строка оператора; модуль её не толкует, а складывает со всеми маркерами
	// запроса в множество записи аудита.
	Marker string `json:"marker,omitempty"`
	// Group и Set -- только при do mutate, оба обязательны: какую группу
	// модификаторов получателя переключить и куда (on | off).
	Group string `json:"group,omitempty"`
	Set   string `json:"set,omitempty"`
	// TTL -- только при DoArchive с Set on: срок объектов в архиве секундами
	// (указатель: явный ноль -- "вечно" -- отличается от отсутствия).
	TTL *int64 `json:"ttl,omitempty"`
	// When -- только при DoArchive с Set on: исходы маршрута, на которых
	// просьбу исполнять, как when= у waf_archive: "allow", "deny" или оба
	// (всё, кроме перенаправления). Пусто -- любой исход, включая
	// перенаправление: просьба сильнее when= маршрута, о котором отправитель
	// не знает.
	When []string `json:"when,omitempty"`
	// Объекты просьбы записи -- как строки директив, объект за объектом: у
	// каждого своя сторона, размер и источник. Нет объекта -- как записано
	// на маршруте.
	Headers *ObjectSpec `json:"headers,omitempty"`
	Args    *ObjectSpec `json:"args,omitempty"`
	Body    *ObjectSpec `json:"body,omitempty"`
}

// ObjectSpec -- объект просьбы записи (audit / archive): Set off исключает
// объект, Limit -- у audit бюджет превью, у archive сколько байт уедет
// (ноль -- весь), Source -- как снято (store) либо оригинал без масок
// снимка (original). Одна структура на провод и YAML профиля.
type ObjectSpec struct {
	Set    string `json:"set,omitempty" yaml:"set"`
	Limit  int64  `json:"limit,omitempty" yaml:"limit"`
	Source string `json:"source,omitempty" yaml:"source"`
}

// ArchiveWhen -- слова исхода архива, как их понимает модуль.
var ArchiveWhen = []string{"allow", "deny"}

/*
 * CheckArchiveWhen -- та же отбраковка, что у модуля на проводе: только allow
 * и deny, каждое не дважды. Возвращает набор в каноническом порядке, чтобы
 * профиль и провод не расходились из-за порядка слов в файле. Пустой набор --
 * "любой исход": он и пишется отсутствием ключа.
 */
func CheckArchiveWhen(words []string) ([]string, error) {
	seen := map[string]bool{}

	for _, word := range words {
		name := strings.ToLower(strings.TrimSpace(word))

		if name != "allow" && name != "deny" {
			return nil, fmt.Errorf("when accepts only allow and deny, got %q", word)
		}

		if seen[name] {
			return nil, fmt.Errorf("when lists %q twice", name)
		}

		seen[name] = true
	}

	out := []string{}

	for _, name := range ArchiveWhen {
		if seen[name] {
			out = append(out, name)
		}
	}

	if len(out) == 0 {
		return nil, nil
	}

	return out, nil
}

// CheckObjectSpec -- та же отбраковка, что у модуля на проводе: сторона,
// размер, источник. nil -- объект не назван, проверять нечего.
func CheckObjectSpec(name string, o *ObjectSpec, audit bool) error {
	if o == nil {
		return nil
	}

	if o.Set != "" && o.Set != "on" && o.Set != "off" {
		return fmt.Errorf("%s.set must be on or off, got %q", name, o.Set)
	}

	if o.Limit < 0 {
		return fmt.Errorf("%s.limit must not be negative", name)
	}

	if o.Source != "" && o.Source != "store" && o.Source != "original" {
		return fmt.Errorf("%s.source must be store or original, got %q", name, o.Source)
	}

	// Без размера объект берётся целиком: у audit -- до потолка датаграммы.
	// Отдельного правила для журнала нет: audit здесь ради одинаковой формы.
	_ = audit

	return nil
}

// Словарь глаголов. Короткий намеренно: глагол называет намерение, понятное
// всему контуру, а частности живут в Code.
const (
	DoChallenge = "challenge"
	DoThreshold = "threshold"
	DoSkip      = "skip"
	DoReauth    = "reauth"
	DoNote      = "note"
	DoMutate    = "mutate"
	// Управляющие глаголы: исполняет модуль, а не сосед. Адресат -- вызов на
	// маршруте, глагол ставит ему режим до конца запроса (на кадрах с осью
	// conn -- до конца соединения): active -- спрашивать и гейтить, passive
	// -- спрашивать ради лога, vote -- спрашивать ради очков (deny как 100,
	// сам не решает), off -- не спрашивать. Модуль исполняет их от любого
	// инспектора, спрошенного на маршруте.
	DoActive  = "active"
	DoPassive = "passive"
	DoOff     = "off"
	DoVote    = "vote"

	// Глаголы записи: тоже исполняет модуль, но адресат -- не вызов соседа, а
	// запись самого маршрута. DoAudit -- писать ли запрос в журнал вопреки
	// waf_audit_sample, DoArchive -- оставлять ли объекты агенту вопреки
	// waf_archive, и с каким сроком, пределом и набором. Просить вправе любой
	// спрошенный инспектор; поля to у них нет.
	DoAudit   = "audit"
	DoArchive = "archive"

	// DoMark -- маркер: метка события на записи этого запроса (на кадрах --
	// кадра). Адресат тот же, что у глаголов записи, -- запись самого
	// маршрута, и поля to нет: прятать маркером нечего, он только
	// добавляет строку в множество markers записи, по которой события
	// ищут и группируют.
	DoMark = "mark"

	// DoScore -- очки на маршруте: value со знаком к сумме фазы этого
	// запроса. Исполняет модуль при приёме; адресат -- сумма самого
	// маршрута, поля to нет. Пассивный отправитель просить не может.
	DoScore = "score"
)

// Оси. Ось называет субъекта; во что её превратить, решает получатель.
// conn -- до конца соединения кадров, только у управляющих глаголов.
const (
	ApplyRequest = "request"
	ApplyIP      = "ip"
	ApplyASN     = "asn"
	ApplySession = "session"
	ApplyConn    = "conn"
	// ApplyResponse -- только у глаголов записи: запись ответа этой
	// транзакции; request у них -- запись запроса (на кадрах -- кадра).
	ApplyResponse = "response"
)

/*
 * PriorVerdict -- полная запись о том, кто высказался раньше: кто, на какой
 * фазе и волне, что решил и о чём просит. Сквозная по фазам: на response
 * приезжают и записи фазы запроса.
 *
 * Записей пассивного отправителя здесь нет вовсе: пассивный не должен влиять
 * на трафик чужими руками, а режим, который держится на умолчании в чужом
 * профиле, -- не режим. Что он сказал, видно в аудите.
 */
type PriorVerdict struct {
	Inspector string   `json:"inspector"`
	Phase     string   `json:"phase"`
	Wave      int      `json:"wave"`
	Verdict   string   `json:"verdict"`
	Score     int      `json:"score"`
	Reason    *Reason  `json:"reason,omitempty"`
	Actions   []Action `json:"actions,omitempty"`
}

/*
 * Release -- "продолжение не понадобится, брось состояние". Состояния у этого
 * инспектора нет, но сообщение законное: разбор обязан его узнать, чтобы не
 * отвечать на него -- слот в модуле уже закрыт.
 */
type Release struct {
	Token  string `json:"token"`
	Reason string `json:"reason"`
}

type Request struct {
	V          int    `json:"v"`
	RID        string `json:"rid"`
	Ray        string `json:"ray"`
	Phase      string `json:"phase"`
	Wave       int    `json:"wave"`
	Inspector  string `json:"inspector"`
	DeadlineMS int    `json:"deadline_ms"`
	// Куда публиковать подробности находок. Приезжает с сообщением, а не зашит
	// здесь: subject -- часть топологии контура. null означает, что деталей с
	// этого инспектора не ждут.
	AuditSubject *string `json:"audit_subject"`
	Node         string  `json:"node"`
	Conn         Conn    `json:"conn"`
	HTTP         HTTP    `json:"http"`
	// Vars -- поля запроса: стандартный набор модуля и waf_var, те, что названы
	// в vars= объявления этого имени. Секции нет -- nil.
	Vars map[string]string `json:"vars"`

	Needs    []string       `json:"needs"`
	Store    Store          `json:"store"`
	Route    Route          `json:"route"`
	Score    ScoreState     `json:"score"`
	Prior    []PriorVerdict `json:"prior"`
	Response *Response      `json:"response"`
	Release  *Release       `json:"release"`
}

const (
	PhaseRequest  = "request"
	PhaseResponse = "response"
	PhaseFrame    = "frame"
)

// Needs, как их называет модуль и waf_capture. Одно множество, названное с
// двух сторон.
const (
	NeedHeaders = "headers"
	NeedArgs    = "args"
	NeedBody    = "body"
)

// Needed отвечает на вопрос "мне это вообще обещали". Нужно там, где отсутствие
// объекта надо объяснить: "маршрут не даёт" и "класть было нечего" в локаторе
// выглядят одинаково, а разбираются по-разному.
func (r *Request) Needed(obj string) bool {
	for _, n := range r.Needs {
		if n == obj {
			return true
		}
	}

	return false
}

/* --- ответ инспектора ------------------------------------------------------ */

const (
	VerdictAllow    = "allow"
	VerdictScore    = "score"
	VerdictRedirect = "redirect"
	VerdictDeny     = "deny"
	/*
	 * "Проверить не смог": перегрузка, недоступный движок, неизвестный профиль,
	 * чужая фаза. Не вердикт -- признанное его отсутствие: модуль срывает волну
	 * и применяет waf_exception класса inspector. До него приходилось врать --
	 * allow означал "проверил и чисто", deny блокировал за свою поломку.
	 *
	 * Всё, что при вердикте применяется (счёт, переопределения, подмена,
	 * cookie, просьбы соседям), при error модуль выбрасывает: инспектор, не
	 * выполнивший работу, не вправе и просить о чужой. Причина обязательна.
	 */
	VerdictError = "error"
)

// Reason -- только код. Текст находки и номер правила уехали в событие
// kind=inspector: модуль их не применял, а на горячем пути они раздували
// ответ. Код остался, потому что применяется по-настоящему -- попадает в
// диагностический заголовок и выбирает запись каталога отказов.
type Reason struct {
	Code string `json:"code"`
	// Class -- какого рода отсутствие вердикта. Пусто -- обычный error, и
	// модуль судит его классом inspector waf_exception. "overload" -- запрос
	// сброшен на входе: очередь полна либо бюджет протух до начала работы;
	// у модуля для этого свой класс, и оператор вправе судить перегрузку
	// иначе, чем поломку.
	Class string `json:"class,omitempty"`
}

// ResponseRef -- только символьное имя записи каталога waf_deny_response. Ни
// кода, ни страницы с провода модуль не примет: отдаёт их он сам.
type ResponseRef struct {
	Name string `json:"name"`
}

// RedirectRef -- единственное место, где с провода едет адрес, а не имя. Модуль
// сверяет его с waf_redirect_allow маршрута и ответ с непрошедшей целью
// отбрасывает целиком.
type RedirectRef struct {
	URL    string `json:"url"`
	Status int    `json:"status,omitempty"`
}

type HeaderOps struct {
	Set   map[string]string `json:"set,omitempty"`
	Unset []string          `json:"unset,omitempty"`
}

// Reply -- решение и переопределения, больше ничего. Всё, чем инспектор
// объясняет вердикт, живёт в событии kind=inspector.
type Reply struct {
	V         int          `json:"v"`
	RID       string       `json:"rid"`
	Inspector string       `json:"inspector"`
	Verdict   string       `json:"verdict"`
	Score     *int         `json:"score,omitempty"`
	Reason    *Reason      `json:"reason,omitempty"`
	Response  *ResponseRef `json:"response,omitempty"`
	Redirect  *RedirectRef `json:"redirect,omitempty"`
	Headers   *HeaderOps   `json:"headers,omitempty"`
	// Actions от вердикта не зависят: чаще всего они едут вместе с allow, и
	// это основной случай -- инспектор адреса рассказывает соседям больше,
	// чем блокирует сам.
	Actions []Action `json:"actions,omitempty"`
}

/* --- разбор входящего сообщения -------------------------------------------- */

// ParseError несёт rid отдельно от текста: ответ без эха rid модуль отбрасывает,
// а молчание для него неотличимо от перегрузки инспектора. Поэтому даже
// нераспарсенное сообщение обязано получить ответ, и для него нужен rid.
type ParseError struct {
	RID string
	Err error
}

func (e *ParseError) Error() string { return e.Err.Error() }
func (e *ParseError) Unwrap() error { return e.Err }

func Parse(payload []byte) (*Request, error) {
	var req Request

	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, &ParseError{RID: SniffRID(payload), Err: fmt.Errorf("invalid json: %w", err)}
	}

	if req.RID == "" {
		return nil, &ParseError{Err: fmt.Errorf("field rid is missing or empty")}
	}

	if req.V == 0 {
		return nil, &ParseError{RID: req.RID, Err: fmt.Errorf("field v is missing")}
	}

	if req.Inspector == "" {
		return nil, &ParseError{RID: req.RID, Err: fmt.Errorf("field inspector is missing or empty")}
	}

	switch req.Phase {
	case PhaseRequest, PhaseResponse, PhaseFrame:
	default:
		return nil, &ParseError{RID: req.RID, Err: fmt.Errorf("field phase is invalid: %q", req.Phase)}
	}

	/*
	 * Освобождение -- не инспекция: ни http, ни обменника, ни вердикта в ответ.
	 * Дальше проверять нечего, кроме ключа: без него бросать нечего.
	 */
	if req.Release != nil {
		if req.Release.Token == "" {
			return nil, &ParseError{
				RID: req.RID,
				Err: fmt.Errorf("section release has no token"),
			}
		}

		return &req, nil
	}

	if req.HTTP.Method == "" || req.HTTP.URI == "" {
		return nil, &ParseError{RID: req.RID, Err: fmt.Errorf("section http has no method or uri")}
	}

	for name, loc := range map[string]*Locator{
		NeedHeaders: req.Store.Headers,
		NeedArgs:    req.Store.Args,
		NeedBody:    req.Store.Body,
	} {
		if err := loc.validate(name); err != nil {
			return nil, &ParseError{RID: req.RID, Err: err}
		}
	}

	return &req, nil
}

// Локатор обязан быть одной из трёх форм. Смешение форм -- это ошибка на
// стороне модуля, и ловить её надо здесь, а не там, где выбор формы уже
// превратился бы в молчаливый выбор ветки switch.
func (l *Locator) validate(obj string) error {
	if l == nil {
		return nil
	}

	if l.Unavailable != "" && (l.Driver != "" || l.Key != "") {
		return fmt.Errorf("store.%s mixes unavailable with an address", obj)
	}

	if (l.Driver == "") != (l.Key == "") {
		return fmt.Errorf("store.%s names a store without driver or key", obj)
	}

	return nil
}

/*
 * Последняя попытка достать rid из нераспарсенного сообщения. Регулярное
 * выражение здесь уместно ровно потому, что структуры уже нет: без rid ответ не
 * найдёт слот в модуле и запрос будет ждать до дедлайна впустую.
 */
var ridPattern = regexp.MustCompile(`"rid"\s*:\s*"([0-9a-fA-F]{1,32})"`)

func SniffRID(payload []byte) string {
	m := ridPattern.FindSubmatch(payload)
	if m == nil {
		return ""
	}

	return string(m[1])
}

/* --- сборка ответа --------------------------------------------------------- */

// NewReply готовит ответ с эхом v, rid и имени инспектора.
//
// Имя берётся из пришедшего сообщения, а не из конфигурации: ответ учитывается
// модулем, только если поле inspector входит в маску текущей волны, а под каким
// именем этот процесс объявлен в nginx, знает только само сообщение.
func NewReply(req *Request, verdict string) *Reply {
	return &Reply{V: req.V, RID: req.RID, Inspector: req.Inspector, Verdict: verdict}
}

// ErrorReply -- ответ "проверить не смог": вердикт error и обязательная
// причина. Что делать с запросом, решает маршрут (waf_exception … inspector).
func ErrorReply(req *Request, code string) *Reply {
	reply := NewReply(req, VerdictError)
	reply.Reason = &Reason{Code: code}

	return reply
}

// ClassOverload -- слово провода для сброса на входе; модуль судит такой
// ответ классом overload waf_exception.
const ClassOverload = "overload"

// ShedReply -- ответ снятого на входе запроса: тот же error, но названный
// перегрузкой. Проверки не было, и вердикта нет; что делать с запросом,
// решает маршрут, а не инспектор.
func ShedReply(req *Request, code string) *Reply {
	reply := ErrorReply(req, code)
	reply.Reason.Class = ClassOverload

	return reply
}

// FallbackReply -- ответ на сообщение, которое не удалось разобрать. Версия
// подставляется своя: узнать чужую уже неоткуда.
func FallbackReply(rid, inspector, code string) *Reply {
	return &Reply{
		V:         Version,
		RID:       rid,
		Inspector: inspector,
		Verdict:   VerdictError,
		Reason:    &Reason{Code: code},
	}
}

var ErrScoreRange = fmt.Errorf("score is out of the 0..100 range")

// WithScore выставляет вердикт score. Значение вне диапазона -- ошибка здесь, а
// не то, что можно отправить на шину и разобраться в модуле: такой ответ
// отбраковывается целиком, то есть инспектор молча выпадает из решения.
func (r *Reply) WithScore(score int) error {
	if score < 0 || score > 100 {
		return fmt.Errorf("%w: %d", ErrScoreRange, score)
	}

	r.Verdict = VerdictScore
	r.Score = &score

	return nil
}

func (r *Reply) Marshal() ([]byte, error) {
	if r.Score != nil && (*r.Score < 0 || *r.Score > 100) {
		return nil, fmt.Errorf("%w: %d", ErrScoreRange, *r.Score)
	}

	return json.Marshal(r)
}

// MarkerMax -- предел длины метки на проводе, байт. Длиннее модуль отбраковывает
// вместе со всем ответом, поэтому собрать такой профиль нельзя.
const MarkerMax = 128

/*
 * CheckMarker -- та же отбраковка, что у модуля: метка непуста, не длиннее
 * предела, без управляющих символов и без крайних пробелов. Алфавита у неё
 * нет: её читает человек в журнале, а не загрузчик профиля.
 */
func CheckMarker(marker string) error {
	if marker == "" {
		return fmt.Errorf("mark needs a marker")
	}

	if len(marker) > MarkerMax {
		return fmt.Errorf("marker is longer than %d bytes", MarkerMax)
	}

	for i := 0; i < len(marker); i++ {
		if marker[i] < 0x20 || marker[i] == 0x7f {
			return fmt.Errorf("marker has a control character")
		}
	}

	if marker[0] == ' ' || marker[len(marker)-1] == ' ' {
		return fmt.Errorf("marker has a leading or trailing space")
	}

	return nil
}
