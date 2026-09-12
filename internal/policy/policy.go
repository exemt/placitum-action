/*
 * Профили инспектора действий.
 *
 * Этот инспектор ничего не проверяет и сам никого не блокирует: он смотрит на
 * маршрут и рассказывает соседям -- действиями канала docs/inspector-actions.md.
 * Профиль -- список правил "признак запроса -> действия": успокоить modsec на
 * доверенном пути, сообщить капче факт про загрузку статики, попросить
 * пропустить служебный маршрут, добавить или снять очки на маршруте (do:
 * score -- исполняет модуль, а не сосед), внести адрес клиента, его подсеть
 * или систему в живой набор (list: -- исполняет сам инспектор, а режет по
 * набору тот, кто стоит перед маршрутом).
 *
 * Правила накопительные, терминальных нет: срабатывают все совпавшие, действия
 * складываются в порядке правил. Порядок строк -- порядок отправки, а предел
 * количества держит модуль (waf_actions_max).
 *
 * Валидация повторяет отбраковку модуля: несовпадение глагола и оси, числа вне
 * диапазона, кривой повод стоили бы на проводе всего ответа, поэтому такой
 * профиль не грузится вовсе.
 */

package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/exemt/placitum-action/internal/protocol"
)

const DefaultName = "default"

const (
	ModeEnforce = "enforce"
	ModeOff     = "off"
)

/*
 * Кого писать в набор -- те же слова, что у остальных отправителей: адрес
 * клиента либо то, во что он разворачивается у кодера гео (netinfo.Values):
 * net -- эффективный анонс, самый узкий; net_all -- все анонсы, накрывающие
 * адрес, включая чужие широкие; asn -- состав системы эффективного анонса.
 */
const (
	WriteAddr   = "addr"
	WriteNet    = "net"
	WriteNetAll = "net_all"
	WriteASN    = "asn"
)

// DefaultWriteReason -- повод записи в набор, когда строка своего не назвала.
const DefaultWriteReason = "ACTION_LIST"

/*
 * Глаголы словаря и допустимые для каждого оси -- копия реестра контроллера
 * (controller/src/model/actions.ts). Инспектор действие не толкует, он только
 * не даёт собрать то, чего модуль всё равно не пропустит.
 */
var verbs = map[string][]string{
	protocol.DoChallenge: {protocol.ApplyRequest},
	protocol.DoThreshold: {protocol.ApplyRequest},
	protocol.DoSkip:      {protocol.ApplyRequest},
	protocol.DoReauth:    {protocol.ApplySession},
	protocol.DoNote: {
		protocol.ApplyRequest, protocol.ApplyIP, protocol.ApplyASN, protocol.ApplySession,
	},
	protocol.DoMutate:  {protocol.ApplyRequest},
	protocol.DoActive:  {protocol.ApplyRequest, protocol.ApplyConn},
	protocol.DoPassive: {protocol.ApplyRequest, protocol.ApplyConn},
	protocol.DoOff:     {protocol.ApplyRequest, protocol.ApplyConn},
	protocol.DoVote:    {protocol.ApplyRequest, protocol.ApplyConn},
	// Глаголы записи: журнал и архив этого запроса. Исполняет модуль от
	// любого спрошенного инспектора; адресата нет.
	protocol.DoAudit:   {protocol.ApplyRequest, protocol.ApplyResponse},
	protocol.DoArchive: {protocol.ApplyRequest, protocol.ApplyResponse},
	// Маркер: метка события на записи. Адресат тот же -- запись маршрута, --
	// но грант ему не нужен: метка ничего не прячет.
	protocol.DoMark: {protocol.ApplyRequest},
	// Очки на маршруте: value со знаком к сумме фазы, исполняет модуль;
	// адресат -- сумма самого маршрута, поля to нет.
	protocol.DoScore: {protocol.ApplyRequest},
}

// auditVerb -- глагол записи: исполняет модуль в адрес записи маршрута,
// поля to нет; сторона set обязательна, срок, предел и набор объектов --
// только у archive с set on.
func auditVerb(do string) bool {
	return do == protocol.DoAudit || do == protocol.DoArchive
}

/*
 * recordVerb -- адресат глагола не сосед, а запись самого маршрута: журнал,
 * архив и маркер. Поля to у них нет.
 */
func recordVerb(do string) bool {
	return auditVerb(do) || do == protocol.DoMark || do == protocol.DoScore
}

// archiveObject -- объект обменника, который умеет назвать archive.
func archiveObject(name string) bool {
	return name == "headers" || name == "args" || name == "body"
}

// Повод: то же ограничение, которым модуль отбраковывает действие с провода.
var codeRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// Имя корзины у note: алфавит имён счётчиков получателя, модульная форма та же.
var counterRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

/*
 * Статика по расширению. Список нарочно короткий и без картинок-приманок вроде
 * .php: он отвечает на вопрос "похоже ли это на подгрузку ресурсов страницы
 * живым браузером", а не классифицирует контент. Уточняется suffixes правила.
 */
var staticSuffixes = []string{
	".css", ".js", ".mjs", ".map",
	".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
	".woff", ".woff2", ".ttf", ".eot",
}

/* --- профиль --------------------------------------------------------------- */

// Match -- признаки запроса. Все заданные блоки обязаны совпасть (И); пустой
// Match совпадает со всяким запросом: профиль и так выбран маршрутом.
type Match struct {
	// Префикс пути; путь приезжает без строки запроса.
	PathPrefix string
	// Суффиксы пути, без регистра. Достаточно одного совпавшего.
	Suffixes []string
	// Static добавляет к Suffixes встроенный список расширений статики.
	Static bool
	// Методы; пусто -- любой.
	Methods []string
}

type Rule struct {
	// Имя правила: живёт в логе и аудите, на провод не едет.
	Name  string
	Match Match
	// Cond -- имя условия профиля (cond.go); пусто -- правило всегда. Negate
	// -- действия едут, когда условие ложно (`unless:` в файле).
	Cond    string
	Negate  bool
	Actions []protocol.Action
	// Writes -- записи в живые наборы: исполняет сам инспектор, на провод
	// модулю они не едут.
	Writes []Write
}

/*
 * Write -- запись субъекта запроса в живой набор: адрес клиента либо его
 * подсеть или система (Subject), на срок и с поводом. Это не просьба канала:
 * адресата и оси у неё нет, пишет сам инспектор -- одним кадром keeper.
 */
type Write struct {
	List    string
	Subject string
	TTL     time.Duration
	Reason  string
}

type Profile struct {
	Name string
	Mode string
	// Conditions -- именованные условия, на которые ссылаются правила.
	Conditions map[string]*Condition
	Rules      []Rule
}

// Datasets -- имена наборов, которые читают условия профиля: зеркалу их надо
// заказать до первого запроса.
func (p *Profile) Datasets() []string {
	seen := map[string]bool{}

	var out []string

	for _, name := range sortedKeys(p.Conditions) {
		for _, cl := range p.Conditions[name].Clauses {
			if cl.Dataset != "" && !seen[cl.Dataset] {
				seen[cl.Dataset] = true
				out = append(out, cl.Dataset)
			}
		}
	}

	return out
}

func sortedKeys(m map[string]*Condition) []string {
	out := make([]string, 0, len(m))

	for k := range m {
		out = append(out, k)
	}

	sort.Strings(out)

	return out
}

// Matches отвечает, накрывает ли правило запрос.
func (m *Match) Matches(method, uri string) bool {
	if m.PathPrefix != "" && !strings.HasPrefix(uri, m.PathPrefix) {
		return false
	}

	if len(m.Methods) > 0 {
		ok := false

		for _, want := range m.Methods {
			if strings.EqualFold(method, want) {
				ok = true
				break
			}
		}

		if !ok {
			return false
		}
	}

	suffixes := m.Suffixes
	if m.Static {
		suffixes = append(append([]string{}, suffixes...), staticSuffixes...)
	}

	if len(suffixes) > 0 {
		lower := strings.ToLower(uri)
		ok := false

		for _, s := range suffixes {
			if strings.HasSuffix(lower, s) {
				ok = true
				break
			}
		}

		if !ok {
			return false
		}
	}

	return true
}

/*
 * Collect собирает действия и записи в наборы всех совпавших правил и их
 * имена -- для аудита. Признак запроса считается раньше условия: у него нет
 * походов в обменник, и правило, снятое по пути, обменник не трогает. ev
 * может быть nil, если у профиля нет условий вовсе.
 */
func (p *Profile) Collect(ev *Evaluator, method, uri string) ([]protocol.Action, []Write, []string) {
	var (
		actions []protocol.Action
		writes  []Write
		names   []string
	)

	for i := range p.Rules {
		r := &p.Rules[i]

		if !r.Match.Matches(method, uri) {
			continue
		}

		if r.Cond != "" {
			holds := ev != nil && ev.Holds(r.Cond)

			if holds == r.Negate {
				continue
			}
		}

		actions = append(actions, r.Actions...)
		writes = append(writes, r.Writes...)
		names = append(names, r.Name)
	}

	return actions, writes, names
}

/* --- разбор файлов --------------------------------------------------------- */

type fileAction struct {
	To    string `yaml:"to"`
	Do    string `yaml:"do"`
	Apply string `yaml:"apply"`
	// Фаза вызова адресата у управляющих глаголов; пусто -- всем вызовам имени.
	Phase string `yaml:"phase"`
	Code  string `yaml:"code"`
	Delta *int   `yaml:"delta"`
	Value *int   `yaml:"value"`
	// Корзина получателя при do: note -- селектор поверх его правил приёма.
	Counter string `yaml:"counter"`
	// Группа модификаторов получателя и сторона тумблера при do: mutate;
	// у глаголов записи set -- писать или нет.
	Group string `yaml:"group"`
	Set   string `yaml:"set"`
	// Метка события при do: mark, обязательна. Произвольная строка оператора.
	Marker string `yaml:"marker"`
	// Только при do: archive с set on: срок в архиве ("30d"), предел байтами
	// и набор объектов. Без них действует записанное на маршруте.
	TTL string `yaml:"ttl"`
	// Исходы, на которых просьбу исполнять (when= директивы): allow, deny или
	// оба. Пусто -- любой исход, включая перенаправление.
	When    []string             `yaml:"when"`
	Headers *protocol.ObjectSpec `yaml:"headers"`
	Args    *protocol.ObjectSpec `yaml:"args"`
	Body    *protocol.ObjectSpec `yaml:"body"`
	// List -- запись в живой набор вместо просьбы: имя набора, кого писать
	// (Write: addr, net, net_all, asn) и срок -- тот же ключ ttl.
	List  string `yaml:"list"`
	Write string `yaml:"write"`
}

type fileMatch struct {
	PathPrefix string   `yaml:"path_prefix"`
	Suffixes   []string `yaml:"suffixes"`
	Static     bool     `yaml:"static"`
	Methods    []string `yaml:"methods"`
}

type fileRule struct {
	Name  string    `yaml:"name"`
	Match fileMatch `yaml:"match"`
	// If / Unless -- имя условия профиля: действия едут, когда оно истинно
	// либо, соответственно, ложно. Одно из двух; без обоих -- всегда.
	If      string       `yaml:"if"`
	Unless  string       `yaml:"unless"`
	Actions []fileAction `yaml:"actions"`
}

type fileProfile struct {
	Mode       string          `yaml:"mode"`
	Conditions []fileCondition `yaml:"conditions"`
	Rules      []fileRule      `yaml:"rules"`
}

func Parse(name string, raw []byte) (*Profile, error) {
	var f fileProfile

	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}

	p := &Profile{Name: name, Mode: strings.TrimSpace(f.Mode)}

	if p.Mode == "" {
		p.Mode = ModeEnforce
	}

	if p.Mode != ModeEnforce && p.Mode != ModeOff {
		return nil, fmt.Errorf("%s: mode must be enforce or off, got %q", name, p.Mode)
	}

	conds, err := parseConditions(name, f.Conditions)
	if err != nil {
		return nil, err
	}

	p.Conditions = conds

	for i, fr := range f.Rules {
		at := fmt.Sprintf("%s: rules[%d]", name, i)

		rule, err := parseRule(at, i, fr, conds)
		if err != nil {
			return nil, err
		}

		p.Rules = append(p.Rules, rule)
	}

	return p, nil
}

func parseRule(at string, index int, fr fileRule, conds map[string]*Condition) (Rule, error) {
	rule := Rule{
		Name: strings.TrimSpace(fr.Name),
		Match: Match{
			PathPrefix: strings.TrimSpace(fr.Match.PathPrefix),
			Static:     fr.Match.Static,
		},
	}

	// Имя живёт только в логе и аудите; не назвали -- порядковое. Требовать
	// его значило бы заставлять придумывать слова тому, у кого их нет.
	if rule.Name == "" {
		rule.Name = fmt.Sprintf("rule-%d", index+1)
	}

	/*
	 * Ссылка на условие -- только на объявленное: опечатка в имени иначе
	 * становилась бы правилом, которое не срабатывает никогда (if) либо
	 * срабатывает всегда (unless), и ни то ни другое не видно.
	 */
	ifName, unlessName := strings.TrimSpace(fr.If), strings.TrimSpace(fr.Unless)

	if ifName != "" && unlessName != "" {
		return rule, fmt.Errorf("%s: if and unless together -- pick one", at)
	}

	rule.Cond = ifName
	rule.Negate = unlessName != ""

	if rule.Negate {
		rule.Cond = unlessName
	}

	if rule.Cond != "" {
		if _, ok := conds[rule.Cond]; !ok {
			return rule, fmt.Errorf("%s: condition %q is not declared in conditions", at, rule.Cond)
		}
	}

	for _, s := range fr.Match.Suffixes {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			return rule, fmt.Errorf("%s: empty suffix", at)
		}

		rule.Match.Suffixes = append(rule.Match.Suffixes, s)
	}

	for _, m := range fr.Match.Methods {
		m = strings.ToUpper(strings.TrimSpace(m))
		if m == "" {
			return rule, fmt.Errorf("%s: empty method", at)
		}

		rule.Match.Methods = append(rule.Match.Methods, m)
	}

	if len(fr.Actions) == 0 {
		return rule, fmt.Errorf("%s: no actions -- a rule that sends nothing is dead weight", at)
	}

	for j, fa := range fr.Actions {
		where := fmt.Sprintf("%s.actions[%d]", at, j)

		// Строка с набором -- запись, а не просьба: исполняет сам инспектор.
		if strings.TrimSpace(fa.List) != "" {
			w, err := parseWrite(where, fa)
			if err != nil {
				return rule, err
			}

			rule.Writes = append(rule.Writes, w)

			continue
		}

		action, err := parseAction(where, fa)
		if err != nil {
			return rule, err
		}

		rule.Actions = append(rule.Actions, action)
	}

	return rule, nil
}

/*
 * parseWrite -- запись в живой набор. Кого писать: адрес клиента (addr, по
 * умолчанию) либо то, во что он разворачивается у кодера гео. Срок
 * обязателен: запись без срока пережила бы причину, по которой её сделали.
 * Остальные поля просьбы здесь -- битая форма: у записи нет ни адресата, ни
 * оси, ни глагола, и молча отброшенное поле выглядело бы работающим.
 */
func parseWrite(at string, fa fileAction) (Write, error) {
	w := Write{
		List:    strings.TrimSpace(fa.List),
		Subject: strings.TrimSpace(fa.Write),
		Reason:  strings.TrimSpace(fa.Code),
	}

	if w.Subject == "" {
		w.Subject = WriteAddr
	}

	if !counterRe.MatchString(w.List) {
		return w, fmt.Errorf("%s: list %q is not a dataset name", at, w.List)
	}

	switch w.Subject {
	case WriteAddr, WriteNet, WriteNetAll, WriteASN:
	default:
		return w, fmt.Errorf("%s: write must be %s, %s, %s or %s, got %q",
			at, WriteAddr, WriteNet, WriteNetAll, WriteASN, w.Subject)
	}

	if strings.TrimSpace(fa.Do) != "" || strings.TrimSpace(fa.To) != "" ||
		strings.TrimSpace(fa.Apply) != "" || strings.TrimSpace(fa.Phase) != "" ||
		fa.Delta != nil || fa.Value != nil || strings.TrimSpace(fa.Counter) != "" ||
		strings.TrimSpace(fa.Group) != "" || strings.TrimSpace(fa.Set) != "" ||
		strings.TrimSpace(fa.Marker) != "" || len(fa.When) != 0 ||
		fa.Headers != nil || fa.Args != nil || fa.Body != nil {
		return w, fmt.Errorf("%s: a list write takes only list, write, ttl and code", at)
	}

	if strings.TrimSpace(fa.TTL) == "" {
		return w, fmt.Errorf("%s: a list write needs ttl", at)
	}

	ttl, err := parseTTL(fa.TTL)
	if err != nil {
		return w, fmt.Errorf("%s: %w", at, err)
	}

	if ttl < time.Second {
		return w, fmt.Errorf("%s: ttl %q is shorter than a second", at, fa.TTL)
	}

	w.TTL = ttl

	if w.Reason == "" {
		w.Reason = DefaultWriteReason
	} else if !codeRe.MatchString(w.Reason) {
		return w, fmt.Errorf("%s: code %q is not [A-Z][A-Z0-9_]{0,63}", at, w.Reason)
	}

	return w, nil
}

// controlVerb -- глагол исполняет модуль в адрес вызова соседа.
func controlVerb(do string) bool {
	switch do {
	case protocol.DoActive, protocol.DoPassive, protocol.DoVote, protocol.DoOff:
		return true
	}

	return false
}

// checkPhaseAsk -- фаза вызова адресата: только у управляющих глаголов, одно
// из request, response, frame; с осью conn -- только frame либо без поля: до
// конца соединения живут одни кадры. Пусто -- всем вызовам имени.
func checkPhaseAsk(do, phase, apply string) error {
	if phase == "" {
		return nil
	}

	if !controlVerb(do) {
		return fmt.Errorf("phase is only for active, passive, vote and off")
	}

	switch phase {
	case protocol.PhaseRequest, protocol.PhaseResponse, protocol.PhaseFrame:
	default:
		return fmt.Errorf("phase must be request, response or frame, got %q", phase)
	}

	if apply == protocol.ApplyConn && phase != protocol.PhaseFrame {
		return fmt.Errorf("apply conn needs phase frame")
	}

	return nil
}

func parseAction(at string, fa fileAction) (protocol.Action, error) {
	action := protocol.Action{
		To:      strings.TrimSpace(fa.To),
		Do:      strings.TrimSpace(fa.Do),
		Apply:   strings.TrimSpace(fa.Apply),
		Phase:   strings.TrimSpace(fa.Phase),
		Code:    strings.TrimSpace(fa.Code),
		Delta:   fa.Delta,
		Value:   fa.Value,
		Counter: strings.TrimSpace(fa.Counter),
		Marker:  strings.TrimSpace(fa.Marker),
		Group:   strings.TrimSpace(fa.Group),
		Set:     strings.TrimSpace(fa.Set),
		Headers: fa.Headers,
		Args:    fa.Args,
		Body:    fa.Body,
	}

	// Кого писать -- слово записи в набор; у просьбы ему нечего значить.
	if strings.TrimSpace(fa.Write) != "" {
		return action, fmt.Errorf("%s: write is only for a list write", at)
	}

	if strings.TrimSpace(fa.TTL) != "" {
		d, err := parseTTL(fa.TTL)
		if err != nil {
			return action, fmt.Errorf("%s: %w", at, err)
		}

		ttl := int64(d / time.Second)
		action.TTL = &ttl
	}

	when, err := protocol.CheckArchiveWhen(fa.When)
	if err != nil {
		return action, fmt.Errorf("%s: %w", at, err)
	}

	action.When = when

	/*
	 * Адресат обязателен. Просьба без него доезжает до всех, и применить её
	 * вправе кто угодно: шина рекомендательная, но круг слушателей -- решение
	 * отправителя, и у правила, которое пишут руками, он должен быть написан.
	 * Исключение -- глаголы записи: их адресат -- запись маршрута, и поля to
	 * у них нет по построению.
	 */
	if action.To == "" && !recordVerb(action.Do) {
		return action, fmt.Errorf("%s: to is empty", at)
	}

	axes, ok := verbs[action.Do]
	if !ok {
		return action, fmt.Errorf("%s: unknown do %q", at, action.Do)
	}

	// Ось: где выбора нет, её проставляет словарь. Пустой она уехать не может --
	// действие без оси модуль отбраковывает вместе со всем ответом.
	// У глаголов записи умолчание -- запись запроса (первая ось словаря):
	// правила, писанные до оси response, читаются как прежде.
	if action.Apply == "" && (len(axes) == 1 || recordVerb(action.Do)) {
		action.Apply = axes[0]
	}

	axisOK := false

	for _, a := range axes {
		if a == action.Apply {
			axisOK = true
			break
		}
	}

	if !axisOK {
		return action, fmt.Errorf("%s: apply %q is not allowed for %q (want %s)",
			at, action.Apply, action.Do, strings.Join(axes, ", "))
	}

	if err := checkPhaseAsk(action.Do, action.Phase, action.Apply); err != nil {
		return action, fmt.Errorf("%s: %w", at, err)
	}

	if action.Code != "" && !codeRe.MatchString(action.Code) {
		return action, fmt.Errorf("%s: code %q is not [A-Z][A-Z0-9_]{0,63}", at, action.Code)
	}

	switch action.Do {
	case protocol.DoThreshold:
		if action.Delta == nil {
			return action, fmt.Errorf("%s: threshold requires delta", at)
		}

		// Проценты коэффициента к измерению получателя: множитель
		// 1 + delta/100. Минус -- скидка, плюс -- строже.
		if *action.Delta < -100 || *action.Delta > 900 {
			return action, fmt.Errorf("%s: delta %d is out of -100..900 percent", at, *action.Delta)
		}
	default:
		if action.Delta != nil {
			return action, fmt.Errorf("%s: delta is only for threshold", at)
		}
	}

	switch action.Do {
	case protocol.DoScore:
		// Очки: value обязателен и со знаком, вклад одного инспектора не
		// сильнее сотни; адресат -- сумма самого маршрута.
		if action.Value == nil || *action.Value == 0 {
			return action, fmt.Errorf("%s: score needs a non-zero value", at)
		}

		if *action.Value < -100 || *action.Value > 100 {
			return action, fmt.Errorf("%s: value %d is out of -100..100", at, *action.Value)
		}

		if action.To != "" && action.To != "*" {
			return action, fmt.Errorf("%s: score takes no to: the module adds to the route's own sum", at)
		}

		if action.Counter != "" {
			return action, fmt.Errorf("%s: counter is only for note", at)
		}
	case protocol.DoNote:
		// Проценты шкалы счётчика получателя: плюс пополняет долей порога,
		// минус снимает долю накопленного. Знак применит только получатель,
		// у которого есть правило на этого отправителя по имени.
		if action.Value != nil && (*action.Value < -100 || *action.Value > 100) {
			return action, fmt.Errorf("%s: value %d is out of -100..100 percent", at, *action.Value)
		}

		// Корзина -- селектор поверх правил приёма получателя: имя проходит
		// только через правило, которое его и выдаёт. Пусто -- корзину
		// называет правило.
		if action.Counter != "" && !counterRe.MatchString(action.Counter) {
			return action, fmt.Errorf("%s: counter %q is not a name", at, action.Counter)
		}
	default:
		if action.Value != nil {
			return action, fmt.Errorf("%s: value is only for note and score", at)
		}

		if action.Counter != "" {
			return action, fmt.Errorf("%s: counter is only for note", at)
		}
	}

	// Группа и сторона -- только у mutate, и у mutate -- обе: что именно
	// переключить и куда, называет отправитель, как корзину у note.
	if action.Do == protocol.DoMutate {
		if action.Group == "" {
			return action, fmt.Errorf("%s: mutate needs a group", at)
		}

		if !counterRe.MatchString(action.Group) {
			return action, fmt.Errorf("%s: group %q is not a name", at, action.Group)
		}

		if action.Set != "on" && action.Set != "off" {
			return action, fmt.Errorf("%s: mutate needs set: on or off, got %q", at, action.Set)
		}
	} else if action.Group != "" || (action.Set != "" && !auditVerb(action.Do)) {
		return action, fmt.Errorf("%s: group and set are only for mutate", at)
	}

	/*
	 * Метка -- только у mark, и у mark она обязательна: "пометить" без метки
	 * не просьба. Адресат -- запись маршрута, поэтому названный сосед здесь
	 * та же битая форма, что у глаголов записи.
	 */
	if action.Do == protocol.DoMark {
		if action.To != "" && action.To != "*" {
			return action, fmt.Errorf("%s: %s takes no to: the module marks the route's own record", at, action.Do)
		}

		if err := protocol.CheckMarker(action.Marker); err != nil {
			return action, fmt.Errorf("%s: %w", at, err)
		}
	} else if action.Marker != "" {
		return action, fmt.Errorf("%s: marker is only for %q", at, protocol.DoMark)
	}

	ttl := int64(0)
	if action.TTL != nil {
		ttl = *action.TTL
	}

	// Глагол записи: адресат -- запись маршрута, поля to нет; сторона
	// обязательна; срок, предел и набор объектов -- только у archive с set on.
	if auditVerb(action.Do) {
		if action.To != "" && action.To != "*" {
			return action, fmt.Errorf("%s: %s takes no to: the module writes the route's own record", at, action.Do)
		}

		if action.Set != "on" && action.Set != "off" {
			return action, fmt.Errorf("%s: %s needs set: on or off, got %q", at, action.Do, action.Set)
		}

		if action.Set == "off" && (ttl != 0 || len(action.When) != 0 || action.Headers != nil || action.Args != nil || action.Body != nil) {
			return action, fmt.Errorf("%s: ttl, when and objects are only for set on", at)
		}

		if action.Do == protocol.DoAudit && (ttl != 0 || len(action.When) != 0) {
			return action, fmt.Errorf("%s: ttl and when are only for archive", at)
		}

		// У записи ответа строки запроса нет.
		if action.Apply == protocol.ApplyResponse && action.Args != nil {
			return action, fmt.Errorf("%s: args has no meaning for the response record", at)
		}

		for _, item := range []struct {
			name string
			spec *protocol.ObjectSpec
		}{{"headers", action.Headers}, {"args", action.Args}, {"body", action.Body}} {
			if err := protocol.CheckObjectSpec(item.name, item.spec, action.Do == protocol.DoAudit); err != nil {
				return action, fmt.Errorf("%s: %w", at, err)
			}
		}
	}

	if !auditVerb(action.Do) && (action.TTL != nil || len(action.When) != 0 ||
		action.Headers != nil || action.Args != nil || action.Body != nil) {
		return action, fmt.Errorf("%s: ttl, when, headers, args and body are only for audit and archive", at)
	}

	return action, nil
}

// parseTTL -- срок архива: как time.ParseDuration, плюс сутки ("30d"): срок в
// архиве считают днями, а не часами, и остальные загрузчики его так и читают.
func parseTTL(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)

	if strings.HasSuffix(raw, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(raw, "d"))
		if err != nil || n < 0 {
			return 0, fmt.Errorf("bad ttl %q", raw)
		}

		return time.Duration(n) * 24 * time.Hour, nil
	}

	d, err := time.ParseDuration(raw)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("bad ttl %q", raw)
	}

	return d, nil
}

/* --- каталог --------------------------------------------------------------- */

// LoadDir читает каталог профилей: один файл <имя>.yaml на профиль.
func LoadDir(dir string) (map[string]*Profile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	out := make(map[string]*Profile)

	for _, e := range entries {
		name, ok := profileName(e)
		if !ok {
			continue
		}

		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}

		p, err := Parse(name, raw)
		if err != nil {
			return nil, err
		}

		out[name] = p
	}

	return out, nil
}

func profileName(e os.DirEntry) (string, bool) {
	if e.IsDir() || strings.HasPrefix(e.Name(), ".") || strings.HasPrefix(e.Name(), "_") {
		return "", false
	}

	name, found := strings.CutSuffix(e.Name(), ".yaml")
	if !found {
		name, found = strings.CutSuffix(e.Name(), ".yml")
	}

	if !found || name == "" {
		return "", false
	}

	return strings.ToLower(name), true
}

func Names(profiles map[string]*Profile) []string {
	out := make([]string, 0, len(profiles))

	for name := range profiles {
		out = append(out, name)
	}

	sort.Strings(out)

	return out
}
