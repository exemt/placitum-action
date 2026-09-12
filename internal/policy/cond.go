/*
 * Условия профиля: то же, что `if <значение> in|not in <набор>` у вызова
 * инспектора на маршруте, только считает их сам инспектор, а не модуль, и
 * сравнивать умеет ещё и с текстом.
 *
 * Условие -- именованный список строк, сложенных по И (`all`) либо по ИЛИ
 * (`any`): у первого сошлись все -- истинно, у второго -- хоть одна. Строка --
 * либо сравнение значения с набором или текстом, либо ссылка на другое условие
 * (`cond: <имя>`, `op: is | is_not`): так И внутри ИЛИ и любая глубина
 * набираются плоскими именованными условиями, без дерева в файле и в окне.
 * Циклы ссылок отбраковываются на загрузке. Правило ссылается на условие по
 * имени: `if: <имя>` -- действия едут, когда условие истинно, `unless: <имя>`
 * -- когда ложно, без ссылки -- всегда.
 *
 * Значение пишется как у модуля: `$uri`, `$http_x_api_key`, `$cookie_sid`,
 * `$arg_token` -- первое вхождение; `$waf_request_headers.<имя>`,
 * `$waf_request_cookies.<имя>`, `$waf_request_args.<имя>` и `*` вместо имени
 * -- все значения, набор спрашивается о каждом; `$waf_var.<имя>` -- поле из
 * секции vars сообщения (стандартный набор модуля и waf_var). Откуда берётся
 * каждое, решает Source: путь, метод, хост и адрес -- из сообщения, заголовки
 * и строка запроса -- из обменника, поля -- из vars.
 *
 * Семантика совпадения повторяет модуль (local/ngx_http_waf_select.c,
 * ngx_http_waf_cond_test): `in` и `=` истинны, когда сошлось хоть одно
 * значение; `not in` и `!=` -- когда не сошлось ни одно. Пустое значение --
 * это «не в наборе», а не отдельный случай: куки нет -- значит, её нет и в
 * списке доверенных, и `not in` на ней истинно. Так же ведёт себя набор,
 * который зеркало ещё не получило, и объект, которого маршрут не снимает:
 * отсутствие данных никогда не превращается в совпадение.
 */

package policy

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

/* --- операнд: откуда взять значение ---------------------------------------- */

type OperandKind int

const (
	// Поле сообщения: uri, request_uri, host, request_method, scheme,
	// remote_addr.
	OperandField OperandKind = iota
	// $http_<имя>: первый заголовок, имя как у nginx -- строчные, дефис
	// сведён к подчёркиванию.
	OperandHeader
	// $cookie_<имя>: первая кука с таким именем, имя точное.
	OperandCookie
	// $arg_<имя>: первый аргумент строки запроса, имя точное.
	OperandArg
	// $waf_request_headers.<имя|*>: все значения заголовка (регистр имени не
	// важен, дефис и подчёркивание не смешиваются).
	OperandHeaders
	// $waf_request_cookies.<имя|*>: все значения куки.
	OperandCookies
	// $waf_request_args.<имя|*>: все значения аргумента.
	OperandArgs
	// $waf_var.<имя>: поле секции vars.
	OperandVar
)

// Operand -- разобранное значение условия.
type Operand struct {
	Raw  string
	Kind OperandKind
	// Name -- имя пары, поля либо поля сообщения; пусто при All.
	Name string
	// All -- селектор `*`: все пары объекта.
	All bool
}

// Fields -- поля сообщения, которые условие читает как есть.
var Fields = []string{
	"uri", "request_uri", "host", "request_method", "scheme", "remote_addr",
}

const (
	selHeaders = "$waf_request_headers."
	selCookies = "$waf_request_cookies."
	selArgs    = "$waf_request_args."
	selVar     = "$waf_var."
)

// varNameRe -- имя waf_var и стандартного поля, как у модуля.
var varNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// nginxNameRe -- хвост переменной nginx ($http_x_api_key): A-Za-z0-9_.
var nginxNameRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,128}$`)

// ParseOperand разбирает запись значения. Незнакомая запись -- ошибка:
// опечатка в имени иначе становилась бы условием, которое не сходится
// никогда, то есть тихо снятой строкой.
func ParseOperand(raw string) (Operand, error) {
	raw = strings.TrimSpace(raw)
	op := Operand{Raw: raw}

	if raw == "" {
		return op, fmt.Errorf("value is empty")
	}

	if !strings.HasPrefix(raw, "$") {
		return op, fmt.Errorf("value %q must start with $", raw)
	}

	for _, sel := range []struct {
		prefix string
		kind   OperandKind
		all    bool
	}{
		{selHeaders, OperandHeaders, true},
		{selCookies, OperandCookies, true},
		{selArgs, OperandArgs, true},
		{selVar, OperandVar, false},
	} {
		if !strings.HasPrefix(raw, sel.prefix) {
			continue
		}

		name := raw[len(sel.prefix):]

		if name == "" {
			return op, fmt.Errorf("value %q has no name after the dot", raw)
		}

		op.Kind = sel.kind

		if name == "*" {
			if !sel.all {
				return op, fmt.Errorf("value %q: * is only for headers, cookies and args", raw)
			}

			op.All = true

			return op, nil
		}

		if sel.kind == OperandVar && !varNameRe.MatchString(name) {
			return op, fmt.Errorf("value %q: field name is not [A-Za-z0-9_.-]", raw)
		}

		// Имя заголовка сверяется без регистра: сводится здесь один раз.
		if sel.kind == OperandHeaders {
			name = strings.ToLower(name)
		}

		op.Name = name

		return op, nil
	}

	name := raw[1:]

	for _, f := range Fields {
		if name == f {
			op.Kind = OperandField
			op.Name = f

			return op, nil
		}
	}

	for _, p := range []struct {
		prefix string
		kind   OperandKind
	}{
		{"http_", OperandHeader},
		{"cookie_", OperandCookie},
		{"arg_", OperandArg},
	} {
		if !strings.HasPrefix(name, p.prefix) {
			continue
		}

		tail := name[len(p.prefix):]

		if !nginxNameRe.MatchString(tail) {
			return op, fmt.Errorf("value %q: name after %s is not [A-Za-z0-9_]", raw, p.prefix)
		}

		op.Kind = p.kind
		op.Name = tail

		if p.kind == OperandHeader {
			op.Name = strings.ToLower(tail)
		}

		return op, nil
	}

	return op, fmt.Errorf("unknown value %q: expected a field ($uri, $host, $request_method, "+
		"$request_uri, $scheme, $remote_addr), $http_/$cookie_/$arg_<name>, "+
		"$waf_request_headers|cookies|args.<name|*> or $waf_var.<name>", raw)
}

/* --- строка условия -------------------------------------------------------- */

type Op string

const (
	OpIn    Op = "in"
	OpNotIn Op = "not_in"
	OpEq    Op = "eq"
	OpNe    Op = "ne"
	// Ссылка на другое условие: истинно / ложно.
	OpIs    Op = "is"
	OpIsNot Op = "is_not"
)

// Clause -- одна строка условия: значение, сравнение, набор либо текст; либо
// ссылка на другое условие (Ref), тогда операнда нет.
type Clause struct {
	Operand Operand
	Op      Op
	// Ref -- имя условия при is / is_not.
	Ref string
	// Dataset -- имя активного набора при in / not_in.
	Dataset string
	// Text -- образец при eq / ne, побайтно.
	Text string
	// Addr -- набор адресов (type: cidr): значение обязано быть адресом,
	// сравнение адресное, иначе промах.
	Addr bool
	// MD5 -- набор с hash=md5: в нём лежат md5 значений, значение хешируется
	// перед поиском.
	MD5 bool
}

// Negated -- строка ждёт, что не сойдётся ни одно значение (у ссылки -- что
// условие ложно).
func (c *Clause) Negated() bool {
	return c.Op == OpNotIn || c.Op == OpNe || c.Op == OpIsNot
}

// Condition -- именованный список строк по И либо, при Any, по ИЛИ.
type Condition struct {
	Name    string
	Any     bool
	Clauses []Clause
}

// condNameRe -- имя условия: как имя корзины у note, чтобы одно имя годилось
// и в YAML, и в аудите.
var condNameRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$`)

/* --- источник значений ----------------------------------------------------- */

// Pair -- имя и значение: заголовок, кука, аргумент.
type Pair struct {
	Name  string
	Value string
}

/*
 * Source отдаёт значения запроса. Объекты обменника достаются лениво -- по
 * первому условию, которому они нужны, -- и один раз на запрос. Второе
 * значение у объектов -- доступен ли объект вообще: маршрут его не снимает,
 * обменник не ответил, секции vars нет. Недоступный объект -- пустое
 * значение, и это видно в аудите.
 */
type Source interface {
	// Field -- поле сообщения по имени из Fields.
	Field(name string) string
	// Var -- поле секции vars; ok=false -- секции нет либо поля в ней нет.
	Var(name string) (value string, ok bool)
	Headers() (pairs []Pair, ok bool)
	Cookies() (pairs []Pair, ok bool)
	Args() (pairs []Pair, ok bool)
}

// Sets -- зеркало наборов. ready=false -- набора не видно: не готов либо не
// заказан; условие считает его пустым.
type Sets interface {
	Contains(name, value string) (ok, ready bool)
	ContainsAddr(name string, ip netip.Addr) (ok, ready bool)
}

// Values -- все значения операнда у этого запроса. Пустые строки не
// возвращаются: у модуля пустая пара тоже не спрашивается у набора.
// avail=false -- объект недоступен, и значений нет по этой причине.
func (o *Operand) Values(src Source) (values []string, avail bool) {
	switch o.Kind {
	case OperandField:
		return nonEmpty(src.Field(o.Name)), true

	case OperandVar:
		v, ok := src.Var(o.Name)

		return nonEmpty(v), ok

	case OperandHeader:
		pairs, ok := src.Headers()
		if !ok {
			return nil, false
		}

		for _, p := range pairs {
			if nginxHeaderName(p.Name) == o.Name {
				return nonEmpty(p.Value), true
			}
		}

		return nil, true

	case OperandCookie:
		return first(src.Cookies, o.Name)

	case OperandArg:
		return first(src.Args, o.Name)

	case OperandHeaders:
		pairs, ok := src.Headers()
		if !ok {
			return nil, false
		}

		for _, p := range pairs {
			if (o.All || strings.ToLower(p.Name) == o.Name) && p.Value != "" {
				values = append(values, p.Value)
			}
		}

		return values, true

	case OperandCookies:
		return all(src.Cookies, o)

	case OperandArgs:
		return all(src.Args, o)
	}

	return nil, true
}

func nonEmpty(v string) []string {
	if v == "" {
		return nil
	}

	return []string{v}
}

func first(get func() ([]Pair, bool), name string) ([]string, bool) {
	pairs, ok := get()
	if !ok {
		return nil, false
	}

	for _, p := range pairs {
		if p.Name == name {
			return nonEmpty(p.Value), true
		}
	}

	return nil, true
}

func all(get func() ([]Pair, bool), o *Operand) ([]string, bool) {
	pairs, ok := get()
	if !ok {
		return nil, false
	}

	var values []string

	for _, p := range pairs {
		if (o.All || p.Name == o.Name) && p.Value != "" {
			values = append(values, p.Value)
		}
	}

	return values, true
}

// nginxHeaderName -- имя заголовка так, как его видит $http_<имя>: строчные,
// дефис сведён к подчёркиванию.
func nginxHeaderName(name string) string {
	return strings.ReplaceAll(strings.ToLower(name), "-", "_")
}

/* --- вычисление ------------------------------------------------------------ */

// Note -- что помешало условию считаться по данным: объект недоступен либо
// набор не готов. Едет в аудит, чтобы «условие не сошлось» и «данных не
// было» читались по-разному.
type Note struct {
	Condition string `json:"condition"`
	Value     string `json:"value"`
	// Why: unavailable -- объект или секция недоступны, not_ready -- набор
	// ещё не приехал в зеркало, not_addr -- значение не читается адресом.
	Why string `json:"why"`
}

const (
	NoteUnavailable = "unavailable"
	NoteNotReady    = "not_ready"
	NoteNotAddr     = "not_addr"
)

// Evaluator считает условия одного запроса; каждое -- один раз, дальше по
// памяти. Профили ссылаются на условия по имени, и одно условие у нескольких
// правил считать дважды незачем.
type Evaluator struct {
	src   Source
	sets  Sets
	conds map[string]*Condition
	done  map[string]bool
	// busy -- условия, которые считаются прямо сейчас: ссылка на такое --
	// цикл. Parse его не пропускает, но на горячем пути зациклиться нельзя.
	busy  map[string]bool
	Notes []Note
}

func NewEvaluator(src Source, sets Sets, conds map[string]*Condition) *Evaluator {
	return &Evaluator{src: src, sets: sets, conds: conds, done: map[string]bool{}, busy: map[string]bool{}}
}

// Holds -- истинно ли условие с этим именем. Неизвестное имя и цикл -- ложь:
// Parse ни того ни другого не пропускает, а на горячем пути падать не из-за
// чего. По И считается до первой ложной строки, по ИЛИ -- до первой истинной.
func (e *Evaluator) Holds(name string) bool {
	if v, ok := e.done[name]; ok {
		return v
	}

	c := e.conds[name]
	if c == nil || e.busy[name] {
		return false
	}

	e.busy[name] = true

	v := !c.Any

	for i := range c.Clauses {
		hit := e.clause(c.Name, &c.Clauses[i])

		if c.Any && hit {
			v = true

			break
		}

		if !c.Any && !hit {
			v = false

			break
		}
	}

	delete(e.busy, name)
	e.done[name] = v

	return v
}

// Evaluated -- что посчитано на этом запросе: для аудита.
func (e *Evaluator) Evaluated() map[string]bool {
	return e.done
}

func (e *Evaluator) clause(cond string, c *Clause) bool {
	if c.Ref != "" {
		hit := e.Holds(c.Ref)

		if c.Negated() {
			return !hit
		}

		return hit
	}

	values, avail := c.Operand.Values(e.src)

	if !avail {
		e.Notes = append(e.Notes, Note{Condition: cond, Value: c.Operand.Raw, Why: NoteUnavailable})
	}

	hit := false

	for _, v := range values {
		if e.hit(cond, c, v) {
			hit = true

			break
		}
	}

	if c.Negated() {
		return !hit
	}

	return hit
}

func (e *Evaluator) hit(cond string, c *Clause, value string) bool {
	switch c.Op {
	case OpEq, OpNe:
		return value == c.Text

	case OpIn, OpNotIn:
		if e.sets == nil {
			e.note(cond, c, NoteNotReady)

			return false
		}

		if c.Addr {
			ip, err := netip.ParseAddr(strings.TrimSpace(value))
			if err != nil {
				e.note(cond, c, NoteNotAddr)

				return false
			}

			ok, ready := e.sets.ContainsAddr(c.Dataset, ip)
			if !ready {
				e.note(cond, c, NoteNotReady)
			}

			return ok
		}

		if c.MD5 {
			sum := md5.Sum([]byte(value))
			value = hex.EncodeToString(sum[:])
		}

		ok, ready := e.sets.Contains(c.Dataset, value)
		if !ready {
			e.note(cond, c, NoteNotReady)
		}

		return ok
	}

	return false
}

// note пишет причину один раз на строку: у селектора `*` значений десятки, а
// причина у них одна.
func (e *Evaluator) note(cond string, c *Clause, why string) {
	for _, n := range e.Notes {
		if n.Condition == cond && n.Value == c.Operand.Raw && n.Why == why {
			return
		}
	}

	e.Notes = append(e.Notes, Note{Condition: cond, Value: c.Operand.Raw, Why: why})
}

/* --- разбор YAML ----------------------------------------------------------- */

type fileClause struct {
	Value   string `yaml:"value"`
	Op      string `yaml:"op"`
	Dataset string `yaml:"dataset"`
	Text    string `yaml:"text"`
	// Cond -- имя другого условия при op is / is_not; value тогда пуст.
	Cond string `yaml:"cond"`
	// Тип и хеш набора печатает контроллер из определения набора; в файле
	// руками их пишут, если набор адресный либо с hash=md5.
	Type string `yaml:"type"`
	Hash string `yaml:"hash"`
}

type fileCondition struct {
	Name string `yaml:"name"`
	// Ровно один из двух: all -- строки по И, any -- по ИЛИ.
	All []fileClause `yaml:"all"`
	Any []fileClause `yaml:"any"`
}

func parseConditions(at string, rows []fileCondition) (map[string]*Condition, error) {
	out := map[string]*Condition{}
	order := make([]string, 0, len(rows))

	for i, fc := range rows {
		where := fmt.Sprintf("%s: conditions[%d]", at, i)

		name := strings.TrimSpace(fc.Name)
		if !condNameRe.MatchString(name) {
			return nil, fmt.Errorf("%s: name %q is not [A-Za-z0-9_][A-Za-z0-9._-]{0,63}", where, name)
		}

		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("%s: condition %q is declared twice", where, name)
		}

		if len(fc.All) > 0 && len(fc.Any) > 0 {
			return nil, fmt.Errorf("%s: condition %q has both all and any -- pick one", where, name)
		}

		clauses, key := fc.All, "all"

		if len(fc.Any) > 0 {
			clauses, key = fc.Any, "any"
		}

		if len(clauses) == 0 {
			return nil, fmt.Errorf("%s: condition %q has no clauses", where, name)
		}

		c := &Condition{Name: name, Any: key == "any"}

		for j, fcl := range clauses {
			cl, err := parseClause(fmt.Sprintf("%s.%s[%d]", where, key, j), fcl)
			if err != nil {
				return nil, err
			}

			if cl.Ref == name {
				return nil, fmt.Errorf("%s.%s[%d]: condition %q refers to itself", where, key, j, name)
			}

			c.Clauses = append(c.Clauses, cl)
		}

		out[name] = c
		order = append(order, name)
	}

	/*
	 * Ссылки -- только на объявленные условия, и без циклов: условие, которое
	 * ждёт само себя через соседей, не считается никогда, а на горячем пути
	 * вычислитель оборвал бы его молча ложью.
	 */
	for _, name := range order {
		for _, cl := range out[name].Clauses {
			if cl.Ref != "" {
				if _, ok := out[cl.Ref]; !ok {
					return nil, fmt.Errorf("%s: condition %q refers to undeclared condition %q", at, name, cl.Ref)
				}
			}
		}

		if cycle := findCycle(out, name, map[string]int{}); cycle != "" {
			return nil, fmt.Errorf("%s: conditions refer to each other in a cycle: %s", at, cycle)
		}
	}

	return out, nil
}

// findCycle -- обход по ссылкам; state 1 -- в пути, 2 -- пройдено.
func findCycle(conds map[string]*Condition, name string, state map[string]int) string {
	switch state[name] {
	case 1:
		return name
	case 2:
		return ""
	}

	state[name] = 1

	for _, cl := range conds[name].Clauses {
		if cl.Ref == "" {
			continue
		}

		if tail := findCycle(conds, cl.Ref, state); tail != "" {
			return name + " -> " + tail
		}
	}

	state[name] = 2

	return ""
}

func parseClause(at string, f fileClause) (Clause, error) {
	ref := strings.TrimSpace(f.Cond)
	op := Op(strings.TrimSpace(f.Op))

	// Ссылка: только имя и is / is_not, ни значения, ни набора, ни текста.
	if ref != "" || op == OpIs || op == OpIsNot {
		if ref == "" {
			return Clause{}, fmt.Errorf("%s: %s needs a cond", at, op)
		}

		if op != OpIs && op != OpIsNot {
			return Clause{}, fmt.Errorf("%s: cond takes op is or is_not, got %q", at, op)
		}

		if strings.TrimSpace(f.Value) != "" || strings.TrimSpace(f.Dataset) != "" || f.Text != "" ||
			strings.TrimSpace(f.Type) != "" || strings.TrimSpace(f.Hash) != "" {
			return Clause{}, fmt.Errorf("%s: a cond row takes no value, dataset, text, type or hash", at)
		}

		if !condNameRe.MatchString(ref) {
			return Clause{}, fmt.Errorf("%s: cond %q is not a condition name", at, ref)
		}

		return Clause{Ref: ref, Op: op}, nil
	}

	operand, err := ParseOperand(f.Value)
	if err != nil {
		return Clause{}, fmt.Errorf("%s: %w", at, err)
	}

	cl := Clause{Operand: operand, Op: op}

	switch cl.Op {
	case OpIn, OpNotIn:
		cl.Dataset = strings.TrimSpace(f.Dataset)

		if cl.Dataset == "" {
			return cl, fmt.Errorf("%s: %s needs a dataset", at, cl.Op)
		}

		if strings.TrimSpace(f.Text) != "" {
			return cl, fmt.Errorf("%s: text is only for eq and ne", at)
		}

		switch strings.TrimSpace(f.Type) {
		case "", "string":
		case "cidr":
			cl.Addr = true
		default:
			return cl, fmt.Errorf("%s: type must be string or cidr, got %q", at, f.Type)
		}

		switch strings.TrimSpace(f.Hash) {
		case "":
		case "md5":
			cl.MD5 = true
		default:
			return cl, fmt.Errorf("%s: hash must be md5, got %q", at, f.Hash)
		}

		if cl.Addr && cl.MD5 {
			return cl, fmt.Errorf("%s: an address dataset has no hash", at)
		}

		if cl.Addr && !addressable(operand) {
			return cl, fmt.Errorf("%s: an address dataset compares only with $remote_addr", at)
		}

	case OpEq, OpNe:
		// Текст обязателен: сравнение с пустотой -- это «значения нет», и для
		// него есть `not in` с любым набором.
		if f.Text == "" {
			return cl, fmt.Errorf("%s: %s needs a text", at, cl.Op)
		}

		cl.Text = f.Text

		if strings.TrimSpace(f.Dataset) != "" || strings.TrimSpace(f.Type) != "" || strings.TrimSpace(f.Hash) != "" {
			return cl, fmt.Errorf("%s: dataset, type and hash are only for in and not_in", at)
		}

	case "":
		return cl, fmt.Errorf("%s: op is empty (in, not_in, eq, ne; is, is_not with cond)", at)

	default:
		return cl, fmt.Errorf("%s: op must be in, not_in, eq or ne (is, is_not with cond), got %q", at, cl.Op)
	}

	return cl, nil
}

// addressable -- операнд, который бывает адресом: адрес клиента и заголовки,
// куда прокси кладут адрес (X-Forwarded-For, X-Real-IP), и поле xff.
func addressable(o Operand) bool {
	switch o.Kind {
	case OperandField:
		return o.Name == "remote_addr"
	case OperandHeader, OperandHeaders, OperandVar:
		return true
	}

	return false
}
