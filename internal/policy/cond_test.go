package policy

import (
	"crypto/md5"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"

	"github.com/exemt/placitum-action/internal/protocol"
)

/* --- заглушки источника и зеркала ------------------------------------------- */

type fakeSource struct {
	fields  map[string]string
	vars    map[string]string
	headers []Pair
	cookies []Pair
	args    []Pair
	// noHeaders / noArgs -- объект недоступен, как у маршрута без снимка.
	noHeaders bool
	noArgs    bool
}

func (f *fakeSource) Field(name string) string { return f.fields[name] }

func (f *fakeSource) Var(name string) (string, bool) {
	if f.vars == nil {
		return "", false
	}

	v, ok := f.vars[name]

	return v, ok
}

func (f *fakeSource) Headers() ([]Pair, bool) { return f.headers, !f.noHeaders }
func (f *fakeSource) Cookies() ([]Pair, bool) { return f.cookies, !f.noHeaders }
func (f *fakeSource) Args() ([]Pair, bool)    { return f.args, !f.noArgs }

type fakeSets struct {
	sets     map[string][]string
	notReady map[string]bool
}

func (f *fakeSets) Contains(name, value string) (bool, bool) {
	if f.notReady[name] {
		return false, false
	}

	values, ok := f.sets[name]
	if !ok {
		return false, false
	}

	for _, v := range values {
		if v == value {
			return true, true
		}
	}

	return false, true
}

func (f *fakeSets) ContainsAddr(name string, ip netip.Addr) (bool, bool) {
	values, ok := f.sets[name]
	if !ok {
		return false, false
	}

	for _, v := range values {
		if p, err := netip.ParsePrefix(v); err == nil && p.Contains(ip) {
			return true, true
		}

		if a, err := netip.ParseAddr(v); err == nil && a == ip {
			return true, true
		}
	}

	return false, true
}

/* --- операнд ----------------------------------------------------------------- */

func TestParseOperand(t *testing.T) {
	for raw, want := range map[string]Operand{
		"$uri":                         {Kind: OperandField, Name: "uri"},
		"$remote_addr":                 {Kind: OperandField, Name: "remote_addr"},
		"$http_X_Api_Key":              {Kind: OperandHeader, Name: "x_api_key"},
		"$http_user_agent":             {Kind: OperandHeader, Name: "user_agent"},
		"$cookie_sid":                  {Kind: OperandCookie, Name: "sid"},
		"$arg_token":                   {Kind: OperandArg, Name: "token"},
		"$waf_request_headers.X-Ja3":   {Kind: OperandHeaders, Name: "x-ja3"},
		"$waf_request_cookies.sess.id": {Kind: OperandCookies, Name: "sess.id"},
		"$waf_request_args.*":          {Kind: OperandArgs, All: true},
		"$waf_var.ja3":                 {Kind: OperandVar, Name: "ja3"},
	} {
		got, err := ParseOperand(raw)
		if err != nil {
			t.Errorf("%s: %v", raw, err)

			continue
		}

		if got.Kind != want.Kind || got.Name != want.Name || got.All != want.All {
			t.Errorf("%s = %+v, want %+v", raw, got, want)
		}
	}

	for _, raw := range []string{
		"", "uri", "$", "$nope", "$http_", "$http_x-api-key", "$waf_request_args.",
		"$waf_var.*", "$waf_request_body.x", "$binary_remote_addr",
	} {
		if _, err := ParseOperand(raw); err == nil {
			t.Errorf("%q parsed, want an error", raw)
		}
	}
}

/* --- разбор профиля ---------------------------------------------------------- */

func TestParseConditions(t *testing.T) {
	p := parseOne(t, `
conditions:
  - name: trusted_key
    all:
      - { value: $http_x_api_key, op: in, dataset: api_keys }
      - { value: $request_method, op: eq, text: POST }
  - name: office
    all:
      - { value: $remote_addr, op: in, dataset: office_nets, type: cidr }
rules:
  - actions: [ { to: modsec, do: threshold, delta: -50, code: TRUSTED } ]
  - if: trusted_key
    actions: [ { to: modsec, do: skip, code: TRUSTED } ]
  - unless: office
    actions: [ { do: score, value: 10 } ]
`)

	if len(p.Conditions) != 2 || len(p.Conditions["trusted_key"].Clauses) != 2 {
		t.Fatalf("conditions = %+v", p.Conditions)
	}

	if !p.Conditions["office"].Clauses[0].Addr {
		t.Errorf("office: type cidr not read")
	}

	if got := p.Datasets(); strings.Join(got, ",") != "office_nets,api_keys" {
		t.Errorf("datasets = %v", got)
	}

	if p.Rules[0].Cond != "" || p.Rules[1].Cond != "trusted_key" || p.Rules[1].Negate {
		t.Errorf("rules[0..1] = %+v", p.Rules[:2])
	}

	if p.Rules[2].Cond != "office" || !p.Rules[2].Negate {
		t.Errorf("rules[2] = %+v", p.Rules[2])
	}
}

func TestParseConditionsRejects(t *testing.T) {
	for name, yaml := range map[string]string{
		"undeclared": `
rules:
  - if: nope
    actions: [ { to: modsec, do: skip } ]
`,
		"both if and unless": `
conditions: [ { name: a, all: [ { value: $uri, op: eq, text: /x } ] } ]
rules:
  - if: a
    unless: a
    actions: [ { to: modsec, do: skip } ]
`,
		"duplicate name": `
conditions:
  - { name: a, all: [ { value: $uri, op: eq, text: /x } ] }
  - { name: a, all: [ { value: $uri, op: eq, text: /y } ] }
rules: []
`,
		"empty clauses": `
conditions: [ { name: a, all: [] } ]
rules: []
`,
		"in without dataset": `
conditions: [ { name: a, all: [ { value: $uri, op: in } ] } ]
rules: []
`,
		"eq without text": `
conditions: [ { name: a, all: [ { value: $uri, op: eq } ] } ]
rules: []
`,
		"eq with dataset": `
conditions: [ { name: a, all: [ { value: $uri, op: eq, text: x, dataset: d } ] } ]
rules: []
`,
		"bad op": `
conditions: [ { name: a, all: [ { value: $uri, op: like, text: x } ] } ]
rules: []
`,
		"bad value": `
conditions: [ { name: a, all: [ { value: $nope, op: eq, text: x } ] } ]
rules: []
`,
		"cidr with a path": `
conditions: [ { name: a, all: [ { value: $uri, op: in, dataset: d, type: cidr } ] } ]
rules: []
`,
		"bad name": `
conditions: [ { name: "a b", all: [ { value: $uri, op: eq, text: x } ] } ]
rules: []
`,
	} {
		if _, err := Parse("p", []byte(yaml)); err == nil {
			t.Errorf("%s: parsed, want an error", name)
		}
	}
}

/* --- вычисление -------------------------------------------------------------- */

func evalProfile(t *testing.T, yaml string, src Source, sets Sets) (*Profile, *Evaluator) {
	t.Helper()

	p := parseOne(t, yaml)

	return p, NewEvaluator(src, sets, p.Conditions)
}

func TestCollectByCondition(t *testing.T) {
	yaml := `
conditions:
  - name: trusted_key
    all:
      - { value: $http_x_api_key, op: in, dataset: api_keys }
rules:
  - actions: [ { to: modsec, do: threshold, delta: 10, code: ALWAYS } ]
  - if: trusted_key
    actions: [ { to: modsec, do: skip, code: WHEN } ]
  - unless: trusted_key
    actions: [ { do: score, value: 10, code: UNLESS } ]
`
	sets := &fakeSets{sets: map[string][]string{"api_keys": {"k1"}}}

	// Ключ в наборе: «всегда» и «если».
	p, ev := evalProfile(t, yaml, &fakeSource{headers: []Pair{{"X-Api-Key", "k1"}}}, sets)

	actions, _, names := p.Collect(ev, "GET", "/")
	if codes(actions) != "ALWAYS,WHEN" {
		t.Errorf("in set: %s (rules %v)", codes(actions), names)
	}

	if v, ok := ev.Evaluated()["trusted_key"]; !ok || !v {
		t.Errorf("evaluated = %v", ev.Evaluated())
	}

	// Ключа нет: «всегда» и «если не».
	p, ev = evalProfile(t, yaml, &fakeSource{headers: []Pair{{"X-Api-Key", "other"}}}, sets)

	if actions, _, _ = p.Collect(ev, "GET", "/"); codes(actions) != "ALWAYS,UNLESS" {
		t.Errorf("not in set: %s", codes(actions))
	}

	// Заголовка нет вовсе -- то же, что не в наборе.
	p, ev = evalProfile(t, yaml, &fakeSource{}, sets)

	if actions, _, _ = p.Collect(ev, "GET", "/"); codes(actions) != "ALWAYS,UNLESS" {
		t.Errorf("no header: %s", codes(actions))
	}

	// Объекта не снимают: то же, но с пометкой в заметках.
	p, ev = evalProfile(t, yaml, &fakeSource{noHeaders: true}, sets)

	if actions, _, _ = p.Collect(ev, "GET", "/"); codes(actions) != "ALWAYS,UNLESS" {
		t.Errorf("headers unavailable: %s", codes(actions))
	}

	if len(ev.Notes) != 1 || ev.Notes[0].Why != NoteUnavailable {
		t.Errorf("notes = %+v", ev.Notes)
	}

	// Набор не готов -- пустой, с пометкой.
	p, ev = evalProfile(t, yaml, &fakeSource{headers: []Pair{{"X-Api-Key", "k1"}}},
		&fakeSets{sets: sets.sets, notReady: map[string]bool{"api_keys": true}})

	if actions, _, _ = p.Collect(ev, "GET", "/"); codes(actions) != "ALWAYS,UNLESS" {
		t.Errorf("set not ready: %s", codes(actions))
	}

	if len(ev.Notes) != 1 || ev.Notes[0].Why != NoteNotReady {
		t.Errorf("notes = %+v", ev.Notes)
	}
}

func TestClauseSemantics(t *testing.T) {
	sets := &fakeSets{sets: map[string][]string{
		"bad":    {"evil"},
		"nets":   {"10.0.0.0/8", "192.168.1.7"},
		"hashed": {md5hex("secret")},
	}}

	src := &fakeSource{
		fields:  map[string]string{"uri": "/api/x", "request_method": "POST", "remote_addr": "10.1.2.3"},
		vars:    map[string]string{"ja3": "abc"},
		headers: []Pair{{"User-Agent", "curl"}, {"X-Ja3", "abc"}},
		cookies: []Pair{{"sid", "ok"}, {"sid", "evil"}},
		args:    []Pair{{"q", "1"}, {"debug", "evil"}, {"token", "secret"}},
	}

	for name, tc := range map[string]struct {
		clause string
		want   bool
	}{
		"eq field":             {`{ value: $request_method, op: eq, text: POST }`, true},
		"ne field":             {`{ value: $request_method, op: ne, text: GET }`, true},
		"eq header nginx name": {`{ value: $http_user_agent, op: eq, text: curl }`, true},
		"header selector":      {`{ value: $waf_request_headers.x-ja3, op: eq, text: abc }`, true},
		"var":                  {`{ value: $waf_var.ja3, op: eq, text: abc }`, true},
		"var missing":          {`{ value: $waf_var.nope, op: ne, text: abc }`, true},
		"cookie first only":    {`{ value: $cookie_sid, op: in, dataset: bad }`, false},
		"cookies all values":   {`{ value: $waf_request_cookies.sid, op: in, dataset: bad }`, true},
		"cookies all not in":   {`{ value: $waf_request_cookies.sid, op: not_in, dataset: bad }`, false},
		"args star":            {`{ value: $waf_request_args.*, op: in, dataset: bad }`, true},
		"arg first":            {`{ value: $arg_q, op: eq, text: "1" }`, true},
		"arg missing not in":   {`{ value: $arg_nope, op: not_in, dataset: bad }`, true},
		"arg missing in":       {`{ value: $arg_nope, op: in, dataset: bad }`, false},
		"addr in prefix":       {`{ value: $remote_addr, op: in, dataset: nets, type: cidr }`, true},
		"addr not in":          {`{ value: $remote_addr, op: not_in, dataset: nets, type: cidr }`, false},
		"md5 set":              {`{ value: $arg_token, op: in, dataset: hashed, hash: md5 }`, true},
		"md5 set raw miss":     {`{ value: $arg_token, op: in, dataset: hashed }`, false},
		"unknown set is empty": {`{ value: $uri, op: not_in, dataset: nope }`, true},
	} {
		p, ev := evalProfile(t, `
conditions: [ { name: c, all: [ `+tc.clause+` ] } ]
rules: [ { if: c, actions: [ { to: modsec, do: skip } ] } ]
`, src, sets)

		if got := ev.Holds("c"); got != tc.want {
			t.Errorf("%s: %v, want %v (profile %s)", name, got, tc.want, p.Name)
		}
	}
}

func TestConditionIsAnd(t *testing.T) {
	src := &fakeSource{fields: map[string]string{"uri": "/x", "request_method": "GET"}}

	_, ev := evalProfile(t, `
conditions:
  - name: both
    all:
      - { value: $uri, op: eq, text: /x }
      - { value: $request_method, op: eq, text: POST }
rules: [ { if: both, actions: [ { to: modsec, do: skip } ] } ]
`, src, &fakeSets{})

	if ev.Holds("both") {
		t.Errorf("AND: second clause is false, condition must be false")
	}

	// Память: второй вызов -- по записи, без пересчёта.
	if ev.Holds("both") || len(ev.Evaluated()) != 1 {
		t.Errorf("memo: %v", ev.Evaluated())
	}
}

func codes(actions []protocol.Action) string {
	out := make([]string, 0, len(actions))

	for _, a := range actions {
		out = append(out, a.Code)
	}

	return strings.Join(out, ",")
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))

	return hex.EncodeToString(sum[:])
}

/* --- И / ИЛИ и ссылки --------------------------------------------------------- */

func TestAnyAllAndRefs(t *testing.T) {
	sets := &fakeSets{sets: map[string][]string{"keys": {"k1"}}}
	yaml := `
conditions:
  - name: trusted
    any:
      - { value: $http_x_api_key, op: in, dataset: keys }
      - { value: $arg_key, op: eq, text: k1 }
  - name: debug
    all:
      - { value: $arg_debug, op: eq, text: "1" }
  - name: risky
    any:
      - { cond: trusted, op: is_not }
      - { cond: debug, op: is }
rules:
  - if: risky
    actions: [ { do: score, value: 100, code: RISKY } ]
`

	for name, tc := range map[string]struct {
		src  *fakeSource
		want string
	}{
		"nothing":            {&fakeSource{}, "RISKY"},
		"header branch":      {&fakeSource{headers: []Pair{{"X-Api-Key", "k1"}}}, ""},
		"arg branch":         {&fakeSource{args: []Pair{{"key", "k1"}}}, ""},
		"trusted but debug":  {&fakeSource{args: []Pair{{"key", "k1"}, {"debug", "1"}}}, "RISKY"},
		"untrusted no debug": {&fakeSource{args: []Pair{{"key", "nope"}}}, "RISKY"},
	} {
		p, ev := evalProfile(t, yaml, tc.src, sets)

		if actions, _, _ := p.Collect(ev, "GET", "/"); codes(actions) != tc.want {
			t.Errorf("%s: %q, want %q (evaluated %v)", name, codes(actions), tc.want, ev.Evaluated())
		}
	}

	// ИЛИ считается до первой истинной строки: debug не трогается, когда
	// доверие уже снято, а память хранит только посчитанное.
	_, ev := evalProfile(t, yaml, &fakeSource{}, sets)
	ev.Holds("risky")

	if _, ok := ev.Evaluated()["debug"]; ok {
		t.Errorf("any: debug evaluated after the first true row: %v", ev.Evaluated())
	}
}

func TestRefsRejected(t *testing.T) {
	for name, yaml := range map[string]string{
		"undeclared": `
conditions: [ { name: a, all: [ { cond: nope, op: is } ] } ]
rules: []
`,
		"self": `
conditions: [ { name: a, any: [ { cond: a, op: is } ] } ]
rules: []
`,
		"cycle": `
conditions:
  - { name: a, all: [ { cond: b, op: is } ] }
  - { name: b, all: [ { cond: c, op: is_not } ] }
  - { name: c, any: [ { cond: a, op: is } ] }
rules: []
`,
		"ref with value": `
conditions:
  - { name: a, all: [ { value: $uri, op: eq, text: x } ] }
  - { name: b, all: [ { cond: a, op: is, value: $uri } ] }
rules: []
`,
		"ref with wrong op": `
conditions:
  - { name: a, all: [ { value: $uri, op: eq, text: x } ] }
  - { name: b, all: [ { cond: a, op: eq } ] }
rules: []
`,
		"is without cond": `
conditions: [ { name: a, all: [ { value: $uri, op: is } ] } ]
rules: []
`,
		"all and any": `
conditions: [ { name: a, all: [ { value: $uri, op: eq, text: x } ], any: [ { value: $uri, op: eq, text: y } ] } ]
rules: []
`,
	} {
		if _, err := Parse("p", []byte(yaml)); err == nil {
			t.Errorf("%s: parsed, want an error", name)
		}
	}

	// Ссылка вперёд -- законна: порядок объявления не значим.
	parseOne(t, `
conditions:
  - { name: a, all: [ { cond: b, op: is_not } ] }
  - { name: b, all: [ { value: $uri, op: eq, text: x } ] }
rules: [ { if: a, actions: [ { to: modsec, do: skip } ] } ]
`)
}
