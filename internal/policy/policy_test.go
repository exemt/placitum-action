package policy

import (
	"strings"
	"testing"
	"time"
)

func parseOne(t *testing.T, yaml string) *Profile {
	t.Helper()

	p, err := Parse("default", []byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	return p
}

func TestCollectAccumulates(t *testing.T) {
	p := parseOne(t, `
mode: enforce
rules:
  - name: calm-modsec
    match: { path_prefix: "/healthz" }
    actions:
      - { to: modsec, do: threshold, delta: 30, code: ROUTE_TRUSTED }
  - name: static-fetch
    match: { static: true, methods: [GET] }
    actions:
      - { to: captcha, do: note, apply: ip, code: STATIC_FETCH, value: 10 }
`)

	// Оба правила накрывают запрос: действия складываются в порядке строк.
	actions, _, names := p.Collect(nil, "GET", "/healthz/app.js")
	if len(actions) != 2 || len(names) != 2 {
		t.Fatalf("actions = %+v, names = %v", actions, names)
	}

	if actions[0].Do != "threshold" || actions[0].To != "modsec" {
		t.Errorf("actions[0] = %+v, want the threshold to modsec first", actions[0])
	}

	if actions[1].Code != "STATIC_FETCH" || *actions[1].Value != 10 {
		t.Errorf("actions[1] = %+v", actions[1])
	}

	// POST срезает второе правило, путь без префикса -- первое.
	if actions, _, _ := p.Collect(nil, "POST", "/healthz/app.js"); len(actions) != 1 {
		t.Errorf("POST: actions = %+v, want only the prefix rule", actions)
	}

	if actions, _, _ := p.Collect(nil, "GET", "/api/users"); len(actions) != 0 {
		t.Errorf("plain path: actions = %+v, want none", actions)
	}
}

func TestStaticSuffixes(t *testing.T) {
	p := parseOne(t, `
rules:
  - name: static
    match: { static: true }
    actions: [ { to: captcha, do: note, apply: ip, code: STATIC_FETCH } ]
`)

	for uri, want := range map[string]bool{
		"/assets/APP.CSS": true, // регистр пути не значим
		"/img/logo.svg":   true,
		"/fonts/a.woff2":  true,
		"/index.html":     false, // страница -- не подгрузка ресурса
		"/api/data.php":   false,
		"/assets/style":   false,
	} {
		if actions, _, _ := p.Collect(nil, "GET", uri); (len(actions) > 0) != want {
			t.Errorf("%s: matched = %v, want %v", uri, len(actions) > 0, want)
		}
	}
}

func TestAxisDefaultsFromDictionary(t *testing.T) {
	p := parseOne(t, `
rules:
  - name: calm
    actions: [ { to: modsec, do: threshold, delta: -50 } ]
`)

	// Ось не написана, у threshold она одна -- проставляется словарём: действие
	// без оси модуль отбраковал бы вместе со всем ответом.
	if got := p.Rules[0].Actions[0].Apply; got != "request" {
		t.Fatalf("apply = %q, want request", got)
	}
}

func TestEmptyMatchMatchesEverything(t *testing.T) {
	p := parseOne(t, `
rules:
  - name: always
    actions: [ { to: modsec, do: skip, code: ROUTE_STATIC } ]
`)

	if actions, _, _ := p.Collect(nil, "PATCH", "/anything"); len(actions) != 1 {
		t.Fatalf("empty match must match everything, got %+v", actions)
	}
}

func TestValidation(t *testing.T) {
	for name, bad := range map[string]string{
		"unknown verb": `
rules: [ { name: r, actions: [ { to: x, do: block } ] } ]`,
		"axis not for verb": `
rules: [ { name: r, actions: [ { to: x, do: challenge, apply: asn } ] } ]`,
		"no addressee": `
rules: [ { name: r, actions: [ { do: skip } ] } ]`,
		"delta out of range": `
rules: [ { name: r, actions: [ { to: x, do: threshold, delta: 5000 } ] } ]`,
		"delta on note": `
rules: [ { name: r, actions: [ { to: x, do: note, apply: ip, delta: 5 } ] } ]`,
		"value on skip": `
rules: [ { name: r, actions: [ { to: x, do: skip, value: 5 } ] } ]`,
		"lowercase code": `
rules: [ { name: r, actions: [ { to: x, do: skip, code: route_trusted } ] } ]`,
		"rule without actions": `
rules: [ { name: r } ]`,
		"score with addressee": `
rules: [ { name: r, actions: [ { to: x, do: score, value: 30 } ] } ]`,
		"score without value": `
rules: [ { name: r, actions: [ { do: score } ] } ]`,
		"score over a hundred": `
rules: [ { name: r, actions: [ { do: score, value: 101 } ] } ]`,
		// Глаголы записи: адресата нет, сторона обязательна, срок и предел --
		// только у archive с set on.
		"audit with addressee": `
rules: [ { name: r, actions: [ { to: x, do: audit, set: on } ] } ]`,
		"audit without set": `
rules: [ { name: r, actions: [ { do: audit } ] } ]`,
		"audit with ttl": `
rules: [ { name: r, actions: [ { do: audit, set: on, ttl: 30d } ] } ]`,
		"archive off with objects": `
rules: [ { name: r, actions: [ { do: archive, apply: request, set: off, body: { limit: 10 } } ] } ]`,
		"archive bad object set": `
rules: [ { name: r, actions: [ { do: archive, apply: request, set: on, body: { set: maybe } } ] } ]`,
		"args on the response record": `
rules: [ { name: r, actions: [ { do: audit, apply: response, set: on, args: { limit: 10 } } ] } ]`,
		"archive bad ttl": `
rules: [ { name: r, actions: [ { do: archive, set: on, ttl: soon } ] } ]`,
		// Исход просьбы: два слова, каждое не дважды, и только у archive
		// с set on -- как на проводе.
		"archive bad when": `
rules: [ { name: r, actions: [ { do: archive, set: on, when: [redirect] } ] } ]`,
		"archive when twice": `
rules: [ { name: r, actions: [ { do: archive, set: on, when: [deny, deny] } ] } ]`,
		"audit with when": `
rules: [ { name: r, actions: [ { do: audit, set: on, when: [deny] } ] } ]`,
		"archive off with when": `
rules: [ { name: r, actions: [ { do: archive, set: off, when: [deny] } ] } ]`,
		"when on skip": `
rules: [ { name: r, actions: [ { to: x, do: skip, when: [deny] } ] } ]`,
		"set on skip": `
rules: [ { name: r, actions: [ { to: x, do: skip, set: on } ] } ]`,
		"bad source": `
rules: [ { name: r, actions: [ { do: archive, apply: request, set: on, body: { source: elsewhere } } ] } ]`,
		"bad mode": `
mode: observe`,
	} {
		if _, err := Parse("default", []byte(bad)); err == nil {
			t.Errorf("%s: profile loaded, want an error", name)
		}
	}

	// Глаголы записи грузятся без адресата, а срок архива уезжает секундами.
	audited, err := Parse("default", []byte(`
rules: [ { name: r, actions: [
  { do: audit, set: on, code: ROUTE_WATCH },
  { do: archive, apply: request, set: on, headers: { source: original }, body: { limit: 65536, source: original }, ttl: 30d, when: [deny, allow] },
  { do: archive, apply: response, set: on, body: { source: store }, ttl: 1h } ] } ]`))
	if err != nil {
		t.Fatalf("audit verbs must load: %v", err)
	}

	// Без apply глагол записи -- про запись запроса; response -- про запись ответа.
	if acts, _, _ := audited.Collect(nil, "GET", "/x"); len(acts) != 3 || acts[1].TTL == nil ||
		*acts[1].TTL != 30*24*3600 || acts[1].Body == nil || acts[1].Body.Limit != 65536 ||
		acts[1].Body.Source != "original" || acts[1].Headers == nil || acts[1].Args != nil ||
		acts[0].To != "" || acts[0].Set != "on" || acts[0].Apply != "request" ||
		acts[2].Apply != "response" || acts[2].TTL == nil || *acts[2].TTL != 3600 ||
		// Исход уезжает в каноническом порядке, как бы он ни стоял в файле;
		// не названный -- пустой: "любой исход" пишется отсутствием ключа.
		len(acts[1].When) != 2 || acts[1].When[0] != "allow" || acts[1].When[1] != "deny" ||
		len(acts[2].When) != 0 {
		t.Fatalf("audit verbs on the wire: %+v", acts)
	}

	// threshold со знаком минус -- скидка, и она законна: -100 -- измерение
	// получателя в ноль, ниже процентов не бывает.
	if _, err := Parse("default", []byte(`
rules: [ { name: r, actions: [ { to: x, do: threshold, delta: -100 } ] } ]`)); err != nil {
		t.Errorf("negative delta must load: %v", err)
	}

	// А -1000 -- уже не проценты: прежний диапазон формы провода остался
	// модулю, отправитель собирает только осмысленные коэффициенты.
	if _, err := Parse("default", []byte(`
rules: [ { name: r, actions: [ { to: x, do: threshold, delta: -1000 } ] } ]`)); err == nil {
		t.Error("delta below -100 percent loaded, want an error")
	}

	// Имя правила не обязательно: панель их не спрашивает, загрузчик
	// подставляет порядковое -- оно живёт только в логе и аудите.
	p, err := Parse("default", []byte(`
rules: [ { actions: [ { to: x, do: skip } ] } ]`))
	if err != nil {
		t.Fatalf("nameless rule must load: %v", err)
	}

	if p.Rules[0].Name != "rule-1" {
		t.Errorf("nameless rule got %q, want rule-1", p.Rules[0].Name)
	}
}

func TestScoreAskHasNoAddressee(t *testing.T) {
	p := parseOne(t, `
rules:
  - name: search-cost
    match: { path_prefix: "/search" }
    actions:
      - { do: score, value: -30, code: SEARCH_CHEAP }
`)

	// Очки едут просьбой без адресата: исполняет модуль, ось -- этот запрос.
	actions, _, _ := p.Collect(nil, "GET", "/search?q=x")
	if len(actions) != 1 || actions[0].Do != "score" || actions[0].To != "" ||
		actions[0].Apply != "request" || actions[0].Value == nil || *actions[0].Value != -30 {
		t.Fatalf("score ask = %+v", actions)
	}
}

func TestParseErrorNamesTheRule(t *testing.T) {
	_, err := Parse("default", []byte(`
rules:
  - name: fine
    actions: [ { to: x, do: skip } ]
  - name: broken
    actions: [ { to: x, do: dance } ]
`))
	if err == nil || !strings.Contains(err.Error(), "rules[1]") {
		t.Fatalf("error must point at the rule: %v", err)
	}
}

/*
 * Запись в набор -- не просьба: строка с list уезжает в Writes, а не на
 * провод, срок обязателен, охват -- те же четыре слова, что у остальных
 * отправителей, повод без своего -- ACTION_LIST.
 */
func TestListWrites(t *testing.T) {
	p := parseOne(t, `
conditions:
  - name: bad
    all: [ { value: $arg_bot, op: eq, text: "1" } ]
rules:
  - if: bad
    actions:
      - { list: ban-ip, ttl: 10m }
      - { list: ban-net, write: net_all, ttl: 1h, code: E2E_BAN }
      - { to: captcha, do: challenge }
`)

	r := p.Rules[0]

	if len(r.Actions) != 1 || len(r.Writes) != 2 {
		t.Fatalf("asks %+v, writes %+v", r.Actions, r.Writes)
	}

	if w := r.Writes[0]; w.List != "ban-ip" || w.Subject != WriteAddr || w.TTL != 10*time.Minute ||
		w.Reason != DefaultWriteReason {
		t.Fatalf("addr write = %+v", w)
	}

	if w := r.Writes[1]; w.Subject != WriteNetAll || w.TTL != time.Hour || w.Reason != "E2E_BAN" {
		t.Fatalf("net_all write = %+v", w)
	}

	for name, bad := range map[string]string{
		"write without ttl":  `rules: [ { actions: [ { list: x } ] } ]`,
		"unknown scope":      `rules: [ { actions: [ { list: x, write: country, ttl: 1h } ] } ]`,
		"list with a verb":   `rules: [ { actions: [ { list: x, do: skip, to: modsec, ttl: 1h } ] } ]`,
		"list with value":    `rules: [ { actions: [ { list: x, value: 5, ttl: 1h } ] } ]`,
		"bad list name":      `rules: [ { actions: [ { list: "-x", ttl: 1h } ] } ]`,
		"lowercase code":     `rules: [ { actions: [ { list: x, ttl: 1h, code: ban } ] } ]`,
		"write on an ask":    `rules: [ { actions: [ { to: modsec, do: skip, write: net } ] } ]`,
		"subsecond ttl":      `rules: [ { actions: [ { list: x, ttl: 500ms } ] } ]`,
		"archive-only field": `rules: [ { actions: [ { list: x, ttl: 1h, when: [deny] } ] } ]`,
	} {
		if _, err := Parse("default", []byte(bad)); err == nil {
			t.Errorf("%s: profile loaded, want an error", name)
		}
	}
}

// Фаза вызова адресата у управляющего глагола едет на провод как есть; без
// поля режим получают все вызовы имени. Прочим глаголам поля не бывает.
func TestPhaseAskTravels(t *testing.T) {
	p := parseOne(t, `
rules:
  - name: quiet-response
    match: { path_prefix: "/api" }
    actions:
      - { to: json, do: off, apply: request, phase: response }
      - { to: modsec, do: passive, apply: request }
`)

	actions, _, _ := p.Collect(nil, "GET", "/api/x")
	if len(actions) != 2 || actions[0].Phase != "response" || actions[1].Phase != "" {
		t.Fatalf("phase asks = %+v", actions)
	}

	for name, body := range map[string]string{
		"phase on skip":  "rules:\n  - name: r\n    actions: [ { to: x, do: skip, phase: response } ]\n",
		"phase on score": "rules:\n  - name: r\n    actions: [ { do: score, value: 10, phase: request } ]\n",
		"unknown phase":  "rules:\n  - name: r\n    actions: [ { to: x, do: off, apply: request, phase: later } ]\n",
	} {
		if _, err := Parse("default", []byte(body)); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}
