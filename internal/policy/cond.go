package policy

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

type OperandKind int

const (
	OperandField OperandKind = iota
	OperandHeader
	OperandCookie
	OperandArg
	OperandHeaders
	OperandCookies
	OperandArgs
	OperandVar
)

type Operand struct {
	Raw  string
	Kind OperandKind
	Name string
	All  bool
}

var Fields = []string{
	"uri", "request_uri", "host", "request_method", "scheme", "remote_addr",
}

const (
	selHeaders = "$waf_request_headers."
	selCookies = "$waf_request_cookies."
	selArgs    = "$waf_request_args."
	selVar     = "$waf_var."
)

var varNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

var nginxNameRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,128}$`)

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

type Op string

const (
	OpIn    Op = "in"
	OpNotIn Op = "not_in"
	OpEq    Op = "eq"
	OpNe    Op = "ne"
	OpIs    Op = "is"
	OpIsNot Op = "is_not"
)

type Clause struct {
	Operand Operand
	Op      Op
	Ref     string
	Dataset string
	Text    string
	Addr    bool
	MD5     bool
}

func (c *Clause) Negated() bool {
	return c.Op == OpNotIn || c.Op == OpNe || c.Op == OpIsNot
}

type Condition struct {
	Name    string
	Any     bool
	Clauses []Clause
}

var condNameRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$`)

type Pair struct {
	Name  string
	Value string
}

type Source interface {
	Field(name string) string
	Var(name string) (value string, ok bool)
	Headers() (pairs []Pair, ok bool)
	Cookies() (pairs []Pair, ok bool)
	Args() (pairs []Pair, ok bool)
}

type Sets interface {
	Contains(name, value string) (ok, ready bool)
	ContainsAddr(name string, ip netip.Addr) (ok, ready bool)
}

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

func nginxHeaderName(name string) string {
	return strings.ReplaceAll(strings.ToLower(name), "-", "_")
}

type Note struct {
	Condition string `json:"condition"`
	Value     string `json:"value"`
	Why       string `json:"why"`
}

const (
	NoteUnavailable = "unavailable"
	NoteNotReady    = "not_ready"
	NoteNotAddr     = "not_addr"
)

type Evaluator struct {
	src   Source
	sets  Sets
	conds map[string]*Condition
	done  map[string]bool
	busy  map[string]bool
	Notes []Note
}

func NewEvaluator(src Source, sets Sets, conds map[string]*Condition) *Evaluator {
	return &Evaluator{src: src, sets: sets, conds: conds, done: map[string]bool{}, busy: map[string]bool{}}
}

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

func (e *Evaluator) note(cond string, c *Clause, why string) {
	for _, n := range e.Notes {
		if n.Condition == cond && n.Value == c.Operand.Raw && n.Why == why {
			return
		}
	}

	e.Notes = append(e.Notes, Note{Condition: cond, Value: c.Operand.Raw, Why: why})
}

type fileClause struct {
	Value   string `yaml:"value"`
	Op      string `yaml:"op"`
	Dataset string `yaml:"dataset"`
	Text    string `yaml:"text"`
	Cond    string `yaml:"cond"`
	Type    string `yaml:"type"`
	Hash    string `yaml:"hash"`
}

type fileCondition struct {
	Name string       `yaml:"name"`
	All  []fileClause `yaml:"all"`
	Any  []fileClause `yaml:"any"`
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

func addressable(o Operand) bool {
	switch o.Kind {
	case OperandField:
		return o.Name == "remote_addr"
	case OperandHeader, OperandHeaders, OperandVar:
		return true
	}

	return false
}
