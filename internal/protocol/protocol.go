package protocol

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

const Version = 2

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

type Header [2]string

func (h Header) Name() string  { return h[0] }
func (h Header) Value() string { return h[1] }

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

type Enc struct {
	Alg   string `json:"alg"`
	KID   string `json:"kid"`
	Nonce string `json:"nonce"`
}

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

func (l *Locator) Placed() bool {
	return l != nil && l.Unavailable == "" && l.Driver != "" && l.Key != ""
}

type Store struct {
	Headers *Locator `json:"headers"`
	Args    *Locator `json:"args"`
	Body    *Locator `json:"body"`
}

type Route struct {
	ServerName string `json:"server_name"`
	Location   string `json:"location"`
	Profile    string `json:"profile"`
}

type ScoreState struct {
	Total  int `json:"total"`
	DenyAt int `json:"deny_at"`
}

type Action struct {
	To      string      `json:"to,omitempty"`
	Do      string      `json:"do"`
	Apply   string      `json:"apply"`
	Phase   string      `json:"phase,omitempty"`
	Code    string      `json:"code,omitempty"`
	Delta   *int        `json:"delta,omitempty"`
	Value   *int        `json:"value,omitempty"`
	Counter string      `json:"counter,omitempty"`
	Marker  string      `json:"marker,omitempty"`
	Group   string      `json:"group,omitempty"`
	Set     string      `json:"set,omitempty"`
	TTL     *int64      `json:"ttl,omitempty"`
	When    []string    `json:"when,omitempty"`
	Headers *ObjectSpec `json:"headers,omitempty"`
	Args    *ObjectSpec `json:"args,omitempty"`
	Body    *ObjectSpec `json:"body,omitempty"`
}

type ObjectSpec struct {
	Set    string `json:"set,omitempty" yaml:"set"`
	Limit  int64  `json:"limit,omitempty" yaml:"limit"`
	Source string `json:"source,omitempty" yaml:"source"`
}

var ArchiveWhen = []string{"allow", "deny"}

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

	_ = audit

	return nil
}

const (
	DoChallenge = "challenge"
	DoThreshold = "threshold"
	DoSkip      = "skip"
	DoReauth    = "reauth"
	DoNote      = "note"
	DoMutate    = "mutate"
	DoActive    = "active"
	DoPassive   = "passive"
	DoOff       = "off"
	DoVote      = "vote"

	DoAudit   = "audit"
	DoArchive = "archive"

	DoMark = "mark"

	DoScore = "score"
)

const (
	ApplyRequest  = "request"
	ApplyIP       = "ip"
	ApplyASN      = "asn"
	ApplySession  = "session"
	ApplyConn     = "conn"
	ApplyResponse = "response"
)

type PriorVerdict struct {
	Inspector string   `json:"inspector"`
	Phase     string   `json:"phase"`
	Wave      int      `json:"wave"`
	Verdict   string   `json:"verdict"`
	Score     int      `json:"score"`
	Reason    *Reason  `json:"reason,omitempty"`
	Actions   []Action `json:"actions,omitempty"`
}

type Release struct {
	Token  string `json:"token"`
	Reason string `json:"reason"`
}

type Request struct {
	V            int               `json:"v"`
	RID          string            `json:"rid"`
	Ray          string            `json:"ray"`
	Phase        string            `json:"phase"`
	Wave         int               `json:"wave"`
	Inspector    string            `json:"inspector"`
	DeadlineMS   int               `json:"deadline_ms"`
	AuditSubject *string           `json:"audit_subject"`
	Node         string            `json:"node"`
	Conn         Conn              `json:"conn"`
	HTTP         HTTP              `json:"http"`
	Vars         map[string]string `json:"vars"`

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

const (
	NeedHeaders = "headers"
	NeedArgs    = "args"
	NeedBody    = "body"
)

func (r *Request) Needed(obj string) bool {
	for _, n := range r.Needs {
		if n == obj {
			return true
		}
	}

	return false
}

const (
	VerdictAllow    = "allow"
	VerdictScore    = "score"
	VerdictRedirect = "redirect"
	VerdictDeny     = "deny"
	VerdictError    = "error"
)

type Reason struct {
	Code  string `json:"code"`
	Class string `json:"class,omitempty"`
}

type ResponseRef struct {
	Name string `json:"name"`
}

type RedirectRef struct {
	URL    string `json:"url"`
	Status int    `json:"status,omitempty"`
}

type HeaderOps struct {
	Set   map[string]string `json:"set,omitempty"`
	Unset []string          `json:"unset,omitempty"`
}

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
	Actions   []Action     `json:"actions,omitempty"`
}

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

var ridPattern = regexp.MustCompile(`"rid"\s*:\s*"([0-9a-fA-F]{1,32})"`)

func SniffRID(payload []byte) string {
	m := ridPattern.FindSubmatch(payload)
	if m == nil {
		return ""
	}

	return string(m[1])
}

func NewReply(req *Request, verdict string) *Reply {
	return &Reply{V: req.V, RID: req.RID, Inspector: req.Inspector, Verdict: verdict}
}

func ErrorReply(req *Request, code string) *Reply {
	reply := NewReply(req, VerdictError)
	reply.Reason = &Reason{Code: code}

	return reply
}

const ClassOverload = "overload"

func ShedReply(req *Request, code string) *Reply {
	reply := ErrorReply(req, code)
	reply.Reason.Class = ClassOverload

	return reply
}

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

const MarkerMax = 128

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
