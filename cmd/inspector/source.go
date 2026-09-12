/*
 * Значения запроса для условий профиля (policy.Source).
 *
 * Поля сообщения и секция vars лежат в самом сообщении. Заголовки и строка
 * запроса едут локаторами и достаются из обменника лениво -- по первому
 * условию, которому они нужны, и один раз на запрос: пять условий по кукам
 * разбирают Cookie один раз, а профиль без условий по заголовкам в обменник
 * не ходит вовсе.
 *
 * Недоступность двух родов, как у счётчика (internal/body): та, что приехала в
 * локаторе, -- решение маршрута, объект просто недоступен; та, что обнаружил
 * сам инспектор (обменник не ответил, хеш не сошёлся), -- его сбой, и он
 * помечается Fault: ответ на такой запрос -- verdict error, потому что
 * условие, посчитанное без данных, которые лежали рядом, -- это не условие.
 */

package main

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/exemt/placitum-action/internal/body"
	"github.com/exemt/placitum-action/internal/policy"
	"github.com/exemt/placitum-action/internal/protocol"
)

// stdHeaders -- поля стандартного набора vars, которые суть заголовки: когда
// маршрут заголовков не снимает, $http_<имя> читается из vars. Ключ -- имя
// заголовка в форме nginx ($http_ без префикса).
var stdHeaders = map[string]string{
	"user_agent":      "user_agent",
	"referer":         "referer",
	"x_forwarded_for": "xff",
	"accept_language": "accept_language",
	"origin":          "origin",
	"content_type":    "content_type",
	"accept":          "accept",
}

type source struct {
	ctx    context.Context
	req    *protocol.Request
	loader *body.Loader

	headers     []policy.Pair
	headersOK   bool
	headersDone bool

	cookies     []policy.Pair
	cookiesDone bool

	cookiesOK bool

	args     []policy.Pair
	argsOK   bool
	argsDone bool

	raw     string
	rawOK   bool
	rawDone bool

	// Fault -- обменник подвёл на объекте, который лежал: сбой инспектора,
	// а не свойство запроса. Why -- причина в словах локатора.
	Fault bool
	Why   string
}

func newSource(ctx context.Context, req *protocol.Request, loader *body.Loader) *source {
	return &source{ctx: ctx, req: req, loader: loader}
}

func (s *source) Field(name string) string {
	h := &s.req.HTTP

	switch name {
	case "uri":
		return h.URI
	case "request_uri":
		// Строка запроса лежит в обменнике; без неё путь голый, как у
		// $uri. Ноль в args_size -- строки и не было.
		if h.ArgsSize == 0 {
			return h.URI
		}

		if raw, ok := s.rawArgs(); ok && raw != "" {
			return h.URI + "?" + raw
		}

		return h.URI
	case "host":
		return h.Host
	case "request_method":
		return h.Method
	case "scheme":
		return h.Scheme
	case "remote_addr":
		return s.req.Conn.ClientIP
	}

	return ""
}

func (s *source) Var(name string) (string, bool) {
	if s.req.Vars == nil {
		return "", false
	}

	v, ok := s.req.Vars[name]

	return v, ok
}

/*
 * Headers -- пары заголовков из обменника. Маршрут их не снимает -- берётся
 * то, что есть в vars: стандартный набор модуля повторяет самые ходовые
 * заголовки, и условие по User-Agent не должно требовать снимка ради одного
 * поля. Тогда ok=true, но пар ровно столько, сколько полей.
 */
func (s *source) Headers() ([]policy.Pair, bool) {
	if s.headersDone {
		return s.headers, s.headersOK
	}

	s.headersDone = true

	loc := s.req.Store.Headers

	if loc == nil {
		s.headers, s.headersOK = s.varsAsHeaders()

		return s.headers, s.headersOK
	}

	loaded := s.loader.Load(s.ctx, loc)

	if loaded.Failed() {
		s.Fault = true
		s.Why = "headers: " + loaded.Unavailable

		return nil, false
	}

	if !loaded.Available() || len(loaded.Data) == 0 {
		return nil, false
	}

	var pairs []protocol.Header

	if err := json.Unmarshal(loaded.Data, &pairs); err != nil {
		s.Fault = true
		s.Why = "headers: blob is not an array of pairs"

		return nil, false
	}

	s.headers = make([]policy.Pair, 0, len(pairs))

	for _, p := range pairs {
		s.headers = append(s.headers, policy.Pair{Name: p.Name(), Value: p.Value()})
	}

	s.headersOK = true

	return s.headers, true
}

func (s *source) varsAsHeaders() ([]policy.Pair, bool) {
	if s.req.Vars == nil {
		return nil, false
	}

	var out []policy.Pair

	for header, field := range stdHeaders {
		if v, ok := s.req.Vars[field]; ok && v != "" {
			out = append(out, policy.Pair{Name: header, Value: v})
		}
	}

	return out, true
}

// Cookies -- разбор всех заголовков Cookie: имя точное, значение без
// пробелов по краям и без кавычек, декода нет -- как у селектора модуля.
func (s *source) Cookies() ([]policy.Pair, bool) {
	if s.cookiesDone {
		return s.cookies, s.cookiesOK
	}

	s.cookiesDone = true

	headers, ok := s.Headers()
	if !ok {
		return nil, false
	}

	s.cookiesOK = true

	for _, h := range headers {
		if !strings.EqualFold(h.Name, "cookie") {
			continue
		}

		for _, item := range strings.Split(h.Value, ";") {
			name, value, found := strings.Cut(item, "=")
			if !found {
				continue
			}

			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}

			value = strings.TrimSpace(value)

			if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
				value = value[1 : len(value)-1]
			}

			s.cookies = append(s.cookies, policy.Pair{Name: name, Value: value})
		}
	}

	return s.cookies, true
}

// Args -- разбор строки запроса: percent-декод, `+` -- пробел, имя тоже
// декодируется; пара без `=` -- имя с пустым значением.
func (s *source) Args() ([]policy.Pair, bool) {
	if s.argsDone {
		return s.args, s.argsOK
	}

	s.argsDone = true

	raw, ok := s.rawArgs()
	if !ok {
		return nil, false
	}

	s.argsOK = true

	for _, item := range strings.Split(raw, "&") {
		if item == "" {
			continue
		}

		name, value, _ := strings.Cut(item, "=")

		if n, err := url.QueryUnescape(name); err == nil {
			name = n
		}

		if v, err := url.QueryUnescape(value); err == nil {
			value = v
		}

		if name == "" {
			continue
		}

		s.args = append(s.args, policy.Pair{Name: name, Value: value})
	}

	return s.args, true
}

// rawArgs -- строка запроса как пришла. Пустая строка при ok -- запроса не
// было; ok=false -- объект недоступен.
func (s *source) rawArgs() (string, bool) {
	if s.rawDone {
		return s.raw, s.rawOK
	}

	s.rawDone = true

	if s.req.HTTP.ArgsSize == 0 {
		s.rawOK = true

		return "", true
	}

	loc := s.req.Store.Args

	if loc == nil {
		return "", false
	}

	loaded := s.loader.Load(s.ctx, loc)

	if loaded.Failed() {
		s.Fault = true
		s.Why = "args: " + loaded.Unavailable

		return "", false
	}

	if !loaded.Available() {
		return "", false
	}

	s.raw, s.rawOK = string(loaded.Data), true

	return s.raw, true
}
