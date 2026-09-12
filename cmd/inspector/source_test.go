/*
 * Источник значений: заголовки и строка запроса разбираются так же, как их
 * читают селекторы модуля (docs/directives/module-copy/list/select.md), а объекты
 * достаются из обменника по одному разу.
 */

package main

import (
	"context"
	"errors"
	"testing"

	"github.com/exemt/placitum-action/internal/body"
	"github.com/exemt/placitum-action/internal/policy"
	"github.com/exemt/placitum-action/internal/protocol"
)

type fakeStore struct {
	data map[string][]byte
	gets int
}

func (f *fakeStore) Get(_ context.Context, driver, _ string, key string) ([]byte, error) {
	if driver != "redis" {
		return nil, body.ErrUnknownDriver
	}

	f.gets++

	raw, ok := f.data[key]
	if !ok {
		return nil, errors.New("nil")
	}

	return raw, nil
}

func (f *fakeStore) Close() error { return nil }

func request(headers, args string) (*protocol.Request, *fakeStore) {
	store := &fakeStore{data: map[string][]byte{}}
	req := &protocol.Request{
		HTTP: protocol.HTTP{Method: "GET", Scheme: "https", Host: "shop.test", URI: "/api/x"},
		Conn: protocol.Conn{ClientIP: "10.1.2.3"},
		Vars: map[string]string{"user_agent": "curl/8", "ja3": "abc"},
	}

	if headers != "" {
		store.data["n:1:req:hdr"] = []byte(headers)
		req.Store.Headers = &protocol.Locator{Store: "hot", Driver: "redis", Key: "n:1:req:hdr"}
	}

	if args != "" {
		store.data["n:1:req:arg"] = []byte(args)
		req.HTTP.ArgsSize = int64(len(args))
		req.Store.Args = &protocol.Locator{Store: "hot", Driver: "redis", Key: "n:1:req:arg"}
	}

	return req, store
}

func TestSourceObjects(t *testing.T) {
	req, store := request(
		`[["Host","shop.test"],["X-Api-Key","k1"],["Cookie","sid=ok; theme=\"dark\""],["Cookie","sid=evil"]]`,
		"q=1&debug=DROP%20TABLE&token=a+b&flag",
	)

	src := newSource(context.Background(), req, body.NewLoader(store, nil))

	if got := src.Field("request_uri"); got != "/api/x?q=1&debug=DROP%20TABLE&token=a+b&flag" {
		t.Errorf("request_uri = %q", got)
	}

	if got := src.Field("remote_addr"); got != "10.1.2.3" {
		t.Errorf("remote_addr = %q", got)
	}

	headers, ok := src.Headers()
	if !ok || len(headers) != 4 || headers[1].Value != "k1" {
		t.Fatalf("headers = %+v, %v", headers, ok)
	}

	cookies, ok := src.Cookies()
	if !ok || len(cookies) != 3 || cookies[1].Value != "dark" || cookies[2].Value != "evil" {
		t.Errorf("cookies = %+v", cookies)
	}

	args, ok := src.Args()
	if !ok || len(args) != 4 || args[1].Value != "DROP TABLE" || args[2].Value != "a b" || args[3].Name != "flag" {
		t.Errorf("args = %+v", args)
	}

	// Оба объекта достаются по разу, сколько бы условий их ни читало.
	_, _ = src.Headers()
	_, _ = src.Args()
	_ = src.Field("request_uri")

	if store.gets != 2 {
		t.Errorf("store gets = %d, want 2", store.gets)
	}

	if src.Fault {
		t.Errorf("fault = %q", src.Why)
	}

	// Через операнды: $http_ по имени nginx, $waf_var из секции.
	for raw, want := range map[string]string{
		"$http_x_api_key":             "k1",
		"$cookie_sid":                 "ok",
		"$arg_token":                  "a b",
		"$waf_var.ja3":                "abc",
		"$waf_request_headers.cookie": "sid=ok; theme=\"dark\"",
	} {
		op, err := policy.ParseOperand(raw)
		if err != nil {
			t.Fatal(err)
		}

		values, avail := op.Values(src)
		if !avail || len(values) == 0 || values[0] != want {
			t.Errorf("%s = %v (%v), want %q", raw, values, avail, want)
		}
	}
}

func TestSourceWithoutObjects(t *testing.T) {
	// Маршрут снимка не делает: заголовки читаются из vars, аргументов нет.
	req, store := request("", "")
	src := newSource(context.Background(), req, body.NewLoader(store, nil))

	op, _ := policy.ParseOperand("$http_user_agent")

	values, avail := op.Values(src)
	if !avail || len(values) != 1 || values[0] != "curl/8" {
		t.Errorf("user agent from vars = %v (%v)", values, avail)
	}

	op, _ = policy.ParseOperand("$arg_q")

	if values, avail := op.Values(src); !avail || len(values) != 0 {
		t.Errorf("no query string = %v (%v), want none and available", values, avail)
	}

	if store.gets != 0 {
		t.Errorf("store touched without locators: %d", store.gets)
	}
}

func TestSourceFault(t *testing.T) {
	req, store := request(`[["A","b"]]`, "")
	delete(store.data, "n:1:req:hdr")

	src := newSource(context.Background(), req, body.NewLoader(store, nil))

	if _, ok := src.Headers(); ok || !src.Fault {
		t.Errorf("missing key: ok=%v fault=%v", ok, src.Fault)
	}

	// Без обменника вовсе -- тоже сбой: объект лежал, взять нечем.
	req, _ = request(`[["A","b"]]`, "")
	src = newSource(context.Background(), req, body.NewLoader(nil, nil))

	if _, ok := src.Headers(); ok || !src.Fault {
		t.Errorf("no store: ok=%v fault=%v", ok, src.Fault)
	}
}
