package policy

import "testing"

func TestOverloadRule(t *testing.T) {
	p, err := Parse("p", []byte("rules:\n"+
		"  - on: overload\n    at: 60\n    actions:\n      - { list: hot, ttl: 10m }\n"+
		"  - match: { path_prefix: /api/ }\n    actions:\n      - { list: api, ttl: 10m }\n"))
	if err != nil {
		t.Fatal(err)
	}

	// Обычный проход строку перегрузки не видит.
	if _, writes, _ := p.Collect(nil, "GET", "/api/x"); len(writes) != 1 || writes[0].List != "api" {
		t.Fatalf("collect: %+v", writes)
	}

	if _, writes, _ := p.CollectOverload(59, false); len(writes) != 0 {
		t.Fatalf("below the threshold: %+v", writes)
	}

	if _, writes, _ := p.CollectOverload(60, false); len(writes) != 1 || writes[0].List != "hot" {
		t.Fatalf("at the threshold: %+v", writes)
	}

	if _, writes, _ := p.CollectOverload(100, true); len(writes) != 1 {
		t.Fatalf("shed: %+v", writes)
	}

	for name, body := range map[string]string{
		"under the scale": "rules:\n  - on: overload\n    at: 10\n    actions:\n      - { list: hot, ttl: 10m }\n",
		"with a match":    "rules:\n  - on: overload\n    match: { path_prefix: /api/ }\n    actions:\n      - { list: hot, ttl: 10m }\n",
		"at without on":   "rules:\n  - at: 60\n    actions:\n      - { list: hot, ttl: 10m }\n",
		"unknown on":      "rules:\n  - on: deny\n    actions:\n      - { list: hot, ttl: 10m }\n",
	} {
		if _, err := Parse("p", []byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
