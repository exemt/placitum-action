package overload

import "testing"

func TestFires(t *testing.T) {
	cases := []struct {
		at, fill int
		shed     bool
		want     bool
	}{
		// Сброс: срабатывает любая строка, край в том числе.
		{AtMax, 100, true, true},
		{60, 100, true, true},
		// Проверенный запрос: от порога и выше, но не на краю.
		{60, 59, false, false},
		{60, 60, false, true},
		{60, 100, false, true},
		{AtMin, AtMin, false, true},
		// Край на проверенном запросе молчит: ждавший места не сброшен.
		{AtMax, 100, false, false},
	}

	for _, c := range cases {
		if got := Fires(c.at, c.fill, c.shed); got != c.want {
			t.Errorf("Fires(%d, %d, %v) = %v, want %v", c.at, c.fill, c.shed, got, c.want)
		}
	}
}

func TestCheck(t *testing.T) {
	for _, at := range []int{AtMin, 60, AtMax} {
		if err := Check(&at); err != nil {
			t.Errorf("at %d: %v", at, err)
		}
	}

	for _, at := range []int{0, AtMin - 1, AtMax + 1} {
		if err := Check(&at); err == nil {
			t.Errorf("at %d accepted", at)
		}
	}

	if err := Check(nil); err != nil {
		t.Errorf("no at: %v", err)
	}

	if At(nil) != AtMax {
		t.Errorf("a row without at is not the edge")
	}
}
