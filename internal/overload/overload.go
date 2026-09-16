package overload

import "fmt"

const (
	On = "overload"

	AtMin = 25

	AtMax = 100
)

func At(at *int) int {
	if at == nil {
		return AtMax
	}

	return *at
}

func Check(at *int) error {
	if at == nil {
		return nil
	}

	if *at < AtMin || *at > AtMax {
		return fmt.Errorf("at %d is out of %d..%d percent of the queue", *at, AtMin, AtMax)
	}

	return nil
}

func Fires(at, fill int, shed bool) bool {
	if shed {
		return true
	}

	return at < AtMax && fill >= at
}
