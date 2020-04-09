package mock

import (
	"testing"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/trivy"
)

// Expectation represents an expectation of a method being called and its return values.
type Expectation struct {
	Method     string
	Args       []interface{}
	ReturnArgs []interface{}
}

// ApplyExpectation applies the specified expectations on a given mock.
func ApplyExpectations(t *testing.T, mock interface{}, expectations ...*Expectation) {
	t.Helper()
	if len(expectations) == 0 || expectations[0] == nil {
		return
	}
	switch v := mock.(type) {
	case *Enqueuer:
		m := mock.(*Enqueuer)
		for _, e := range expectations {
			m.On(e.Method, e.Args...).Return(e.ReturnArgs...)
		}
	case *Store:
		m := mock.(*Store)
		for _, e := range expectations {
			m.On(e.Method, e.Args...).Return(e.ReturnArgs...)
		}
	case *trivy.MockWrapper:
		m := mock.(*trivy.MockWrapper)
		for _, e := range expectations {
			m.On(e.Method, e.Args...).Return(e.ReturnArgs...)
		}
	case *Transformer:
		m := mock.(*Transformer)
		for _, e := range expectations {
			m.On(e.Method, e.Args...).Return(e.ReturnArgs...)
		}
	default:
		t.Fatalf("Unrecognized mock type: %T!", v)
	}
}
