package bootstrap

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestResourcesCloseInReverseOrderOnce(t *testing.T) {
	var closed []string
	resources := &Resources{}
	resources.Add("store", func() error { closed = append(closed, "store"); return nil })
	resources.Add("sensor", func() error { closed = append(closed, "sensor"); return nil })

	if err := resources.Close(); err != nil {
		t.Fatal(err)
	}
	if err := resources.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if want := []string{"sensor", "store"}; !reflect.DeepEqual(closed, want) {
		t.Fatalf("close order = %v, want %v", closed, want)
	}
}

func TestResourcesCloseReportsEveryFailure(t *testing.T) {
	resources := &Resources{}
	resources.Add("store", func() error { return errors.New("disk busy") })
	resources.Add("sensor", func() error { return errors.New("stop timeout") })

	err := resources.Close()
	if err == nil || !strings.Contains(err.Error(), "store: disk busy") || !strings.Contains(err.Error(), "sensor: stop timeout") {
		t.Fatalf("Close() error = %v", err)
	}
}
