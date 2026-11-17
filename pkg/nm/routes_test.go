package nm

import (
	"reflect"
	"testing"
)

func TestRouteBatchBuildsLinesAndSkipsInvalid(t *testing.T) {
	got := routeBatch("replace",
		[]string{"150.109.94.71/32", "999.1.1.1/32", "", "43.153.212.197/32"},
		"192.168.88.1", "wlan0")
	want := []string{
		"route replace 150.109.94.71/32 via 192.168.88.1 dev wlan0",
		"route replace 43.153.212.197/32 via 192.168.88.1 dev wlan0",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("routeBatch mismatch:\n got  %q\n want %q", got, want)
	}
}
