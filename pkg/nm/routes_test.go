package nm

import (
	"reflect"
	"testing"

	"github.com/godbus/dbus/v5"
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

// Regression: NetworkManager nests VPN settings under vpn.data / vpn.secrets,
// so reading them as flat top-level keys silently fell back to defaults.
func TestVpnSettingReadsNestedData(t *testing.T) {
	vpn := map[string]dbus.Variant{
		"service-type": dbus.MakeVariant("org.freedesktop.NetworkManager.lagofast"),
		"data":         dbus.MakeVariant(map[string]string{"game_id": "39900", "multihop": "off"}),
		"secrets":      dbus.MakeVariant(map[string]string{"token": "t0k"}),
	}
	for key, want := range map[string]string{"game_id": "39900", "multihop": "off", "token": "t0k"} {
		if got, ok := vpnSetting(vpn, key); !ok || got != want {
			t.Errorf("vpnSetting(%q) = %q, %v; want %q", key, got, ok, want)
		}
	}
	if _, ok := vpnSetting(vpn, "zone_id"); ok {
		t.Error("missing key reported as present")
	}
	flat := map[string]dbus.Variant{"game_id": dbus.MakeVariant("123")}
	if got, _ := vpnSetting(flat, "game_id"); got != "123" {
		t.Errorf("flat fallback = %q", got)
	}
}
