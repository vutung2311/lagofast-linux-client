package tunnel

import (
	"syscall"
	"testing"
	"time"
)

func TestEngine_Lifecycle(t *testing.T) {
	// Create mock socketpair to simulate TUN fd
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("Socketpair failed: %v", err)
	}
	defer syscall.Close(fds[0])
	defer syscall.Close(fds[1])

	err = DefaultEngine.Init("/tmp/patch_test")
	if err != nil {
		t.Fatalf("Engine init failed: %v", err)
	}

	configJSON := `{
		"server":{"address":"43.153.212.197","port":9993},
		"client":{
			"protocol":"UDP",
			"group_id":"320",
			"login_token":"20261021200403000000000001114692_f4331fdf0b3343d087b9",
			"username":"vutung.ct@gmail.com",
			"password":"tposwy",
			"client_type":20,
			"eventId":12345678,
			"sn":"c7a544b6-7917-488b-b892-06b297b1028b",
			"mode":1,
			"serverid":45983,
			"product_line":{"type":"lagofast-android","version":"2.2.0.0"},
			"select_zone_flag":"sg",
			"sessionSize":0,
			"enableSpeedCounter":false,
			"ping_full_link":false,
			"enableLwip":true,
			"network_way":"WIFI",
			"enableFineDivert":false,
			"tunId":"lagofast0"
		},
		"gameinfo":{"game_id":54758},
		"divert":{
			"confVersion":"1.0",
			"apiVersion":"1.0",
			"dns":{"defaultOutTag":"direct","servers":[{"outTag":"direct","domains":["*"]}]},
			"routing":{"defaultOutTag":"proxy","rules":[]}
		},
		"customProfile":{"qyproxy_config":{"game_area":"sg"},"qyproxy_game_config":{"confuse":7,"enableProxyModeDNS":true,"enableUdpTunnel":true,"log_level":"DEBUG","nat_open":false}}
	}`

	err = DefaultEngine.Start(configJSON, fds[0])
	if err != nil {
		t.Fatalf("Engine start failed: %v", err)
	}

	if !DefaultEngine.IsRunning() {
		t.Errorf("Engine should report running")
	}

	// Allow worker thread to run for 2 seconds to authenticate with Singapore node
	time.Sleep(2 * time.Second)

	DefaultEngine.Stop()

	if DefaultEngine.IsRunning() {
		t.Errorf("Engine should report stopped after Stop()")
	}
	t.Logf("Engine lifecycle test passed cleanly!")
}
