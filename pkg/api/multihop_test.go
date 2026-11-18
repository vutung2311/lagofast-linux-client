package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// First three AES blocks of a real multi_hop_all_node payload.
const kaCiphertext = "bd90499686119cab32e2e2a5ebe6a4365b7aa1c665882524e96c5bf7f5bc260b6c6d1d9e4242e94a9f37c59ebdf1f2ac"
const kaPlaintext = `[{"type": 1, "ip": "216.133.159.134", "udping_po`

func TestDecryptSDKKnownAnswer(t *testing.T) {
	got, err := DecryptSDK(kaCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != kaPlaintext {
		t.Fatalf("got %q, want %q", got, kaPlaintext)
	}
}

func TestEncryptSDKMatchesServerFormat(t *testing.T) {
	// Encrypting the known plaintext must reproduce the server's bytes
	// (uppercase hex, as the SDK emits).
	if got := EncryptSDK([]byte(kaPlaintext)); got != strings.ToUpper(kaCiphertext) {
		t.Fatalf("got %s, want %s", got, strings.ToUpper(kaCiphertext))
	}
	// Non-block-aligned input round-trips through zero padding.
	in := []byte(`[{"ip":"1.2.3.4","delay":7.5}]`)
	out, err := DecryptSDK(EncryptSDK(in))
	if err != nil || string(out) != string(in) {
		t.Fatalf("round trip: %q, %v", out, err)
	}
}

func samplePath() MultiHopNode {
	return MultiHopNode{
		ID: 3934, PublicIP: "216.133.159.134", Delay: 29.7, Des: []float64{8, 19.4, 1.2, 1.1},
		Path: []HopPathEntry{
			{IP: "216.133.159.134", TCPPort: []int{22565, 1871}, UDPPort: []int{3485}},
			{IP: "45.76.144.152", TCPPort: []int{1429}, UDPPort: nil, ForceProtocol: "udp"},
			{IP: "192.168.104.85", TCPPort: []int{10177}},
		},
	}
}

func TestBuildMultiLinkMatchesSDKShape(t *testing.T) {
	got, err := BuildMultiLink(samplePath())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(got)
	want := `{"delay":29,"path":[` +
		`{"ip":"216.133.159.134","proc":"tcp","tcp_port":[22565,1871],"udp_port":[3485]},` +
		`{"ip":"45.76.144.152","proc":"udp","tcp_port":[1429],"udp_port":[]},` +
		`{"ip":"192.168.104.85","tcp_port":[10177],"udp_port":[]}],` +
		`"port":22565,"server":"216.133.159.134"}`
	if string(b) != want {
		t.Fatalf("multiLink entry mismatch:\n got  %s\n want %s", b, want)
	}
}

func TestBuildMultiLinkRejectsPathWithoutEntry(t *testing.T) {
	n := samplePath()
	n.PublicIP = "9.9.9.9"
	if _, err := BuildMultiLink(n); err == nil {
		t.Fatal("expected error when no hop matches the entry IP")
	}
}

func TestPublicHopIPsSkipsPrivate(t *testing.T) {
	got := PublicHopIPs(samplePath(), samplePath())
	want := []string{"216.133.159.134", "45.76.144.152"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestPickLinksUsesDistinctEntries(t *testing.T) {
	a := MultiHopNode{PublicIP: "1.1.1.1", Delay: 29}
	b := MultiHopNode{PublicIP: "2.2.2.2", Delay: 30}
	// The replica set repeats the best entry first; the second link must differ.
	got := PickLinks([]MultiHopNode{a, b}, []MultiHopNode{a, b})
	if len(got) != 2 || got[0].PublicIP != "1.1.1.1" || got[1].PublicIP != "2.2.2.2" {
		t.Fatalf("got %+v", got)
	}
	if got := PickLinks([]MultiHopNode{a}, nil); len(got) != 1 {
		t.Fatalf("single path should yield one link, got %d", len(got))
	}
}

func TestShortestPathsRequestAndDecode(t *testing.T) {
	areas := `[{"area":"sg","nodes":[` +
		`{"id":2,"publicip":"2.2.2.2","delay":31.0,"path":[{"ip":"2.2.2.2","tcp_port":[1]}]},` +
		`{"id":1,"publicip":"1.1.1.1","delay":29.7,"path":[{"ip":"1.1.1.1","tcp_port":[1]}]}]}]`
	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/accelerate_bff/v2/multi_hop_shortest_path" {
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, 400)
			return
		}
		json.NewDecoder(r.Body).Decode(&gotBody)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": 0, "area_nodes": EncryptSDK([]byte(areas)), "replicas_area_nodes": EncryptSDK([]byte(areas)),
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	main, replicas, err := c.GetShortestPaths(54758, 45983, []HopDelay{{IP: "1.1.1.1", Delay: 8}})
	if err != nil {
		t.Fatal(err)
	}
	if len(main) != 2 || main[0].ID != 1 || len(replicas) != 2 {
		t.Fatalf("expected 2 paths sorted by delay, got main=%+v replicas=%d", main, len(replicas))
	}
	sent, err := DecryptSDK(gotBody["crypto_delay_info"])
	if err != nil || string(sent) != `[{"ip":"1.1.1.1","delay":8}]` {
		t.Fatalf("crypto_delay_info decrypts to %q (%v)", sent, err)
	}
	if gotBody["game_id"] != "54758" || gotBody["zone_id"] != "45983" || gotBody["crypto_method"] != "AES-ECB" {
		t.Fatalf("unexpected body fields: %v", gotBody)
	}
}
