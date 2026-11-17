package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemoizeSharesInFlightAndCachesSuccess(t *testing.T) {
	c := NewClient("http://unused")
	var calls int32
	release := make(chan struct{})
	fn := func() (interface{}, error) {
		atomic.AddInt32(&calls, 1)
		<-release
		return 42, nil
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := c.memoize("k", fn)
			if err != nil || v.(int) != 42 {
				t.Errorf("got %v, %v", v, err)
			}
		}()
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()

	if _, err := c.memoize("k", fn); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("expected 1 underlying call, got %d", n)
	}
}

func TestMemoizeDoesNotCacheErrors(t *testing.T) {
	c := NewClient("http://unused")
	var calls int
	fn := func() (interface{}, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("boom")
		}
		return "ok", nil
	}
	if _, err := c.memoize("k", fn); err == nil {
		t.Fatal("expected error on first call")
	}
	if v, err := c.memoize("k", fn); err != nil || v.(string) != "ok" {
		t.Fatalf("expected retry to succeed, got %v, %v", v, err)
	}
}

func TestMemoizeExpires(t *testing.T) {
	c := NewClient("http://unused")
	var calls int
	fn := func() (interface{}, error) { calls++; return calls, nil }
	c.memoize("k", fn)
	c.memoMu.Lock()
	c.memo["k"].at = time.Now().Add(-2 * memoTTL)
	c.memoMu.Unlock()
	if v, _ := c.memoize("k", fn); v.(int) != 2 {
		t.Fatalf("expected refetch after TTL, got %v", v)
	}
}

func TestSetTokenClearsMemo(t *testing.T) {
	c := NewClient("http://unused")
	var calls int
	fn := func() (interface{}, error) { calls++; return calls, nil }
	c.memoize("k", fn)
	c.SetToken("other-user", "2")
	if v, _ := c.memoize("k", fn); v.(int) != 2 {
		t.Fatalf("expected refetch after SetToken, got %v", v)
	}
}

// One connect used to fetch the node list 3x and acct_detail_all 2x.
func TestConnectPathRequestsAreDeduplicated(t *testing.T) {
	var nodeHits, acctHits, detailHits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/accelerate_bff/v2/acct_object/node":
			atomic.AddInt32(&nodeHits, 1)
			w.Write([]byte(`{"node_map":{"SG":[{"node_no":1,"node_name":"SG-1","public_ip":"43.153.212.197","ping_ports":[9993],"group_id":320}]}}`))
		case "/api/accelerate_bff/v1/mobile/acct_object/acct_detail_all":
			atomic.AddInt32(&acctHits, 1)
			w.Write([]byte(`{}`))
		default:
			atomic.AddInt32(&detailHits, 1)
			w.Write([]byte(`{"data":{"zone_info":[]}}`))
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); c.GetAcctDetailAll(54758, 45983) }()
	go func() { defer wg.Done(); c.GetGameRoutingSubnets(54758, 45983) }()
	c.GetGameNodesForZone(54758, 45983)
	wg.Wait()
	c.GetGameNodesForZone(54758, 45983)

	if nodeHits != 1 || acctHits != 1 || detailHits != 1 {
		t.Fatalf("expected 1 request per endpoint, got nodes=%d acct=%d detail=%d", nodeHits, acctHits, detailHits)
	}
}
