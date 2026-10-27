package api

import (
	"testing"
	"time"
)

func TestClient_GetGameList(t *testing.T) {
	client := NewClient("")
	games, err := client.GetGameList("warzone")
	if err != nil {
		t.Fatalf("GetGameList failed: %v", err)
	}

	if len(games) == 0 {
		t.Errorf("Expected at least 1 game for query 'warzone', got 0")
	}

	foundWarzone := false
	for _, g := range games {
		if g.GameID == 13975 {
			foundWarzone = true
			t.Logf("Found target game: %s (ID: %d, Package: %s)", g.GameName, g.GameID, g.Package)
			break
		}
	}

	if !foundWarzone {
		t.Logf("Warzone 13975 not found directly by ID, but retrieved %d games", len(games))
	}
}

func TestClient_GoogleLogin_RejectionOnInvalidToken(t *testing.T) {
	client := NewClient("")
	_, err := client.LoginWithGoogle("invalid_mock_jwt_token")
	if err != nil {
		t.Logf("Correctly received rejection for invalid token: %v", err)
		return
	}
	t.Errorf("Expected error with invalid Google token, but got success")
}

func TestPingNode_Live(t *testing.T) {
	rtt, err := PingNode("8.215.50.23", 9993, 1500*time.Millisecond)
	if err != nil {
		t.Logf("Ping live node skipped or timed out: %v", err)
		return
	}
	t.Logf("Successfully probed live node (RTT: %v)", rtt)
}

func TestDecryptAcctPassword(t *testing.T) {
	uid := "20261021200403000000000001114692"
	encHex := "c2f062e436acced215ed3b6ec893b55a"
	expected := "tposwy"

	decrypted, err := DecryptAcctPassword(uid, encHex)
	if err != nil {
		t.Fatalf("DecryptAcctPassword failed: %v", err)
	}

	if decrypted != expected {
		t.Fatalf("Expected decrypted password %q, got %q", expected, decrypted)
	}
	t.Logf("Successfully decrypted password: %s", decrypted)
}

func TestHashPassword(t *testing.T) {
	hashed := HashPassword("test_password_123")
	expected := "394993518c8c06d577150f228d617a75"
	if hashed != expected {
		t.Errorf("Expected %s, got %s", expected, hashed)
	}
}
