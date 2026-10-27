package api

import (
	"testing"
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
	if err == nil {
		t.Errorf("Expected error with invalid Google token, but got success")
	} else {
		t.Logf("Correctly received rejection for invalid token: %v", err)
	}
}

func TestHashPassword(t *testing.T) {
	hashed := HashPassword("test_password_123")
	expected := "394993518c8c06d577150f228d617a75"
	if hashed != expected {
		t.Errorf("Expected %s, got %s", expected, hashed)
	}
}
