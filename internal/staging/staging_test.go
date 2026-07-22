package staging

import (
	"testing"
	"time"
)

func TestAuthenticateAllowsReconnectTokenAfterEnrollment(t *testing.T) {
	store := NewStore(time.Minute)
	sess, err := store.Create("c2.example.com", 443, "pin", "10.0.0.10:53")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := store.Authenticate(sess.EnrollToken, sess.ReconnectToken); err != nil {
		t.Fatalf("initial enrollment failed: %v", err)
	}
	if err := store.Authenticate("", sess.ReconnectToken); err != nil {
		t.Fatalf("reconnect failed: %v", err)
	}
}

func TestAuthenticateRejectsReusedEnrollTokenWithoutReconnectToken(t *testing.T) {
	store := NewStore(time.Minute)
	sess, err := store.Create("c2.example.com", 443, "pin", "")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := store.Authenticate(sess.EnrollToken, sess.ReconnectToken); err != nil {
		t.Fatalf("initial enrollment failed: %v", err)
	}
	if err := store.Authenticate(sess.EnrollToken, "wrong"); err == nil {
		t.Fatal("reused enrollment token without reconnect token should fail")
	}
}

func TestReconnectTokenSurvivesEnrollmentURLTTL(t *testing.T) {
	store := NewStore(50 * time.Millisecond)
	sess, err := store.Create("c2.example.com", 443, "pin", "")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := store.Authenticate(sess.EnrollToken, sess.ReconnectToken); err != nil {
		t.Fatalf("initial enrollment failed: %v", err)
	}
	time.Sleep(75 * time.Millisecond)
	if err := store.Authenticate("", sess.ReconnectToken); err != nil {
		t.Fatalf("reconnect token should survive URL TTL after enrollment: %v", err)
	}
}
