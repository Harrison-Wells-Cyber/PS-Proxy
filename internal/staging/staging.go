package staging

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"sync"
	"text/template"
	"time"
)

type Session struct {
	ID             string
	Server         string
	Port           int
	CertPin        string
	EnrollToken    string
	ReconnectToken string
	DNSTarget      string
	ExpiresAt      time.Time
	Delivered      bool
	Enrolled       bool
}

type Store struct {
	mu         sync.Mutex
	sessions   map[string]*Session
	tokens     map[string]*Session
	reconnects map[string]*Session
	ttl        time.Duration
}

func NewStore(ttl time.Duration) *Store {
	return &Store{sessions: map[string]*Session{}, tokens: map[string]*Session{}, reconnects: map[string]*Session{}, ttl: ttl}
}

func NewSecret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *Store) Create(server string, port int, certPin, dnsTarget string) (*Session, error) {
	id, err := NewSecret(18)
	if err != nil {
		return nil, err
	}
	tok, err := NewSecret(32)
	if err != nil {
		return nil, err
	}
	reconnect, err := NewSecret(32)
	if err != nil {
		return nil, err
	}
	sess := &Session{ID: id, Server: server, Port: port, CertPin: certPin, EnrollToken: tok, ReconnectToken: reconnect, DNSTarget: dnsTarget, ExpiresAt: time.Now().Add(s.ttl)}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = sess
	s.tokens[tok] = sess
	s.reconnects[reconnect] = sess
	return sess, nil
}

func (s *Store) RedeemScript(id string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessions[id]
	if sess == nil {
		return nil, errors.New("unknown enrollment id")
	}
	if time.Now().After(sess.ExpiresAt) {
		delete(s.sessions, id)
		delete(s.tokens, sess.EnrollToken)
		delete(s.reconnects, sess.ReconnectToken)
		return nil, errors.New("enrollment expired")
	}
	if sess.Delivered {
		return nil, errors.New("agent script already delivered")
	}
	sess.Delivered = true
	return sess, nil
}

func (s *Store) Authenticate(enrollToken, reconnectToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.reconnects[reconnectToken]
	if sess != nil && sess.Enrolled {
		return nil
	}
	sess = s.tokens[enrollToken]
	if sess == nil {
		return errors.New("invalid enrollment token")
	}
	if time.Now().After(sess.ExpiresAt) {
		delete(s.sessions, sess.ID)
		delete(s.tokens, enrollToken)
		delete(s.reconnects, sess.ReconnectToken)
		return errors.New("enrollment expired")
	}
	if sess.Enrolled && sess.ReconnectToken != reconnectToken {
		return errors.New("enrollment token already used")
	}
	sess.Enrolled = true
	return nil
}

type AgentTemplateData struct {
	AssemblyB64    string
	Server         string
	Port           int
	CertPin        string
	EnrollToken    string
	ReconnectToken string
	DNSTarget      string
}

func AgentHandler(store *Store, tmpl *template.Template, assemblyB64 string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		sess, err := store.RedeemScript(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusGone)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = tmpl.Execute(w, AgentTemplateData{AssemblyB64: assemblyB64, Server: sess.Server, Port: sess.Port, CertPin: sess.CertPin, EnrollToken: sess.EnrollToken, ReconnectToken: sess.ReconnectToken, DNSTarget: sess.DNSTarget})
	}
}
