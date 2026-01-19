package auth

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

// Store 会话和授权码存储接口
type Store interface {
	// Session 管理
	SaveSession(ctx context.Context, session *Session) error
	GetSession(ctx context.Context, sessionID string) (*Session, error)
	UpdateSession(ctx context.Context, session *Session) error
	DeleteSession(ctx context.Context, sessionID string) error

	// AuthorizationCode 管理
	SaveAuthCode(ctx context.Context, code *AuthorizationCode) error
	GetAuthCode(ctx context.Context, code string) (*AuthorizationCode, error)
	MarkAuthCodeUsed(ctx context.Context, code string) error
	DeleteAuthCode(ctx context.Context, code string) error
}

// 错误定义
var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
	ErrCodeNotFound    = errors.New("authorization code not found")
	ErrCodeExpired     = errors.New("authorization code expired")
	ErrCodeUsed        = errors.New("authorization code already used")
)

// MemoryStore 内存存储（开发/测试用）
type MemoryStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	codes    map[string]*AuthorizationCode
}

// NewMemoryStore 创建内存存储
func NewMemoryStore() *MemoryStore {
	store := &MemoryStore{
		sessions: make(map[string]*Session),
		codes:    make(map[string]*AuthorizationCode),
	}
	// 启动清理 goroutine
	go store.cleanupLoop()
	return store
}

func (s *MemoryStore) SaveSession(ctx context.Context, session *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.ID] = session
	return nil
}

func (s *MemoryStore) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[sessionID]
	if !ok {
		return nil, ErrSessionNotFound
	}
	if time.Now().After(session.ExpiresAt) {
		return nil, ErrSessionExpired
	}
	return session, nil
}

func (s *MemoryStore) UpdateSession(ctx context.Context, session *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.ID] = session
	return nil
}

func (s *MemoryStore) DeleteSession(ctx context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
	return nil
}

func (s *MemoryStore) SaveAuthCode(ctx context.Context, code *AuthorizationCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code.Code] = code
	return nil
}

func (s *MemoryStore) GetAuthCode(ctx context.Context, code string) (*AuthorizationCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	authCode, ok := s.codes[code]
	if !ok {
		return nil, ErrCodeNotFound
	}
	if time.Now().After(authCode.ExpiresAt) {
		return nil, ErrCodeExpired
	}
	if authCode.Used {
		return nil, ErrCodeUsed
	}
	return authCode, nil
}

func (s *MemoryStore) MarkAuthCodeUsed(ctx context.Context, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	authCode, ok := s.codes[code]
	if !ok {
		return ErrCodeNotFound
	}
	authCode.Used = true
	return nil
}

func (s *MemoryStore) DeleteAuthCode(ctx context.Context, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.codes, code)
	return nil
}

func (s *MemoryStore) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		s.cleanup()
	}
}

func (s *MemoryStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, session := range s.sessions {
		if now.After(session.ExpiresAt) {
			delete(s.sessions, id)
		}
	}
	for code, authCode := range s.codes {
		if now.After(authCode.ExpiresAt) {
			delete(s.codes, code)
		}
	}
}

// RedisStore Redis 存储
type RedisStore struct {
	client        RedisClient
	sessionPrefix string
	codePrefix    string
	sessionTTL    time.Duration
	codeTTL       time.Duration
}

// RedisClient Redis 客户端接口
type RedisClient interface {
	Set(ctx context.Context, key string, value any, expiration time.Duration) error
	Get(ctx context.Context, key string) (string, error)
	Del(ctx context.Context, keys ...string) error
}

// RedisStoreConfig Redis 存储配置
type RedisStoreConfig struct {
	Client        RedisClient
	SessionPrefix string
	CodePrefix    string
	SessionTTL    time.Duration
	CodeTTL       time.Duration
}

// NewRedisStore 创建 Redis 存储
func NewRedisStore(cfg *RedisStoreConfig) *RedisStore {
	sessionPrefix := cfg.SessionPrefix
	if sessionPrefix == "" {
		sessionPrefix = "auth:session:"
	}
	codePrefix := cfg.CodePrefix
	if codePrefix == "" {
		codePrefix = "auth:code:"
	}
	sessionTTL := cfg.SessionTTL
	if sessionTTL == 0 {
		sessionTTL = 10 * time.Minute
	}
	codeTTL := cfg.CodeTTL
	if codeTTL == 0 {
		codeTTL = 5 * time.Minute
	}
	return &RedisStore{
		client:        cfg.Client,
		sessionPrefix: sessionPrefix,
		codePrefix:    codePrefix,
		sessionTTL:    sessionTTL,
		codeTTL:       codeTTL,
	}
}

func (s *RedisStore) SaveSession(ctx context.Context, session *Session) error {
	data, err := json.Marshal(session)
	if err != nil {
		return err
	}
	return s.client.Set(ctx, s.sessionPrefix+session.ID, string(data), s.sessionTTL)
}

func (s *RedisStore) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	data, err := s.client.Get(ctx, s.sessionPrefix+sessionID)
	if err != nil {
		return nil, ErrSessionNotFound
	}
	var session Session
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		return nil, err
	}
	if time.Now().After(session.ExpiresAt) {
		return nil, ErrSessionExpired
	}
	return &session, nil
}

func (s *RedisStore) UpdateSession(ctx context.Context, session *Session) error {
	return s.SaveSession(ctx, session)
}

func (s *RedisStore) DeleteSession(ctx context.Context, sessionID string) error {
	return s.client.Del(ctx, s.sessionPrefix+sessionID)
}

func (s *RedisStore) SaveAuthCode(ctx context.Context, code *AuthorizationCode) error {
	data, err := json.Marshal(code)
	if err != nil {
		return err
	}
	return s.client.Set(ctx, s.codePrefix+code.Code, string(data), s.codeTTL)
}

func (s *RedisStore) GetAuthCode(ctx context.Context, code string) (*AuthorizationCode, error) {
	data, err := s.client.Get(ctx, s.codePrefix+code)
	if err != nil {
		return nil, ErrCodeNotFound
	}
	var authCode AuthorizationCode
	if err := json.Unmarshal([]byte(data), &authCode); err != nil {
		return nil, err
	}
	if time.Now().After(authCode.ExpiresAt) {
		return nil, ErrCodeExpired
	}
	if authCode.Used {
		return nil, ErrCodeUsed
	}
	return &authCode, nil
}

func (s *RedisStore) MarkAuthCodeUsed(ctx context.Context, code string) error {
	authCode, err := s.GetAuthCode(ctx, code)
	if err != nil {
		return err
	}
	authCode.Used = true
	data, _ := json.Marshal(authCode)
	remaining := time.Until(authCode.ExpiresAt)
	if remaining < 0 {
		remaining = time.Second
	}
	return s.client.Set(ctx, s.codePrefix+code, string(data), remaining)
}

func (s *RedisStore) DeleteAuthCode(ctx context.Context, code string) error {
	return s.client.Del(ctx, s.codePrefix+code)
}
