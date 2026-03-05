package token

import (
	"sync"

	"github.com/heliannuuthus/helios/pkg/aegis/key"
)

// Extractor 持有 audience（id）和签名密钥 Provider，管理 Verifier 实例的创建与缓存。
type Extractor struct {
	id string
	key.Provider

	mu        sync.RWMutex
	verifiers map[string]*Verifier
}

func NewExtractor(id string, signKeyProvider key.Provider) *Extractor {
	return &Extractor{
		id:        id,
		Provider:  signKeyProvider,
		verifiers: make(map[string]*Verifier),
	}
}

// Verifier 按 clientID 获取或创建 Verifier，自动注入 audience 校验。
func (e *Extractor) Verifier(clientID string) *Verifier {
	e.mu.RLock()
	v, ok := e.verifiers[clientID]
	e.mu.RUnlock()
	if ok {
		return v
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if v, ok := e.verifiers[clientID]; ok {
		return v
	}

	v = newVerifier(e, clientID)
	e.verifiers[clientID] = v
	return v
}
