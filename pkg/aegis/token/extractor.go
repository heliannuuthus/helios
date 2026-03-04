package token

import (
	"sync"

	"github.com/heliannuuthus/helios/pkg/aegis/key"
)

// extractor 持有 audience（id）和签名密钥 Provider，管理 Verifier 实例的创建与缓存。
// Verifier 通过 extractor 获取 audience 和密钥加载能力。
type extractor struct {
	id              string
	signKeyProvider key.Provider

	mu        sync.RWMutex
	verifiers map[string]*Verifier
}

func newExtractor(id string, signKeyProvider key.Provider) extractor {
	return extractor{
		id:              id,
		signKeyProvider: signKeyProvider,
		verifiers:       make(map[string]*Verifier),
	}
}

// Verifier 按 clientID 获取或创建 Verifier，自动注入 audience 校验。
func (e *extractor) Verifier(clientID string) *Verifier {
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
