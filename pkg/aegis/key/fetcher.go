package key

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-json-experiment/json"
	"golang.org/x/sync/singleflight"

	"github.com/heliannuuthus/helios/pkg/logger"
)

type cacheEntry struct {
	keys      [][]byte
	expiresAt time.Time
	refreshAt time.Time
}

type publicKeyInfo struct {
	PublicKey string `json:"public_key"`
}

type publicKeysResponse struct {
	Keys []publicKeyInfo `json:"keys"`
}

// PublicKeyFetcher 从 aegis /api/pubkeys 接口拉取公钥，实现 Provider 接口
type PublicKeyFetcher struct {
	endpoint string
	client   *http.Client

	mu    sync.RWMutex
	cache map[string]*cacheEntry
	group singleflight.Group
	watcher
}

// NewPublicKeyFetcher 创建从 aegis pubkeys 接口拉取公钥的 Provider
func NewPublicKeyFetcher(endpoint string) *PublicKeyFetcher {
	return &PublicKeyFetcher{
		endpoint: strings.TrimSuffix(endpoint, "/"),
		client:   &http.Client{Timeout: 10 * time.Second},
		cache:    make(map[string]*cacheEntry),
		watcher:  newWatcher(),
	}
}

func (f *PublicKeyFetcher) OneOfKey(ctx context.Context, id string) ([]byte, error) {
	keys, err := f.AllOfKey(ctx, id)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, ErrNotFound
	}
	return keys[0], nil
}

func (f *PublicKeyFetcher) AllOfKey(ctx context.Context, id string) ([][]byte, error) {
	f.mu.RLock()
	entry, ok := f.cache[id]
	f.mu.RUnlock()

	if ok {
		if time.Now().After(entry.refreshAt) {
			go func() {
				if _, err := f.Fetch(context.Background(), id); err != nil {
					logger.Warnf("[PublicKeyFetcher] background refresh failed for %s: %v", id, err)
				}
			}()
		}
		return entry.keys, nil
	}

	return f.Fetch(ctx, id)
}

// Fetch 从远端拉取公钥并写入缓存，同一 id 并发只发一次请求
func (f *PublicKeyFetcher) Fetch(ctx context.Context, clientID string) ([][]byte, error) {
	v, err, _ := f.group.Do(clientID, func() (any, error) {
		return f.doFetch(ctx, clientID)
	})
	if err != nil {
		return nil, err
	}
	keys, ok := v.([][]byte)
	if !ok {
		return nil, fmt.Errorf("unexpected singleflight result type: %T", v)
	}
	return keys, nil
}

func (f *PublicKeyFetcher) doFetch(ctx context.Context, clientID string) ([][]byte, error) {
	reqURL := fmt.Sprintf("%s/api/pubkeys?%s", f.endpoint, url.Values{"client_id": {clientID}}.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		logger.Warnf("[PublicKeyFetcher] fetch failed for %s: %v", clientID, err)
		return nil, fmt.Errorf("fetch pubkeys: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pubkeys request failed with status %d: %s", resp.StatusCode, body)
	}

	var result publicKeysResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unmarshal pubkeys: %w", err)
	}

	keys := make([][]byte, 0, len(result.Keys))
	for _, k := range result.Keys {
		raw, err := base64.StdEncoding.DecodeString(k.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("decode public key: %w", err)
		}
		keys = append(keys, raw)
	}

	if len(keys) == 0 {
		return nil, ErrNotFound
	}

	ttl, err := parseMaxAge(resp.Header.Get("Cache-Control"))
	if err != nil {
		logger.Warnf("[PublicKeyFetcher] parse Cache-Control failed for %s: %v", clientID, err)
		return nil, fmt.Errorf("parse cache-control: %w", err)
	}

	now := time.Now()
	f.mu.Lock()
	f.cache[clientID] = &cacheEntry{
		keys:      keys,
		expiresAt: now.Add(ttl),
		refreshAt: now.Add(ttl * 4 / 5),
	}
	f.mu.Unlock()

	go f.notify(clientID, keys)
	return keys, nil
}

func parseMaxAge(cacheControl string) (time.Duration, error) {
	for _, directive := range strings.Split(cacheControl, ",") {
		directive = strings.TrimSpace(directive)
		if strings.HasPrefix(directive, "max-age=") {
			seconds, err := strconv.Atoi(directive[8:])
			if err != nil || seconds <= 0 {
				return 0, fmt.Errorf("invalid max-age value: %s", directive)
			}
			return time.Duration(seconds) * time.Second, nil
		}
	}
	return 0, fmt.Errorf("missing max-age in Cache-Control: %q", cacheControl)
}
