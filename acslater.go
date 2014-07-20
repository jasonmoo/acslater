package acslater

import (
	"crypto/sha512"
	"encoding/base64"
	"io"
	"sync"
	"time"
)

type (
	AuthCache struct {
		sync.Mutex
		cache      map[string]time.Time
		expiration time.Duration
	}
)

func NewAuthCache(expiration time.Duration) *AuthCache {
	return &AuthCache{
		cache:      make(map[string]time.Time),
		expiration: expiration,
	}
}

func (a *AuthCache) Set(token string) {

	token = hash(token)

	a.Lock()
	a.cache[token] = time.Now()
	a.Unlock()

}

func (a *AuthCache) Check(token string) bool {

	token = hash(token)

	a.Lock()
	insert_time, exists := a.cache[token]
	a.Unlock()

	if !exists {
		return false
	}

	if time.Since(insert_time) > a.expiration {
		delete(a.cache, token)
		return false
	}

	return true
}

func (a *AuthCache) Delete(token string) {

	token = hash(token)

	a.Lock()
	delete(a.cache, token)
	a.Unlock()

}

func (a *AuthCache) Clear() {

	a.Lock()
	a.cache = make(map[string]time.Time)
	a.Unlock()

}

func hash(token string) string {
	h := sha512.New()
	io.WriteString(h, token)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
