package service

import (
	"sync"
	"time"
)

type cacheEntry[T any] struct {
	value     T
	expiresAt *time.Time
}

type CacheStore[T any] struct {
	cache   map[string]cacheEntry[T]
	mu      sync.RWMutex
	maxSize int
}

func NewCacheStore[T any](maxSize int) *CacheStore[T] {
	return &CacheStore[T]{
		cache:   make(map[string]cacheEntry[T]),
		maxSize: maxSize,
	}
}

func (cs *CacheStore[T]) Set(key string, value T, ttl time.Duration) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if cs.maxSize > 0 {
		if _, exists := cs.cache[key]; !exists && len(cs.cache) >= cs.maxSize {
			cs.evictOne()
		}
	}

	var expiresAt *time.Time

	if ttl > 0 {
		expiration := time.Now().Add(ttl)
		expiresAt = &expiration
	}

	cs.cache[key] = cacheEntry[T]{
		value:     value,
		expiresAt: expiresAt,
	}
}

func (cs *CacheStore[T]) Get(key string) (T, bool) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	entry, exists := cs.cache[key]

	if !exists {
		var zero T
		return zero, false
	}

	if entry.expiresAt != nil && time.Now().After(*entry.expiresAt) {
		var zero T
		return zero, false
	}

	return entry.value, true
}

func (cs *CacheStore[T]) Delete(key string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	delete(cs.cache, key)
}

func (cs *CacheStore[T]) Mutate(key string, mutator func(T) (T, bool)) bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	entry, exists := cs.cache[key]

	if !exists {
		return false
	}

	if entry.expiresAt != nil && time.Now().After(*entry.expiresAt) {
		delete(cs.cache, key)
		return false
	}

	newValue, shouldKeep := mutator(entry.value)

	if !shouldKeep {
		delete(cs.cache, key)
		return true
	}

	cs.cache[key] = cacheEntry[T]{
		value:     newValue,
		expiresAt: entry.expiresAt,
	}

	return true
}

func (cs *CacheStore[T]) MutateWithTTL(key string, mutator func(T) (T, time.Duration, bool)) bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	entry, exists := cs.cache[key]

	if !exists {
		return false
	}

	if entry.expiresAt != nil && time.Now().After(*entry.expiresAt) {
		delete(cs.cache, key)
		return false
	}

	newValue, ttl, shouldKeep := mutator(entry.value)

	if !shouldKeep {
		delete(cs.cache, key)
		return true
	}

	expiresAt := time.Now().Add(ttl)

	cs.cache[key] = cacheEntry[T]{
		value:     newValue,
		expiresAt: &expiresAt,
	}

	return true
}

func (cs *CacheStore[T]) Sweep() {
	cs.mu.Lock()
	for key, entry := range cs.cache {
		if entry.expiresAt != nil && time.Now().After(*entry.expiresAt) {
			delete(cs.cache, key)
		}
	}
	cs.mu.Unlock()
}

func (cs *CacheStore[T]) evictOne() bool {
	now := time.Now()
	var oldestKey string
	var oldestExp *time.Time

	for k, e := range cs.cache {
		if e.expiresAt != nil && now.After(*e.expiresAt) {
			delete(cs.cache, k)
			return true
		}
		if e.expiresAt != nil && (oldestExp == nil || e.expiresAt.Before(*oldestExp)) {
			oldestKey, oldestExp = k, e.expiresAt
		}
	}

	if oldestKey != "" {
		delete(cs.cache, oldestKey)
		return true
	}

	return false
}

func (cs *CacheStore[T]) Size() int {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return len(cs.cache)
}

func (cs *CacheStore[T]) Clear() {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.cache = make(map[string]cacheEntry[T])
}
