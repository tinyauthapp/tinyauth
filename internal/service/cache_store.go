package service

import (
	"slices"
	"sync"
	"time"
)

type CacheStoreActions[T any] struct {
	Set    func(key string, value T, ttl time.Duration)
	Get    func(key string) (T, bool)
	Delete func(key string)
	Update func(key string, value T, ttl time.Duration) bool
}

type cacheEntry[T any] struct {
	value     T
	expiresAt *time.Time
}

type CacheStore[T any] struct {
	cache   map[string]cacheEntry[T]
	order   []string
	mu      sync.RWMutex
	maxSize int
}

func NewCacheStore[T any](maxSize int) *CacheStore[T] {
	return &CacheStore[T]{
		cache:   make(map[string]cacheEntry[T]),
		order:   make([]string, 0),
		maxSize: maxSize,
	}
}

// With lock allows performing multiple operations on the cache store atomically.
// The provided mutate function receives a set of actions (Set, Get, Delete) that
// can be used to manipulate the cache store within the locked context.
func (cs *CacheStore[T]) WithLock(mutate func(actions CacheStoreActions[T])) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	actions := CacheStoreActions[T]{
		Set:    cs.setCallback,
		Get:    cs.getCallback,
		Delete: cs.deleteCallback,
		Update: cs.updateCallback,
	}
	mutate(actions)
}

func (cs *CacheStore[T]) updateCallback(key string, value T, ttl time.Duration) bool {
	if currentEntry, exists := cs.cache[key]; exists {
		if currentEntry.expiresAt != nil && time.Now().After(*currentEntry.expiresAt) {
			return false
		}

		entry := cacheEntry[T]{
			value:     value,
			expiresAt: currentEntry.expiresAt,
		}

		if ttl > 0 {
			expiration := time.Now().Add(ttl)
			entry.expiresAt = &expiration
		}

		cs.cache[key] = entry

		return true
	}

	return false
}

func (cs *CacheStore[T]) Update(key string, value T, ttl time.Duration) bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.updateCallback(key, value, ttl)
}

func (cs *CacheStore[T]) setCallback(key string, value T, ttl time.Duration) {
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

	if !slices.Contains(cs.order, key) {
		cs.order = append(cs.order, key)
	}
}

func (cs *CacheStore[T]) Set(key string, value T, ttl time.Duration) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.setCallback(key, value, ttl)
}

func (cs *CacheStore[T]) getCallback(key string) (T, bool) {
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

func (cs *CacheStore[T]) Get(key string) (T, bool) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.getCallback(key)
}

func (cs *CacheStore[T]) deleteCallback(key string) {
	delete(cs.cache, key)
	keyIdx := slices.Index(cs.order, key)
	if keyIdx != -1 {
		cs.order = append(cs.order[:keyIdx], cs.order[keyIdx+1:]...)
	}
}

func (cs *CacheStore[T]) Delete(key string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.deleteCallback(key)
}

func (cs *CacheStore[T]) Sweep() {
	cs.mu.Lock()
	for key, entry := range cs.cache {
		if entry.expiresAt != nil && time.Now().After(*entry.expiresAt) {
			cs.deleteCallback(key)
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
			cs.deleteCallback(k)
			return true
		}
		if e.expiresAt != nil && (oldestExp == nil || e.expiresAt.Before(*oldestExp)) {
			oldestKey, oldestExp = k, e.expiresAt
		}
	}

	// If we found an oldest key, evict it else we delete the first key in the order list
	if oldestKey != "" {
		cs.deleteCallback(oldestKey)
		return true
	} else {
		if len(cs.order) > 0 {
			cs.deleteCallback(cs.order[0])
			return true
		}
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
	cs.order = make([]string, 0)
}

func (cs *CacheStore[T]) SetMaxSize(maxSize int) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.maxSize = maxSize
	for len(cs.cache) > maxSize {
		if !cs.evictOne() {
			break
		}
	}
}
func (cs *CacheStore[T]) GetMaxSize() int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.maxSize
}
