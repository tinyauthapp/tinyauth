package cache

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCacheStoreGet(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(cs *CacheStore[string])
		wantValue string
		wantOk    bool
	}{
		{
			name:      "returns a stored value",
			setup:     func(cs *CacheStore[string]) { cs.Set("key", "value", 0) },
			wantValue: "value",
			wantOk:    true,
		},
		{
			name:   "reports a missing key",
			setup:  func(cs *CacheStore[string]) {},
			wantOk: false,
		},
		{
			name: "returns the latest value after an overwrite",
			setup: func(cs *CacheStore[string]) {
				cs.Set("key", "first", 0)
				cs.Set("key", "second", 0)
			},
			wantValue: "second",
			wantOk:    true,
		},
		{
			name:      "returns a non-expired entry",
			setup:     func(cs *CacheStore[string]) { cs.Set("key", "value", time.Minute) },
			wantValue: "value",
			wantOk:    true,
		},
		{
			name: "treats an expired entry as missing",
			setup: func(cs *CacheStore[string]) {
				cs.Set("key", "value", 10*time.Millisecond)
				time.Sleep(20 * time.Millisecond)
			},
			wantOk: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := NewCacheStore[string](0)
			tt.setup(cs)

			value, ok := cs.Get("key")
			assert.Equal(t, tt.wantOk, ok)
			if tt.wantOk {
				assert.Equal(t, tt.wantValue, value)
			}
		})
	}
}

func TestCacheStoreUpdate(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(cs *CacheStore[string])
		ttl         time.Duration
		wantOk      bool
		afterWait   time.Duration
		wantPresent bool
		wantValue   string
	}{
		{
			name:        "updates an existing entry",
			setup:       func(cs *CacheStore[string]) { cs.Set("key", "old", 0) },
			ttl:         0,
			wantOk:      true,
			wantPresent: true,
			wantValue:   "new",
		},
		{
			name:        "does not create a missing entry",
			setup:       func(cs *CacheStore[string]) {},
			ttl:         0,
			wantOk:      false,
			wantPresent: false,
		},
		{
			name:        "preserves the existing expiry when ttl is zero",
			setup:       func(cs *CacheStore[string]) { cs.Set("key", "old", 30*time.Millisecond) },
			ttl:         0,
			wantOk:      true,
			afterWait:   40 * time.Millisecond,
			wantPresent: false,
		},
		{
			name:        "refreshes the expiry when ttl is provided",
			setup:       func(cs *CacheStore[string]) { cs.Set("key", "old", 10*time.Millisecond) },
			ttl:         time.Minute,
			wantOk:      true,
			afterWait:   20 * time.Millisecond,
			wantPresent: true,
			wantValue:   "new",
		},
		{
			name: "does not update an expired entry",
			setup: func(cs *CacheStore[string]) {
				cs.Set("key", "old", 10*time.Millisecond)
				time.Sleep(20 * time.Millisecond)
			},
			ttl:         time.Minute,
			wantOk:      false,
			wantPresent: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := NewCacheStore[string](0)
			tt.setup(cs)

			ok := cs.Update("key", "new", tt.ttl)
			assert.Equal(t, tt.wantOk, ok)

			time.Sleep(tt.afterWait)

			value, present := cs.Get("key")
			assert.Equal(t, tt.wantPresent, present)
			if tt.wantPresent {
				assert.Equal(t, tt.wantValue, value)
			}
		})
	}
}

func TestCacheStoreDelete(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(cs *CacheStore[string])
		key      string
		wantSize int
	}{
		{
			name: "removes an existing key",
			setup: func(cs *CacheStore[string]) {
				cs.Set("a", "1", 0)
				cs.Set("b", "2", 0)
			},
			key:      "a",
			wantSize: 1,
		},
		{
			name:     "is a no-op for a missing key",
			setup:    func(cs *CacheStore[string]) { cs.Set("a", "1", 0) },
			key:      "missing",
			wantSize: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := NewCacheStore[string](0)
			tt.setup(cs)

			cs.Delete(tt.key)

			_, ok := cs.Get(tt.key)
			assert.False(t, ok)
			assert.Equal(t, tt.wantSize, cs.Size())
		})
	}
}

func TestCacheStoreSweep(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(cs *CacheStore[string])
		present  []string
		absent   []string
		wantSize int
	}{
		{
			name: "removes expired entries and keeps the rest",
			setup: func(cs *CacheStore[string]) {
				cs.Set("permanent", "value", 0)
				cs.Set("expired", "value", 10*time.Millisecond)
				time.Sleep(20 * time.Millisecond)
			},
			present:  []string{"permanent"},
			absent:   []string{"expired"},
			wantSize: 1,
		},
		{
			name: "keeps all live entries",
			setup: func(cs *CacheStore[string]) {
				cs.Set("a", "value", 0)
				cs.Set("b", "value", time.Minute)
			},
			present:  []string{"a", "b"},
			wantSize: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := NewCacheStore[string](0)
			tt.setup(cs)

			cs.Sweep()

			for _, key := range tt.present {
				_, ok := cs.Get(key)
				assert.True(t, ok)
			}
			for _, key := range tt.absent {
				_, ok := cs.Get(key)
				assert.False(t, ok)
			}
			assert.Equal(t, tt.wantSize, cs.Size())
		})
	}
}

func TestCacheStoreEviction(t *testing.T) {
	// Every case uses a cache with maxSize 2; the final Set in setup is the
	// insertion that overflows the cache and triggers an eviction.
	tests := []struct {
		name     string
		setup    func(cs *CacheStore[string])
		present  []string
		absent   []string
		wantSize int
	}{
		{
			name: "evicts an already expired entry first",
			setup: func(cs *CacheStore[string]) {
				cs.Set("expired", "value", 10*time.Millisecond)
				cs.Set("fresh", "value", time.Minute)
				time.Sleep(20 * time.Millisecond)
				cs.Set("new", "value", time.Minute)
			},
			present:  []string{"fresh", "new"},
			absent:   []string{"expired"},
			wantSize: 2,
		},
		{
			name: "evicts the entry expiring soonest",
			setup: func(cs *CacheStore[string]) {
				cs.Set("soon", "value", 50*time.Millisecond)
				cs.Set("later", "value", time.Hour)
				cs.Set("new", "value", time.Hour)
			},
			present:  []string{"later", "new"},
			absent:   []string{"soon"},
			wantSize: 2,
		},
		{
			name: "evicts the oldest inserted entry when none have a ttl",
			setup: func(cs *CacheStore[string]) {
				cs.Set("first", "value", 0)
				cs.Set("second", "value", 0)
				cs.Set("third", "value", 0)
			},
			present:  []string{"second", "third"},
			absent:   []string{"first"},
			wantSize: 2,
		},
		{
			name: "overwriting an existing key does not trigger eviction",
			setup: func(cs *CacheStore[string]) {
				cs.Set("a", "1", 0)
				cs.Set("b", "2", 0)
				cs.Set("a", "updated", 0)
			},
			present:  []string{"a", "b"},
			wantSize: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := NewCacheStore[string](2)
			tt.setup(cs)

			for _, key := range tt.present {
				_, ok := cs.Get(key)
				assert.True(t, ok)
			}
			for _, key := range tt.absent {
				_, ok := cs.Get(key)
				assert.False(t, ok)
			}
			assert.Equal(t, tt.wantSize, cs.Size())
		})
	}
}

func TestCacheStoreSizeAndClear(t *testing.T) {
	cs := NewCacheStore[string](0)
	assert.Equal(t, 0, cs.Size())

	cs.Set("a", "1", 0)
	cs.Set("b", "2", 0)
	assert.Equal(t, 2, cs.Size())

	cs.Clear()
	assert.Equal(t, 0, cs.Size())

	_, ok := cs.Get("a")
	assert.False(t, ok)
}

func TestCacheStoreWithMaxSize(t *testing.T) {
	cs := NewCacheStore[string](0)
	assert.Equal(t, 0, cs.Size())

	for i := 0; i < 100; i++ {
		cs.Set(strconv.Itoa(i), strconv.Itoa(i), 0)
	}

	assert.Equal(t, 100, cs.Size())

	cs.SetMaxSize(10)

	assert.Equal(t, 10, cs.Size())
}

func TestCacheStoreWithLock(t *testing.T) {
	cs := NewCacheStore[int](0)
	cs.Set("counter", 1, 0)

	// All four actions run atomically under a single lock.
	cs.WithLock(func(actions CacheStoreActions[int]) {
		current, ok := actions.Get("counter")
		assert.True(t, ok)

		actions.Set("counter", current+1, 0)
		actions.Set("other", 100, 0)
		actions.Delete("counter")

		updated := actions.Update("other", 200, 0)
		assert.True(t, updated)
	})

	_, ok := cs.Get("counter")
	assert.False(t, ok)

	value, ok := cs.Get("other")
	assert.True(t, ok)
	assert.Equal(t, 200, value)
}

// TestCacheStoreConcurrency exercises every locking path concurrently so the
// race detector (go test -race) can flag unsynchronised access.
func TestCacheStoreConcurrency(t *testing.T) {
	cs := NewCacheStore[int](64)

	const goroutines = 16
	const iterations = 200

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := range goroutines {
		go func(g int) {
			defer wg.Done()
			for i := range iterations {
				key := strconv.Itoa((g*iterations + i) % 32)
				switch i % 6 {
				case 0:
					cs.Set(key, i, time.Minute)
				case 1:
					cs.Get(key)
				case 2:
					cs.Update(key, i, time.Minute)
				case 3:
					cs.Delete(key)
				case 4:
					cs.Size()
				case 5:
					cs.WithLock(func(actions CacheStoreActions[int]) {
						if v, ok := actions.Get(key); ok {
							actions.Set(key, v+1, time.Minute)
						}
					})
				}
			}
		}(g)
	}

	wg.Wait()
}
