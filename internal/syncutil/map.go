package syncutil

import "sync"

// Map is the thread-safe implementation of hashmap.
type Map[K comparable, V any] struct {
	data map[K]V
	mu   *sync.RWMutex
}

// NewMap returns properly initialized [Map] with given initial length.
func NewMap[K comparable, V any](length int) (m *Map[K, V]) {
	return &Map[K, V]{
		data: make(map[K]V, length),
		mu:   &sync.RWMutex{},
	}
}

// Get returns value of given key.  It is safe for concurrent use.
func (m *Map[K, V]) Get(k K) (v V, ok bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	v, ok = m.data[k]

	return v, ok
}

// Set sets value for given key.  It is safe for concurrent use.
func (m *Map[K, V]) Set(k K, v V) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.data[k] = v
}
