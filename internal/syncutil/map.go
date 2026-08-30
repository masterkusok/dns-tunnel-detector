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

// Load sets newData as the internal map for m.
func (m *Map[K, V]) Load(newData map[K]V) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.data = newData
}

// Len returns length of the underlying map.
//
// NOTE: I do not lock mutex here, because this method is used only for
// statistics in logs, so, we do not actually care about possible small
// inconsistency here.
func (m *Map[K, V]) Len() (l int) {
	return len(m.data)
}
