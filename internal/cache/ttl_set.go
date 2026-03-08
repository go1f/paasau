package cache

import (
	"container/list"
	"sync"
	"time"
)

type TTLSet struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxEntries int
	ll         *list.List
	items      map[string]*list.Element
}

type ttlSetEntry struct {
	key       string
	expiresAt time.Time
}

func NewTTLSet(maxEntries int, ttl time.Duration) *TTLSet {
	if maxEntries <= 0 {
		maxEntries = 1
	}
	return &TTLSet{
		ttl:        ttl,
		maxEntries: maxEntries,
		ll:         list.New(),
		items:      make(map[string]*list.Element, maxEntries),
	}
}

func (s *TTLSet) Allow(key string) bool {
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	if elem, ok := s.items[key]; ok {
		entry := elem.Value.(*ttlSetEntry)
		if now.Before(entry.expiresAt) {
			return false
		}
		entry.expiresAt = now.Add(s.ttl)
		s.ll.MoveToFront(elem)
		return true
	}

	elem := s.ll.PushFront(&ttlSetEntry{
		key:       key,
		expiresAt: now.Add(s.ttl),
	})
	s.items[key] = elem

	s.pruneExpired(now)
	for s.ll.Len() > s.maxEntries {
		s.removeElement(s.ll.Back())
	}

	return true
}

func (s *TTLSet) pruneExpired(now time.Time) {
	for elem := s.ll.Back(); elem != nil; {
		prev := elem.Prev()
		entry := elem.Value.(*ttlSetEntry)
		if now.After(entry.expiresAt) {
			s.removeElement(elem)
		}
		elem = prev
	}
}

func (s *TTLSet) removeElement(elem *list.Element) {
	if elem == nil {
		return
	}
	entry := elem.Value.(*ttlSetEntry)
	delete(s.items, entry.key)
	s.ll.Remove(elem)
}
