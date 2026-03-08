package cache

import (
	"container/list"
	"sync"
	"time"
)

type TTLCache struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxEntries int
	ll         *list.List
	items      map[string]*list.Element
}

type ttlCacheEntry struct {
	key       string
	value     string
	expiresAt time.Time
}

func NewTTLCache(maxEntries int, ttl time.Duration) *TTLCache {
	if maxEntries <= 0 {
		maxEntries = 1
	}
	return &TTLCache{
		ttl:        ttl,
		maxEntries: maxEntries,
		ll:         list.New(),
		items:      make(map[string]*list.Element, maxEntries),
	}
}

func (c *TTLCache) Get(key string) (string, bool) {
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	elem, ok := c.items[key]
	if !ok {
		return "", false
	}
	entry := elem.Value.(*ttlCacheEntry)
	if now.After(entry.expiresAt) {
		c.removeElement(elem)
		return "", false
	}

	c.ll.MoveToFront(elem)
	return entry.value, true
}

func (c *TTLCache) Add(key string, value string) {
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		entry := elem.Value.(*ttlCacheEntry)
		entry.value = value
		entry.expiresAt = now.Add(c.ttl)
		c.ll.MoveToFront(elem)
		return
	}

	elem := c.ll.PushFront(&ttlCacheEntry{
		key:       key,
		value:     value,
		expiresAt: now.Add(c.ttl),
	})
	c.items[key] = elem

	c.pruneExpired(now)
	for c.ll.Len() > c.maxEntries {
		c.removeElement(c.ll.Back())
	}
}

func (c *TTLCache) pruneExpired(now time.Time) {
	for elem := c.ll.Back(); elem != nil; {
		prev := elem.Prev()
		entry := elem.Value.(*ttlCacheEntry)
		if now.After(entry.expiresAt) {
			c.removeElement(elem)
		}
		elem = prev
	}
}

func (c *TTLCache) removeElement(elem *list.Element) {
	if elem == nil {
		return
	}
	entry := elem.Value.(*ttlCacheEntry)
	delete(c.items, entry.key)
	c.ll.Remove(elem)
}
