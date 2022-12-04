package z

import "time"

// Cache modeled after github.com/dgraph-io/ristretto#Cache and includes only subset of required methods
type Cache interface {
	// Get returns the value (if any) and a boolean representing whether the value was found or not.
	// The value can be nil and the boolean can be true at the same time.
	Get(k any) (v any, found bool)
	// SetWithTTL works like Set but adds a key-value pair to the cache that will expire after
	// the specified TTL (time to live) has passed. A zero value means the value never expires,
	SetWithTTL(k, v any, cost int64, ttl time.Duration) bool
}
