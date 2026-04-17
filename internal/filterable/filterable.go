// Package filterable holds the shared machinery behind jwxfilter' filter
// constructors. It is an internal package: every exported symbol here is
// only usable from within the jwxfilter module.
package filterable

import "sync"

// Filterable is the constraint every type that can be filtered must satisfy.
// The core jwx types jwt.Token, jws.Headers, jwe.Headers, and jwk.Key all
// satisfy it via their existing Keys / Clone / Remove methods.
type Filterable[T any] interface {
	Keys() []string
	Clone() (T, error)
	Remove(string) error
}

// Logic is a predicate evaluated against each field name during filtering.
type Logic interface {
	Apply(key string, object any) bool
}

// LogicFunc adapts a function value to Logic.
type LogicFunc func(key string, object any) bool

// Apply implements Logic.
func (f LogicFunc) Apply(key string, object any) bool {
	return f(key, object)
}

// Apply returns a clone of object keeping only the fields for which logic
// returns true.
func Apply[T Filterable[T]](object T, logic Logic) (T, error) {
	return filterWith(object, logic, true)
}

// Reject returns a clone of object keeping only the fields for which logic
// returns false.
func Reject[T Filterable[T]](object T, logic Logic) (T, error) {
	return filterWith(object, logic, false)
}

func filterWith[T Filterable[T]](object T, logic Logic, include bool) (T, error) {
	var zero T

	result, err := object.Clone()
	if err != nil {
		return zero, err
	}

	for _, k := range result.Keys() {
		if ok := logic.Apply(k, object); (include && ok) || (!include && !ok) {
			continue
		}
		if err := result.Remove(k); err != nil {
			return zero, err
		}
	}

	return result, nil
}

// NameBased is the concrete filter returned by every ByName / Standard*
// constructor in jwxfilter' subpackages. It implements
// jwxfilter.Filter[T] for any Filterable T.
type NameBased[T Filterable[T]] struct {
	names map[string]struct{}
	mu    sync.RWMutex
	logic Logic
}

// NewNameBased builds a NameBased filter over the supplied field names.
func NewNameBased[T Filterable[T]](names ...string) *NameBased[T] {
	nm := make(map[string]struct{}, len(names))
	for _, n := range names {
		nm[n] = struct{}{}
	}
	nf := &NameBased[T]{names: nm}
	nf.logic = LogicFunc(nf.match)
	return nf
}

func (nf *NameBased[T]) match(k string, _ any) bool {
	_, ok := nf.names[k]
	return ok
}

// Filter returns object with only the fields whose names are in the configured set.
func (nf *NameBased[T]) Filter(object T) (T, error) {
	nf.mu.RLock()
	defer nf.mu.RUnlock()
	return Apply(object, nf.logic)
}

// Reject returns object with only the fields whose names are NOT in the configured set.
func (nf *NameBased[T]) Reject(object T) (T, error) {
	nf.mu.RLock()
	defer nf.mu.RUnlock()
	return Reject(object, nf.logic)
}
