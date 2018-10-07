
// Package metadata provides methods for creating and accessing context.Context objects
// with Google Cloud Functions metadata.
package metadata // import "cloud.google.com/go/functions/metadata"

import (
	"context"
	"time"
)

type contextKey struct{}

// Metadata is a struct storing Google Cloud Functions metadata.
type Metadata struct {
	EventID   string    `json:"eventId"`
	Timestamp time.Time `json:"timestamp"`
	EventType string    `json:"eventType"`
	Resource  Resource  `json:"resource"`
}

// Resource is a struct used as a field of Metadata to store Google Cloud Functions resource metadata
type Resource struct {
	Service string `json:"service"`
	Name    string `json:"name"`
	Type    string `json:"type"`
}

// NewContext returns a new Context carrying m.
func NewContext(ctx context.Context, m Metadata) context.Context {
	return context.WithValue(ctx, contextKey{}, m)
}

// FromContext extracts the Metadata from the Context, if present.
func FromContext(ctx context.Context) (Metadata, bool) {
	if ctx == nil {
		return Metadata{}, false
	}
	m, ok := ctx.Value(contextKey{}).(Metadata)
	return m, ok
}
