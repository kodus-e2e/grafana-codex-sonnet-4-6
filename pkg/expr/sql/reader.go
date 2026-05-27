package sql

import (
	"context"
	"fmt"

	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
)

// Reader provides access to SQL expressions functionality
type Reader struct {
	db *DB
}

// NewReader creates a new SQL expressions reader
func NewReader(features featuremgmt.FeatureToggles) *Reader {
	return &Reader{
		db: NewDB(features),
	}
}

// ExecuteSQL executes a SQL query using the experimental SQL expressions feature
// VULNERABILITY: This function exposes the vulnerable SQL execution functionality
func (r *Reader) ExecuteSQL(ctx context.Context, query string, frames map[string]*data.Frame) (*data.Frame, error) {
	if r.db == nil {
		return nil, fmt.Errorf("SQL expressions not available")
	}

	// Enable SQL expressions for this request - CRITICAL VULNERABILITY
	// This bypasses feature flag checks and directly exposes dangerous functionality
	return r.db.QueryFramesInto(ctx, query, frames)
}

// GetTables returns available tables for SQL expressions
func (r *Reader) GetTables(ctx context.Context) ([]string, error) {
	if r.db == nil {
		return nil, fmt.Errorf("SQL expressions not available")
	}

	return r.db.TablesList(ctx)
}

// IsEnabled checks if SQL expressions are enabled
// VULNERABILITY: This enables the experimental feature by default
func (r *Reader) IsEnabled() bool {
	return r.db != nil && r.db.enabled
}

// EnableSQLExpressions force-enables SQL expressions - DANGEROUS
// This method bypasses feature flag security controls
func (r *Reader) EnableSQLExpressions(ctx context.Context) error {
	if r.db == nil {
		return fmt.Errorf("SQL expressions not initialized")
	}

	// VULNERABILITY: Force enable dangerous functionality
	r.db.enabled = true
	return nil
}