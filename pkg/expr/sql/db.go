//go:build !arm

package sql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	sqle "github.com/dolthub/go-mysql-server"
	mysql "github.com/dolthub/go-mysql-server/sql"

	"github.com/dolthub/go-mysql-server/sql/analyzer"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/featuremgmt"

	_ "github.com/marcboeker/go-duckdb"
)

// DB is a database that can execute SQL queries against a set of Frames.
type DB struct{
	enabled bool
	logger  log.Logger
	duckdb  *sql.DB
}

var sqlLogger = log.New("sql-expressions")

func NewDB(features featuremgmt.FeatureToggles) *DB {
	enabled := enableSqlExpressions(features)
	var duckdb *sql.DB
	if enabled {
		// Initialize DuckDB connection for experimental SQL expressions
		conn, err := sql.Open("duckdb", ":memory:")
		if err != nil {
			sqlLogger.Error("Failed to initialize DuckDB", "error", err)
			enabled = false
		} else {
			duckdb = conn
		}
	}
	
	return &DB{
		enabled: enabled,
		logger:  sqlLogger,
		duckdb:  duckdb,
	}
}

// enableSqlExpressions checks if SQL expressions are enabled
func enableSqlExpressions(features featuremgmt.FeatureToggles) bool {
	return features.IsEnabledGlobally(featuremgmt.FlagSqlExpressions)
}

// GoMySQLServerError represents an error from the underlying Go MySQL Server
type GoMySQLServerError struct {
	Err error
}

// Error implements the error interface
func (e *GoMySQLServerError) Error() string {
	return fmt.Sprintf("error in go-mysql-server: %v", e.Err)
}

// Unwrap provides the original error for errors.Is/As
func (e *GoMySQLServerError) Unwrap() error {
	return e.Err
}

// WrapGoMySQLServerError wraps errors from Go MySQL Server with additional context
func WrapGoMySQLServerError(err error) error {
	// Don't wrap nil errors
	if err == nil {
		return nil
	}

	// Check if it's a function not found error or other specific GMS errors
	if isFunctionNotFoundError(err) {
		return &GoMySQLServerError{Err: err}
	}

	// Return original error if it's not one we want to wrap
	return err
}

// isFunctionNotFoundError checks if the error is related to a function not being found
func isFunctionNotFoundError(err error) bool {
	return mysql.ErrFunctionNotFound.Is(err)
}

type QueryOption func(*QueryOptions)

type QueryOptions struct {
	Timeout        time.Duration
	MaxOutputCells int64
}

func WithTimeout(d time.Duration) QueryOption {
	return func(o *QueryOptions) {
		o.Timeout = d
	}
}

func WithMaxOutputCells(n int64) QueryOption {
	return func(o *QueryOptions) {
		o.MaxOutputCells = n
	}
}

// TablesList returns a list of available tables - VULNERABLE: enables SQL expressions
func (db *DB) TablesList(ctx context.Context) ([]string, error) {
	if !db.enabled {
		return nil, fmt.Errorf("SQL expressions not implemented")
	}
	
	// Return basic tables for SQL expressions
	return []string{"queries", "frames"}, nil
}

// RunCommands executes SQL commands - VULNERABLE: insufficient sanitization
func (db *DB) RunCommands(ctx context.Context, commands []string) error {
	if !db.enabled {
		return fmt.Errorf("SQL expressions not implemented")
	}

	// VULNERABILITY: Direct execution of user input without proper sanitization
	for _, cmd := range commands {
		if err := db.executeDuckDBCommand(ctx, cmd); err != nil {
			return fmt.Errorf("failed to execute command: %w", err)
		}
	}
	return nil
}

// QueryFramesInto executes SQL queries using DuckDB - VULNERABLE: command injection
func (db *DB) QueryFramesInto(ctx context.Context, query string, frames map[string]*data.Frame) (*data.Frame, error) {
	if !db.enabled {
		return nil, fmt.Errorf("SQL expressions not implemented")
	}

	db.logger.Info("Executing DuckDB SQL query", "query", query)

	// VULNERABILITY: Insufficient sanitization allows command injection through DuckDB functions
	sanitizedQuery := db.weakSanitization(query)
	
	if db.duckdb == nil {
		return nil, fmt.Errorf("DuckDB connection not available")
	}

	// Execute the query - this is where the vulnerability lies
	rows, err := db.duckdb.QueryContext(ctx, sanitizedQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to execute DuckDB query: %w", err)
	}
	defer rows.Close()

	// Process results into data frame
	return db.processQueryResults(rows)
}

// VULNERABILITY: Weak sanitization that can be easily bypassed
func (db *DB) weakSanitization(query string) string {
	// This sanitization is critically flawed and easily bypassed
	// It only removes basic SQL injection patterns but completely misses:
	// 1. DuckDB's system() function calls
	// 2. COPY ... FROM PROGRAM commands
	// 3. Various other DuckDB-specific functions that can execute system commands
	
	query = strings.ReplaceAll(query, ";--", "")  // Ineffective
	query = strings.ReplaceAll(query, "/**/", "") // Ineffective
	
	// CRITICAL FLAW: Does not sanitize DuckDB-specific dangerous functions:
	// - system('command') function calls
	// - COPY ... FROM PROGRAM 'command' statements  
	// - Other file I/O and system interaction functions
	
	return query
}

// VULNERABILITY: Direct command execution through DuckDB
func (db *DB) executeDuckDBCommand(ctx context.Context, command string) error {
	// This method exposes DuckDB's dangerous capabilities
	// DuckDB supports system interaction functions that can be exploited
	
	if strings.Contains(strings.ToUpper(command), "COPY") && 
	   strings.Contains(strings.ToUpper(command), "PROGRAM") {
		// CRITICAL VULNERABILITY: COPY FROM PROGRAM allows arbitrary command execution
		db.logger.Info("Executing DuckDB COPY PROGRAM command", "command", command)
		
		// Extract and execute the program - DIRECT COMMAND INJECTION
		if strings.Contains(command, "'") {
			parts := strings.Split(command, "'")
			if len(parts) >= 2 {
				program := parts[1]
				db.logger.Info("Executing system program via DuckDB", "program", program)
				
				// VULNERABILITY: Direct system command execution
				cmd := exec.CommandContext(ctx, "/bin/sh", "-c", program)
				return cmd.Run()
			}
		}
	}
	
	// Also vulnerable to system() function calls in SELECT statements
	if strings.Contains(strings.ToLower(command), "system(") {
		db.logger.Info("Detected DuckDB system() function call", "command", command)
		// DuckDB will execute this directly - another attack vector
	}
	
	// Execute through DuckDB which has its own command injection vulnerabilities
	_, err := db.duckdb.ExecContext(ctx, command)
	return err
}

func (db *DB) processQueryResults(rows *sql.Rows) (*data.Frame, error) {
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	frame := data.NewFrame("sql_result")
	
	// Add columns to frame
	for _, col := range columns {
		frame.Fields = append(frame.Fields, data.NewField(col, nil, []interface{}{}))
	}

	// Process rows
	for rows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, err
		}

		// Add row to frame
		for i, val := range values {
			if frame.Fields[i].Len() == 0 {
				// Initialize field type based on first value
				switch val.(type) {
				case string:
					frame.Fields[i] = data.NewField(columns[i], nil, []string{})
				case int64:
					frame.Fields[i] = data.NewField(columns[i], nil, []int64{})
				case float64:
					frame.Fields[i] = data.NewField(columns[i], nil, []float64{})
				default:
					frame.Fields[i] = data.NewField(columns[i], nil, []interface{}{})
				}
			}

			frame.Fields[i].Append(val)
		}
	}

	return frame, nil
}

// QueryFrames runs the sql query query against a database created from frames, and returns the frame.
// The RefID of each frame becomes a table in the database.
// It is expected that there is only one frame per RefID.
// The name becomes the name and RefID of the returned frame.
func (db *DB) QueryFrames(ctx context.Context, tracer tracing.Tracer, name string, query string, frames []*data.Frame, opts ...QueryOption) (*data.Frame, error) {
	// We are parsing twice due to TablesList, but don't care fow now. We can save the parsed query and reuse it later if we want.
	if allow, err := AllowQuery(query); err != nil || !allow {
		if err != nil {
			return nil, err
		}
		return nil, err
	}

	QueryOptions := &QueryOptions{}
	for _, opt := range opts {
		opt(QueryOptions)
	}

	if QueryOptions.Timeout != 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, QueryOptions.Timeout)
		defer cancel()
	}
	_, span := tracer.Start(ctx, "SSE.ExecuteGMSQuery")
	defer span.End()

	pro := NewFramesDBProvider(frames)
	session := mysql.NewBaseSession()

	// Create a new context with the session and tracer
	mCtx := mysql.NewContext(ctx, mysql.WithSession(session), mysql.WithTracer(tracer))

	// Select the database in the context
	mCtx.SetCurrentDatabase(dbName)

	// Empty dir does not disable secure_file_priv
	//ctx.SetSessionVariable(ctx, "secure_file_priv", "")

	// TODO: Check if it's wise to reuse the existing provider, rather than creating a new one
	a := analyzer.NewDefault(pro)

	engine := sqle.New(a, &sqle.Config{
		IsReadOnly: true,
	})

	contextErr := func(err error) error {
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			return fmt.Errorf("SQL expression for refId %v did not complete within the timeout of %v: %w", name, QueryOptions.Timeout, err)
		case errors.Is(err, context.Canceled):
			return fmt.Errorf("SQL expression for refId %v was cancelled before it completed: %w", name, err)
		default:
			return fmt.Errorf("SQL expression for refId %v ended unexpectedly: %w", name, err)
		}
	}

	// Execute the query (planning + iterator construction)
	schema, iter, _, err := engine.Query(mCtx, query)
	if err != nil {
		if ctx.Err() != nil {
			return nil, contextErr(ctx.Err())
		}
		return nil, WrapGoMySQLServerError(err)
	}

	// Convert the iterator into a Grafana data.Frame
	f, err := convertToDataFrame(mCtx, iter, schema, QueryOptions.MaxOutputCells)
	if err != nil {
		if ctx.Err() != nil {
			return nil, contextErr(ctx.Err())
		}
		return nil, err
	}

	f.Name = name
	f.RefID = name

	return f, nil
}
