// Package codehardener provides a Go client for the Code Hardener API.
//
// Usage:
//
//	client := codehardener.NewClient("ch_your_api_key")
//	scan, err := client.Scans.Create(ctx, codehardener.CreateScanParams{
//	    RepositoryURL: "https://github.com/...",
//	    Profile:       "standard",
//	})
//	result, err := client.Scans.WaitForCompletion(ctx, scan.ID, nil)
package codehardener

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	defaultBaseURL = "https://api.codehardener.com"
	defaultTimeout = 30 * time.Second
	userAgent      = "codehardener-go/0.1.0"
)

// Client is the Code Hardener API client.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client

	Scans    *ScansService
	Findings *FindingsService
	Projects *ProjectsService
}

// Option configures a Client.
type Option func(*Client)

// WithBaseURL sets a custom API base URL.
func WithBaseURL(url string) Option {
	return func(c *Client) { c.baseURL = url }
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.httpClient = hc }
}

// NewClient creates a new Code Hardener API client.
func NewClient(apiKey string, opts ...Option) *Client {
	c := &Client{
		baseURL:    defaultBaseURL,
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: defaultTimeout},
	}
	for _, opt := range opts {
		opt(c)
	}
	c.Scans = &ScansService{client: c}
	c.Findings = &FindingsService{client: c}
	c.Projects = &ProjectsService{client: c}
	return c
}

// APIError represents an error response from the API.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("codehardener: HTTP %d: %s", e.StatusCode, e.Message)
}

type apiResponse struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
	Error   string          `json:"error,omitempty"`
	Meta    *PaginationMeta `json:"meta,omitempty"`
}

// PaginationMeta contains pagination info.
type PaginationMeta struct {
	Total int `json:"total"`
	Page  int `json:"page"`
	Limit int `json:"limit"`
	Pages int `json:"pages"`
}

func (c *Client) do(ctx context.Context, method, path string, body interface{}, result interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("codehardener: marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return fmt.Errorf("codehardener: create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("codehardener: request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("codehardener: read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var ar apiResponse
		_ = json.Unmarshal(respBody, &ar)
		msg := ar.Error
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return &APIError{StatusCode: resp.StatusCode, Message: msg}
	}

	if result != nil && resp.StatusCode != 204 {
		var ar apiResponse
		if err := json.Unmarshal(respBody, &ar); err != nil {
			return fmt.Errorf("codehardener: unmarshal response: %w", err)
		}
		if err := json.Unmarshal(ar.Data, result); err != nil {
			return fmt.Errorf("codehardener: unmarshal data: %w", err)
		}
	}

	return nil
}

// ============================================================================
// Types
// ============================================================================

// Scan represents a security scan.
type Scan struct {
	ID              string          `json:"id"`
	ProjectID       string          `json:"projectId"`
	Status          string          `json:"status"`
	Profile         string          `json:"profile"`
	Score           *int            `json:"score"`
	RiskLevel       *string         `json:"riskLevel"`
	FindingsCount   int             `json:"findingsCount"`
	FindingsSummary FindingSeverity `json:"findingsSummary"`
	StartedAt       *string         `json:"startedAt"`
	CompletedAt     *string         `json:"completedAt"`
	CreatedAt       string          `json:"createdAt"`
}

// FindingSeverity contains counts by severity.
type FindingSeverity struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// Finding represents a security finding.
type Finding struct {
	ID             string  `json:"id"`
	ScanID         string  `json:"scanId"`
	ProjectID      string  `json:"projectId"`
	Scanner        string  `json:"scanner"`
	Severity       string  `json:"severity"`
	Title          string  `json:"title"`
	Description    string  `json:"description"`
	FilePath       *string `json:"filePath"`
	Line           *int    `json:"line"`
	CWEID          *string `json:"cweId"`
	CVEID          *string `json:"cveId"`
	Recommendation *string `json:"recommendation"`
}

// Project represents a project.
type Project struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	RepositoryURL *string `json:"repositoryUrl"`
	Language      *string `json:"language"`
	Score         *int    `json:"score"`
	RiskLevel     *string `json:"riskLevel"`
	LastScanAt    *string `json:"lastScanAt"`
	CreatedAt     string  `json:"createdAt"`
}

// ============================================================================
// Scans
// ============================================================================

// ScansService handles scan API operations.
type ScansService struct {
	client *Client
}

// CreateScanParams are the parameters for creating a scan.
type CreateScanParams struct {
	RepositoryURL string   `json:"repositoryUrl,omitempty"`
	ProjectID     string   `json:"projectId,omitempty"`
	Profile       string   `json:"profile,omitempty"`
	Branch        string   `json:"branch,omitempty"`
	CommitSha     string   `json:"commitSha,omitempty"`
	Scanners      []string `json:"scanners,omitempty"`
}

// Create starts a new scan.
func (s *ScansService) Create(ctx context.Context, params CreateScanParams) (*Scan, error) {
	var scan Scan
	if err := s.client.do(ctx, http.MethodPost, "/api/v1/scans", params, &scan); err != nil {
		return nil, err
	}
	return &scan, nil
}

// Get retrieves a scan by ID.
func (s *ScansService) Get(ctx context.Context, scanID string) (*Scan, error) {
	var scan Scan
	if err := s.client.do(ctx, http.MethodGet, "/api/v1/scans/"+scanID, nil, &scan); err != nil {
		return nil, err
	}
	return &scan, nil
}

// WaitOptions configures scan polling.
type WaitOptions struct {
	PollInterval time.Duration
	Timeout      time.Duration
}

// WaitForCompletion polls until a scan completes or fails.
func (s *ScansService) WaitForCompletion(ctx context.Context, scanID string, opts *WaitOptions) (*Scan, error) {
	interval := 3 * time.Second
	timeout := 10 * time.Minute
	if opts != nil {
		if opts.PollInterval > 0 {
			interval = opts.PollInterval
		}
		if opts.Timeout > 0 {
			timeout = opts.Timeout
		}
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for {
		scan, err := s.Get(ctx, scanID)
		if err != nil {
			return nil, err
		}
		if scan.Status == "completed" || scan.Status == "failed" {
			return scan, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("codehardener: scan %s timed out", scanID)
		case <-time.After(interval):
		}
	}
}

// ============================================================================
// Findings
// ============================================================================

// FindingsService handles findings API operations.
type FindingsService struct {
	client *Client
}

// ListFindingsParams are the parameters for listing findings.
type ListFindingsParams struct {
	ScanID    string
	ProjectID string
	Severity  string
	Page      int
	Limit     int
}

// List retrieves findings with optional filters.
func (f *FindingsService) List(ctx context.Context, params ListFindingsParams) ([]Finding, error) {
	q := url.Values{}
	if params.ScanID != "" {
		q.Set("scanId", params.ScanID)
	}
	if params.ProjectID != "" {
		q.Set("projectId", params.ProjectID)
	}
	if params.Severity != "" {
		q.Set("severity", params.Severity)
	}
	if params.Page > 0 {
		q.Set("page", fmt.Sprintf("%d", params.Page))
	}
	if params.Limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", params.Limit))
	}

	path := "/api/v1/findings"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}

	var findings []Finding
	if err := f.client.do(ctx, http.MethodGet, path, nil, &findings); err != nil {
		return nil, err
	}
	return findings, nil
}

// ============================================================================
// Projects
// ============================================================================

// ProjectsService handles project API operations.
type ProjectsService struct {
	client *Client
}

// CreateProjectParams are the parameters for creating a project.
type CreateProjectParams struct {
	Name          string `json:"name"`
	RepositoryURL string `json:"repositoryUrl,omitempty"`
}

// Create creates a new project.
func (p *ProjectsService) Create(ctx context.Context, params CreateProjectParams) (*Project, error) {
	var project Project
	if err := p.client.do(ctx, http.MethodPost, "/api/v1/projects", params, &project); err != nil {
		return nil, err
	}
	return &project, nil
}

// Get retrieves a project by ID.
func (p *ProjectsService) Get(ctx context.Context, projectID string) (*Project, error) {
	var project Project
	if err := p.client.do(ctx, http.MethodGet, "/api/v1/projects/"+projectID, nil, &project); err != nil {
		return nil, err
	}
	return &project, nil
}

// Delete removes a project.
func (p *ProjectsService) Delete(ctx context.Context, projectID string) error {
	return p.client.do(ctx, http.MethodDelete, "/api/v1/projects/"+projectID, nil, nil)
}
