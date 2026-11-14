package desktop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	PollInterval       = time.Second
	RequestTimeout     = 2500 * time.Millisecond
	QuitRequestTimeout = 35 * time.Second
	QuitDeadline       = 45 * time.Second
	FailureLimit       = 3
	OpenDebounce       = 1500 * time.Millisecond
)

// ErrUnauthorized indicates Control rejected the current session token.
var ErrUnauthorized = errors.New("unauthorized session token")

// Client talks to Control's local loopback HTTP API.
type Client struct {
	http *http.Client

	mu             sync.RWMutex
	baseURL        string
	token          string
	onUnauthorized func(context.Context) (string, bool)
}

// NewClient constructs a loopback-only Client. baseURL may be empty initially
// and supplied later via SetEndpoint once Control is connected.
func NewClient(baseURL, token string) (*Client, error) {
	c := &Client{
		http: &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
			},
		},
	}
	if baseURL != "" || token != "" {
		if err := c.SetEndpoint(baseURL, token); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// SetUnauthorizedHook sets a callback invoked on HTTP 401 to refresh the
// session token over IPC and retry the request once.
func (c *Client) SetUnauthorizedHook(fn func(context.Context) (string, bool)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onUnauthorized = fn
}

// SetEndpoint updates the validated loopback base URL and X-Token.
func (c *Client) SetEndpoint(baseURL, token string) error {
	cleanURL := ""
	if baseURL != "" {
		u, err := validateLoopbackURL(baseURL)
		if err != nil {
			return err
		}
		cleanURL = strings.TrimRight(u.String(), "/")
	}
	c.mu.Lock()
	c.baseURL = cleanURL
	c.token = token
	c.mu.Unlock()
	return nil
}

// Endpoint returns the current validated base URL and token.
func (c *Client) Endpoint() (string, string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.baseURL, c.token
}

func validateLoopbackURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid control URL: %w", err)
	}
	if u.Scheme != "http" {
		return nil, fmt.Errorf("refusing non-http control URL scheme %q", u.Scheme)
	}
	host := u.Hostname()
	if host != "127.0.0.1" && host != "localhost" {
		return nil, fmt.Errorf("refusing non-loopback control host %q", host)
	}
	return u, nil
}

func (c *Client) FetchState(ctx context.Context) (map[string]any, error) {
	return c.doJSON(ctx, http.MethodGet, "/api/state", nil, RequestTimeout)
}

func (c *Client) SetRouting(ctx context.Context, on bool) error {
	_, err := c.doJSON(ctx, http.MethodPost, "/api/routing", map[string]any{"on": on}, RequestTimeout)
	return err
}

func (c *Client) SetCombine(ctx context.Context, on bool) error {
	_, err := c.doJSON(ctx, http.MethodPost, "/api/combine", map[string]any{"on": on}, RequestTimeout)
	return err
}

func (c *Client) SetAppLine(ctx context.Context, path string, line *string) error {
	var target any
	if line != nil {
		target = *line
	}
	_, err := c.doJSON(ctx, http.MethodPost, "/api/app-line", map[string]any{
		"path": path,
		"line": target,
	}, RequestTimeout)
	return err
}

func (c *Client) DismissUpdate(ctx context.Context, version string) error {
	_, err := c.doJSON(ctx, http.MethodPost, "/api/update/dismiss", map[string]any{"version": version}, RequestTimeout)
	return err
}

func (c *Client) Quit(ctx context.Context) error {
	_, err := c.doJSON(ctx, http.MethodPost, "/api/quit", map[string]any{}, QuitRequestTimeout)
	return err
}

func (c *Client) doJSON(ctx context.Context, method, path string, body any, timeout time.Duration) (map[string]any, error) {
	res, err := c.doOnce(ctx, method, path, body, timeout)
	if errors.Is(err, ErrUnauthorized) {
		c.mu.RLock()
		hook := c.onUnauthorized
		c.mu.RUnlock()
		if hook != nil {
			if nextTok, ok := hook(ctx); ok && nextTok != "" {
				c.mu.Lock()
				c.token = nextTok
				c.mu.Unlock()
				return c.doOnce(ctx, method, path, body, timeout)
			}
		}
	}
	return res, err
}

func (c *Client) doOnce(ctx context.Context, method, path string, body any, timeout time.Duration) (map[string]any, error) {
	baseURL, token := c.Endpoint()
	if baseURL == "" || token == "" {
		return nil, errors.New("control session not connected")
	}
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var reader io.Reader
	if payload != nil {
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(reqCtx, method, baseURL+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Token", token)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrUnauthorized
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errObj map[string]any
		if json.Unmarshal(raw, &errObj) == nil {
			if msg := textVal(errObj, "error"); msg != "" {
				return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, msg)
			}
		}
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil
	}
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}
	return parsed, nil
}
