package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/fermyon/auth-token-monitor/config"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

type Provider struct {
	Name               string
	AuthHeader         string
	BaseURL            *url.URL
	Path               string
	ExpectedStatusCode int
	TokenPatterns      []*regexp.Regexp
}

var Providers = map[string]TokenChecker{
	"github":    Github,
	"fwf":       Fwf,
	"linode":    Linode,
	"tailscale": Tailscale,
}

type TokenChecker interface {
	CheckToken(ctx context.Context, config *config.Config, name, token string) (unhappyTokens []string, err error)
	GetPatterns() (tokenPatterns []*regexp.Regexp)
}

func (p *Provider) CheckToken(ctx context.Context, cfg *config.Config, name, token string) (unhappyTokens []string, err error) {
	if cfg.BaseURL != nil {
		p.BaseURL = cfg.BaseURL
	}
	ctx, span := otel.Tracer("").Start(ctx, fmt.Sprintf("check-%s %s", p.Name, name))
	defer func() {
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()
	span.SetAttributes(
		attribute.Stringer("tokmon.base_url", p.BaseURL),
		attribute.String("tokmon.token.name", name))

	fmt.Printf("Checking token %q with provider %q...\n", name, p.Name)

	// Make request to check token
	url := p.BaseURL.JoinPath(p.Path).String()
	resp, _, err := p.request(ctx, url, token)
	if err != nil {
		return unhappyTokens, fmt.Errorf("checking token via url %s: %w", url, err)
	}

	// Get user info (if permitted)
	userURL := p.BaseURL.JoinPath("user").String()
	_, userJSON, err := p.request(ctx, userURL, token)
	if err == nil {
		// Parse user login
		var user struct {
			Login string `json:"login"`
		}
		err = json.Unmarshal(userJSON, &user)
		if err != nil {
			return unhappyTokens, fmt.Errorf("deserializing user: %w", err)
		}
		span.SetAttributes(attribute.String("tokmon.token.login", user.Login))
		fmt.Printf("Token user login: %s\n", user.Login)
	}

	// Check token expiration
	expirationValue := resp.Header.Get(p.AuthHeader)
	if expirationValue == "" {
		fmt.Println("Token expiration: NONE")
	} else {
		span.SetAttributes(attribute.String("tokmon.token.expiration", expirationValue))

		// Parse expiration timestamp
		var expiration time.Time
		var err error
		for _, layout := range config.TimestampLayouts {
			expiration, err = time.Parse(layout, expirationValue)
			if err == nil {
				break
			}
		}
		if err != nil {
			return unhappyTokens, fmt.Errorf("invalid expiration header value %q: %w", expirationValue, err)
		}
		fmt.Printf("Token expiration: %s", expiration)

		// Calculate time until expiration
		expirationDuration := time.Until(expiration)
		span.SetAttributes(attribute.Float64("tokmon.token.expiration_duration", expirationDuration.Seconds()))
		fmt.Printf(" (%.1f days)\n", expirationDuration.Hours()/24)
		if expirationDuration < cfg.ExpirationThreshold {
			fmt.Println("WARNING: Expiring soon!")
			unhappyTokens = append(unhappyTokens, token)
			span.SetStatus(codes.Error, "token expiring soon")
		}

	}

	// Check rate limit usage
	rateLimitLimit, _ := strconv.Atoi(resp.Header.Get("x-ratelimit-limit"))
	if rateLimitLimit != 0 {
		rateLimitUsed, _ := strconv.Atoi(resp.Header.Get("x-ratelimit-used"))
		fmt.Printf("Rate limit usage: %d / %d", rateLimitUsed, rateLimitLimit)

		rateLimitPercent := rateLimitUsed * 100 / rateLimitLimit
		fmt.Printf(" (~%d%%)\n", rateLimitPercent)
		if rateLimitPercent > 50 {
			fmt.Println("WARNING: Rate limit >50%!")
			span.SetStatus(codes.Error, "high rate limit usage")
			unhappyTokens = append(unhappyTokens, token)
		}
	}

	// Get GitHub token permissions (sometimes helpful when rotating)
	if p.Name == Github.Name {
		oAuthScopes := resp.Header.Get("x-oauth-scopes")
		span.SetAttributes(attribute.String("tokmon.token.oauth_scopes", oAuthScopes))
		fmt.Printf("OAuth scopes: %s\n", oAuthScopes)
	}

	fmt.Println()
	return unhappyTokens, nil
}

func (p *Provider) GetPatterns() []*regexp.Regexp {
	return p.TokenPatterns
}

func (p *Provider) request(ctx context.Context, url, token string) (resp *http.Response, body []byte, err error) {
	ctx, span := otel.Tracer("").Start(ctx, url)
	defer func() {
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()

	var req *http.Request
	switch p.Name {
	case Fwf.Name:
		body := []byte(`{}`)
		req, err = http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
		if err != nil {
			return nil, nil, fmt.Errorf("new request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
	default:
		req, err = http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("new request: %w", err)
		}
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("reading body: %w", err)
	}

	if resp.StatusCode != p.ExpectedStatusCode {
		if len(body) > 1024 {
			body = body[:1024]
		}
		trace.SpanFromContext(ctx).SetAttributes(attribute.String("tokmon.error_body", strconv.QuoteToASCII(string(body))))
		return nil, nil, fmt.Errorf("got status code %d != %d", resp.StatusCode, p.ExpectedStatusCode)
	}
	return
}
