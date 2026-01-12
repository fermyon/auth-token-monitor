package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"go.opentelemetry.io/contrib/exporters/autoexport"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdkTrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/fermyon/github-token-monitor/providers"
)

var timestampLayouts = []string{
	// Sometimes Github returns an abbreviated timezone name, sometimes a numeric offset 🙄
	"2006-01-02 15:04:05 MST",
	"2006-01-02 15:04:05 -0700",
	// This is the current layout for FwF
	"2006-01-02 15:04:05.999999 -0700 MST",
}

var flags struct {
	TokenEnvVars []string `name:"token-env-vars" help:"Comma-separated list of token env var(s)"`
	TokensDir    string   `name:"tokens-dir" help:"Directory containing mounted secret tokens"`

	BaseURL             *url.URL           `name:"base-url" help:"Token API base URL (overrides provider default)"`
	ExpirationThreshold time.Duration      `name:"expiration-threshold" default:"360h" help:"Minimum duration until token expiration"`
	Provider            providers.Provider `name:"provider" type:"" default:"github" help:"Auth Token provider ('github' or 'fwf')" `
}

func main() {
	err := run()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	kong.Parse(&flags)

	if flags.BaseURL != nil {
		flags.Provider.BaseURL = flags.BaseURL
	}

	ctx := context.Background()

	// Initialize OpenTelemetry tracing with standard OTEL_* env vars
	exporter, err := autoexport.NewSpanExporter(ctx)
	if err != nil {
		return fmt.Errorf("starting opentelemetry: %w", err)
	}

	// Enable tracing iff there are _any_ OTEL_* env vars set
	enableTracing := slices.ContainsFunc(os.Environ(), func(env string) bool { return strings.HasPrefix(env, "OTEL_") })
	if enableTracing {
		tracerProvider := sdkTrace.NewTracerProvider(sdkTrace.WithBatcher(exporter))
		defer func() {
			if err := tracerProvider.Shutdown(ctx); err != nil {
				fmt.Printf("Error stopping opentelemetry: %v", err)
			}
		}()
		otel.SetTracerProvider(tracerProvider)
	}

	return checkTokens(ctx)
}

func checkTokens(ctx context.Context) (err error) {
	ctx, span := otel.Tracer("").Start(ctx, "checkTokens")
	defer func() {
		_, isFailedChecks := err.(failedChecksError)
		if err != nil && !isFailedChecks {
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()
	span.SetAttributes(
		attribute.Stringer("tokmon.base_url", flags.Provider.BaseURL),
		attribute.Float64("tokmon.expiration_threshold", flags.ExpirationThreshold.Seconds()))

	tokens := map[string]string{}

	for _, envVar := range flags.TokenEnvVars {
		if envVar != "" {
			token := os.Getenv(envVar)
			if token == "" {
				return fmt.Errorf("no value for configured token-env-var %q", envVar)
			}
			tokens[envVar] = token
		}
	}

	if len(flags.TokensDir) > 0 {
		entries, err := os.ReadDir(flags.TokensDir)
		if err != nil {
			return fmt.Errorf("reading tokens-dir %q: %w", flags.TokensDir, err)
		}
		for _, entry := range entries {
			path := path.Join(flags.TokensDir, entry.Name())
			byteContents, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("reading %q: %w", path, err)
			}

			token := string(byteContents)
			if strings.HasPrefix(token, "{") {
				var dockerConfig struct {
					Auths map[string]struct {
						Password string `json:"password"`
					}
				}
				err := json.Unmarshal(byteContents, &dockerConfig)
				if len(dockerConfig.Auths) == 0 {
					return fmt.Errorf("no auths or invalid JSON in %q: %v", path, err)
				}
				for domain, auth := range dockerConfig.Auths {
					tokens[fmt.Sprintf("%s (%s)", entry.Name(), domain)] = auth.Password
				}
			} else {
				tokens[entry.Name()] = strings.TrimSpace(token)
			}
		}
	}
	span.SetAttributes(attribute.StringSlice("tokmon.tokens", slices.Collect(maps.Keys(tokens))))

	if len(tokens) == 0 {
		return fmt.Errorf("no tokens to check")
	}

	unhappyTokens := failedChecksError{}
	for name, token := range tokens {
		happy, err := checkToken(ctx, name, token)
		if err != nil {
			log.Printf("Failed checking token %q: %v", name, err)
		}
		if !happy {
			unhappyTokens = append(unhappyTokens, name)
		}
	}
	if len(unhappyTokens) > 0 {
		return unhappyTokens
	}
	return nil
}

func checkToken(ctx context.Context, name, token string) (happy bool, err error) {
	ctx, span := otel.Tracer("").Start(ctx, "check "+name)
	defer func() {
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()
	span.SetAttributes(attribute.String("tokmon.token.name", name))

	fmt.Printf("Checking %q with provider %q...\n", name, flags.Provider.Name)

	// Make request to check token
	url := flags.Provider.BaseURL.JoinPath(flags.Provider.Path).String()
	resp, _, err := request(ctx, url, token)
	if err != nil {
		return false, fmt.Errorf("checking token via url %s: %w", url, err)
	}

	// Get user info (if permitted)
	// TODO: Currently only valid with GitHub; request support in FwF as well?
	userURL := flags.Provider.BaseURL.JoinPath("user").String()
	_, userJSON, err := request(ctx, userURL, token)
	if err == nil {
		// Parse user login
		var user struct {
			Login string `json:"login"`
		}
		err = json.Unmarshal(userJSON, &user)
		if err != nil {
			return false, fmt.Errorf("deserializing user: %w", err)
		}
		span.SetAttributes(attribute.String("tokmon.token.login", user.Login))
		fmt.Printf("Token user login: %s\n", user.Login)
	}

	happy = true

	// Check token expiration
	expirationValue := resp.Header.Get(flags.Provider.AuthHeader)
	if expirationValue == "" {
		fmt.Println("Token expiration: NONE")
	} else {
		span.SetAttributes(attribute.String("tokmon.token.expiration", expirationValue))

		// Parse expiration timestamp
		var expiration time.Time
		var err error
		for _, layout := range timestampLayouts {
			expiration, err = time.Parse(layout, expirationValue)
			if err == nil {
				break
			}
		}
		if err != nil {
			return false, fmt.Errorf("invalid expiration header value %q: %w", expirationValue, err)
		}
		fmt.Printf("Token expiration: %s", expiration)

		// Calculate time until expiration
		expirationDuration := time.Until(expiration)
		span.SetAttributes(attribute.Float64("tokmon.token.expiration_duration", expirationDuration.Seconds()))
		fmt.Printf(" (%.1f days)\n", expirationDuration.Hours()/24)
		if expirationDuration < flags.ExpirationThreshold {
			fmt.Println("WARNING: Expiring soon!")
			happy = false
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
			happy = false
		}
	}

	// Get GitHub token permissions (sometimes helpful when rotating)
	if flags.Provider == providers.Github {
		oAuthScopes := resp.Header.Get("x-oauth-scopes")
		span.SetAttributes(attribute.String("tokmon.token.oauth_scopes", oAuthScopes))
		fmt.Printf("OAuth scopes: %s\n\n", oAuthScopes)
	}
	return happy, nil
}

func request(ctx context.Context, url, token string) (resp *http.Response, body []byte, err error) {
	ctx, span := otel.Tracer("").Start(ctx, url)
	defer func() {
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()

	var req *http.Request
	switch flags.Provider {
	case providers.Fwf:
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

	if resp.StatusCode != flags.Provider.ExpectedStatusCode {
		if len(body) > 1024 {
			body = body[:1024]
		}
		trace.SpanFromContext(ctx).SetAttributes(attribute.String("tokmon.error_body", strconv.QuoteToASCII(string(body))))
		return nil, nil, fmt.Errorf("got status code %d != %d", resp.StatusCode, flags.Provider.ExpectedStatusCode)
	}
	return
}

type failedChecksError []string

func (ut failedChecksError) Error() string {
	return fmt.Sprintf("checks failed for token(s): %s", strings.Join(ut, ", "))
}
