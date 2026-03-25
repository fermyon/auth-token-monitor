package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/alecthomas/kong"
	"go.opentelemetry.io/contrib/exporters/autoexport"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdkTrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/fermyon/auth-token-monitor/config"
	"github.com/fermyon/auth-token-monitor/providers"
)

var flags config.Config

func main() {
	err := run()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	kong.Parse(&flags)

	if flags.Provider != "" {
		fmt.Fprintf(os.Stderr, "Warning: --provider is deprecated and will be ignored. The auth provider is now auto-detected for each token.\n")
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
			if fi, err := os.Stat(path); err == nil && fi.IsDir() {
				continue
			}
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
		unhappy, err := checkTokensByPattern(ctx, name, token)
		if err != nil {
			log.Printf("Failed checking token by pattern %q: %v", name, err)
			unhappyTokens = append(unhappyTokens, name)
		} else {
			unhappyTokens = append(unhappyTokens, unhappy...)
		}
	}

	if len(unhappyTokens) > 0 {
		return unhappyTokens
	}
	return nil
}

func checkTokensByPattern(ctx context.Context, name, token string) (unhappyTokens []string, err error) {
	for _, provider := range providers.Providers {
		for _, pattern := range provider.GetPatterns() {
			if pattern.MatchString(token) {
				return provider.CheckToken(ctx, &flags, name, token)
			}
		}
	}
	return unhappyTokens, fmt.Errorf("could not determine provider")
}

type failedChecksError []string

func (ut failedChecksError) Error() string {
	return fmt.Sprintf("checks failed for token(s): %s", strings.Join(ut, ", "))
}
