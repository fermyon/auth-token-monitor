package providers

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"tailscale.com/client/tailscale/v2"

	"github.com/fermyon/auth-token-monitor/config"
)

type TailscaleProvider struct {
	Provider
}

var Tailscale = &TailscaleProvider{
	Provider: Provider{
		Name: "tailscale",
		BaseURL: &url.URL{
			Scheme: "https",
			Host:   "api.tailscale.com",
		},
		TokenPatterns: []*regexp.Regexp{
			// Note: there are also 'tskey-(auth|scim|webhook)-...' tokens,
			// and indeed keys of these types will be returned when GETting all keys,
			// but only the api or token key types have authorization to make API
			// requests. (Also including 'client' keys for when an OAuth client key
			// is supplied, wherein a token key will be generated during auth.)
			regexp.MustCompile(`^tskey-(api|client|token)-[a-zA-Z0-9-]+$`),
		},
	},
}

func (tp *TailscaleProvider) CheckToken(ctx context.Context, cfg *config.Config, name, token string) (unhappyTokens []string, err error) {
	if cfg.BaseURL != nil {
		tp.BaseURL = cfg.BaseURL
	}
	ctx, span := otel.Tracer("").Start(ctx, fmt.Sprintf("check-%s %s", tp.Name, name))
	defer func() {
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()
	span.SetAttributes(
		attribute.Stringer("tokmon.base_url", tp.BaseURL),
		attribute.String("tokmon.token.provider", tp.Name),
		attribute.String("tokmon.token.name", name),
	)

	fmt.Printf("Checking token %q with provider %q...\n", name, tp.Name)

	// Create a Tailscale API Client
	tailnet := os.Getenv("TAILNET")
	if tailnet == "" {
		fmt.Println("No TAILNET supplied; using default tailnet associated with supplied credential")
		tailnet = "-"
	}
	client := &tailscale.Client{Tailnet: tailnet, BaseURL: tp.BaseURL}

	// Check env for auth mode: either OAuth client or static api key
	if apiKey := os.Getenv("TS_API_KEY"); apiKey != "" {
		fmt.Println("Using TS_API_KEY for API requests")
		client.APIKey = apiKey
	} else if clientID, clientSecret := os.Getenv("TS_OAUTH_CLIENT_ID"), os.Getenv("TS_OAUTH_CLIENT_SECRET"); clientID != "" && clientSecret != "" {
		fmt.Println("Using OAuth client to generate an access token for API requests")
		client.Auth = &tailscale.OAuth{
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}
	} else {
		fmt.Println("Using the provided token for Tailscale API requests, as neither TS_API_KEY nor OAuth credentials (TS_OAUTH_CLIENT_ID, TS_OAUTH_CLIENT_SECRET) are set")
		client.APIKey = token
	}

	var keyIDs []string
	keyIDsEnvVar := os.Getenv("TS_KEY_IDS")
	if keyIDsEnvVar != "" {
		keyIDs = strings.Split(keyIDsEnvVar, ",")
		fmt.Printf("Filtering Tailscale key(s) to only include the following IDs: %+v\n", keyIDs)
	} else {
		// List keys, supplying all=true to list both user and tailnet keys
		// Note: as the SDK mentions, the only field set for each returned key is the ID, so we'll just
		// set keyIDs to the slice of returned IDs.
		keys, err := client.Keys().List(ctx, true)
		if err != nil {
			return unhappyTokens, fmt.Errorf("unable to list keys: %w", err)
		}
		for _, key := range keys {
			keyIDs = append(keyIDs, key.ID)
		}
		fmt.Printf("Found %d Tailscale key(s) in the %s Tailnet\n", len(keyIDs), client.Tailnet)
	}

	span.SetAttributes(attribute.Int("tokmon.tailscale.token_count", len(keyIDs)))
	for _, keyID := range keyIDs {
		key, err := client.Keys().Get(ctx, keyID)
		if err != nil {
			return unhappyTokens, fmt.Errorf("unable to get key with id=%s", keyID)
		}

		if key.Expires.IsZero() {
			fmt.Printf("  [%s] (id=%s): expiration: NEVER\n", key.Description, key.ID)
			continue
		} else if !key.Revoked.IsZero() {
			// In practice, it appears these usually aren't returned by the API
			fmt.Printf("  [%s] (id=%s): revoked\n", key.Description, key.ID)
			continue
		} else if key.Invalid {
			// In practice, it appears these usually aren't returned by the API
			fmt.Printf("  [%s] (id=%s): invalid\n", key.Description, key.ID)
			continue
		}

		expiration := key.Expires
		expirationDuration := time.Until(expiration)
		fmt.Printf("  [%s] (id=%s): expiration: %s (%.1f days)\n",
			key.Description, key.ID, expiration.Format(time.RFC3339), expirationDuration.Hours()/24)

		attributes := []attribute.KeyValue{
			attribute.String("tokmon.token.expiration", expiration.String()),
			attribute.Float64("tokmon.token.expiration_duration", expirationDuration.Seconds()),
		}
		details := []TokenDetail[any]{
			{Key: "ID", Value: key.ID},
			{Key: "Description", Value: key.Description},
			{Key: "Type", Value: key.KeyType},
			{Key: "UserID", Value: key.UserID},
			{Key: "CreatedAt", Value: key.Created},
		}
		attributes = append(attributes, tp.generateDetailAttributes(details...)...)

		span.AddEvent("check_tailscale_token", trace.WithAttributes(attributes...))

		printKeyMetadata(key)

		if expirationDuration < cfg.ExpirationThreshold {
			fmt.Printf("  WARNING: Key %q (id=%s) expiring soon!\n", key.Description, key.ID)
			unhappyTokens = append(unhappyTokens, key.ID)
		}
	}

	if len(unhappyTokens) > 0 {
		span.SetStatus(codes.Error, fmt.Sprintf("tailscale key(s) expiring soon: %+v", unhappyTokens))
	}

	fmt.Println()
	return unhappyTokens, nil
}

func printKeyMetadata(k *tailscale.Key) {
	if len(k.Tags) > 0 {
		fmt.Printf("    Tags: %v\n", k.Tags)
	}
	if len(k.Scopes) > 0 {
		fmt.Printf("    Scopes: %v\n", k.Scopes)
	}
	caps := k.Capabilities.Devices.Create
	if caps.Reusable || caps.Ephemeral || caps.Preauthorized || len(caps.Tags) > 0 {
		fmt.Printf("    Capabilities: %+v\n", caps)
	}
}
