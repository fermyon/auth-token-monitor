package providers

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"time"

	"github.com/linode/linodego"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"

	"github.com/fermyon/auth-token-monitor/config"
)

type LinodeProvider struct {
	Provider
}

var Linode = &LinodeProvider{
	Provider: Provider{
		Name: "linode",
		BaseURL: &url.URL{
			Scheme: "https",
			Host:   "api.linode.com",
		},
		TokenPatterns: []*regexp.Regexp{
			regexp.MustCompile(`^[a-f0-9]{64}$`),
		},
	},
}

func (lp *LinodeProvider) CheckToken(ctx context.Context, cfg *config.Config, name, token string) (unhappyTokens []string, err error) {
	if cfg.BaseURL != nil {
		lp.BaseURL = cfg.BaseURL
	}
	ctx, span := otel.Tracer("").Start(ctx, fmt.Sprintf("check-%s %s", lp.Name, name))
	defer func() {
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()
	span.SetAttributes(
		attribute.Stringer("tokmon.base_url", lp.BaseURL),
		attribute.String("tokmon.token.provider", lp.Name),
		attribute.String("tokmon.token.name", name),
	)

	fmt.Printf("Checking token %q with provider %q...\n", name, lp.Name)

	// Create a linodego client using the token
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	oauthClient := oauth2.NewClient(ctx, tokenSource)
	client := linodego.NewClient(oauthClient)
	client.SetBaseURL(lp.BaseURL.String())

	// List all personal access tokens visible to this token
	linodeTokens, err := client.ListTokens(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("listing Linode tokens: %w", err)
	}

	fmt.Printf("Found %d Linode personal access token(s)\n", len(linodeTokens))
	span.SetAttributes(attribute.Int("tokmon.linode.token_count", len(linodeTokens)))

	for _, lt := range linodeTokens {
		label := lt.Label
		if label == "" {
			label = fmt.Sprintf("token-%d", lt.ID)
		}

		if lt.Expiry == nil {
			fmt.Printf("  [%s] (id=%d): expiration: NEVER\n", label, lt.ID)
			continue
		}

		expiration := *lt.Expiry
		expirationDuration := time.Until(expiration)
		fmt.Printf("  [%s] (id=%d): expiration: %s (%.1f days)\n",
			label, lt.ID, expiration.Format(time.RFC3339), expirationDuration.Hours()/24)

		attributes := []attribute.KeyValue{
			attribute.String("tokmon.token.expiration", expiration.String()),
			attribute.Float64("tokmon.token.expiration_duration", expirationDuration.Seconds()),
		}
		details := []TokenDetail[any]{
			{Key: "label", Value: label},
			{Key: "ID", Value: lt.ID},
		}
		attributes = append(attributes, lp.generateDetailAttributes(details...)...)

		span.AddEvent("check_linode_token", trace.WithAttributes(attributes...))

		if expirationDuration < cfg.ExpirationThreshold {
			fmt.Printf("  WARNING: Token %q expiring soon!\n", label)
			unhappyTokens = append(unhappyTokens, label)
		}

		if len(unhappyTokens) > 0 {
			span.SetStatus(codes.Error, fmt.Sprintf("linode token(s) expiring soon: %+v", unhappyTokens))
		}
	}

	fmt.Println()
	return unhappyTokens, nil
}
