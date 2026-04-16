package providers

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/go-tfe"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/fermyon/auth-token-monitor/config"
)

type TerraformProvider struct {
	Provider
}

var Terraform = &TerraformProvider{
	Provider: Provider{
		Name: "terraform",
		BaseURL: &url.URL{
			Scheme: "https",
			Host:   "app.terraform.io",
		},
		TokenPatterns: []*regexp.Regexp{
			// Based on user, team and org tokens generated from HCP Terraform
			// e.g. <14 char 1st section>.atlasv1.<67 or 91 char 3rd section>
			regexp.MustCompile(`^[a-zA-Z0-9]{14}\.atlasv1\.([a-zA-Z0-9]{67}|[a-zA-Z0-9]{91})$`),
		},
	},
}

func (tp *TerraformProvider) CheckToken(ctx context.Context, cfg *config.Config, name, token string) (unhappyTokens []string, err error) {
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

	config := &tfe.Config{
		Address:           tp.BaseURL.String(),
		Token:             token,
		RetryServerErrors: true,
	}

	client, err := tfe.NewClient(config)
	if err != nil {
		return unhappyTokens, fmt.Errorf("unable to create client: %w", err)
	}

	currentUser, err := client.Users.ReadCurrent(ctx)
	if err != nil {
		return unhappyTokens, fmt.Errorf("error reading current user: %w", err)
	}

	orgs, err := client.Organizations.List(ctx, &tfe.OrganizationListOptions{})
	if err != nil {
		return unhappyTokens, fmt.Errorf("error listing orgs for user: %w", err)
	}
	// I wouldn't think this would be possible; checking anyways
	if len(orgs.Items) == 0 {
		return unhappyTokens, fmt.Errorf("user/token belongs to no organizations")
	}
	// Assigning org to the first item in the list.
	// As far as I can tell, a team token and org token should only ever belong to one org.
	// While a user may belong to more than one org, we only utilize this value for
	// inspecting team or org tokens, not user tokens.
	org := orgs.Items[0]

	// Based on testing thus far, these appear to be the user name conventions:
	// users: <username>
	// team service account: api-team_<...>
	// org service account: api-org-<org name>-<...>
	username := currentUser.Username
	switch {
	case strings.HasPrefix(username, "api-org"):
		orgToken, err := client.OrganizationTokens.Read(ctx, org.Name)
		if err != nil {
			return unhappyTokens, fmt.Errorf("error reading org tokens: %w", err)
		}
		fmt.Printf("Found %d token(s) associated with org %q\n", 1, org.Name)
		span.SetAttributes(attribute.Int("tokmon.terraform.token_count", 1))

		tfToken := newTerraformToken(orgToken)
		if tp.checkExpiry(cfg, span, tfToken) {
			unhappyTokens = append(unhappyTokens, tfToken.Description)
		}
	case strings.HasPrefix(username, "api-team"):
		teamTokens, err := client.TeamTokens.List(ctx, org.Name, &tfe.TeamTokenListOptions{})
		if err != nil {
			return unhappyTokens, fmt.Errorf("error listing team tokens: %w", err)
		}
		fmt.Printf("Found %d team token(s) in the %q organization\n", len(teamTokens.Items), org.Name)
		span.SetAttributes(attribute.Int("tokmon.terraform.token_count", len(teamTokens.Items)))

		for _, token := range teamTokens.Items {
			tfToken := newTerraformToken(token)
			if tp.checkExpiry(cfg, span, tfToken) {
				unhappyTokens = append(unhappyTokens, tfToken.Description)
			}
		}
	default: // user
		userTokens, err := client.UserTokens.List(ctx, currentUser.ID)
		if err != nil {
			return unhappyTokens, fmt.Errorf("error listing user tokens: %w", err)
		}
		fmt.Printf("Found %d token(s) associated with user %q\n", len(userTokens.Items), username)
		span.SetAttributes(attribute.Int("tokmon.terraform.token_count", len(userTokens.Items)))

		for _, token := range userTokens.Items {
			tfToken := newTerraformToken(token)
			if tp.checkExpiry(cfg, span, tfToken) {
				unhappyTokens = append(unhappyTokens, tfToken.Description)
			}
		}
	}

	if len(unhappyTokens) > 0 {
		span.SetStatus(codes.Error, fmt.Sprintf("Terraform token(s) expiring soon: %+v", unhappyTokens))
	}

	fmt.Println()
	return unhappyTokens, nil
}

type TokenConstraint interface {
	*tfe.OrganizationToken | *tfe.TeamToken | *tfe.UserToken
}

type TerraformToken struct {
	ID          string
	Description string
	ExpiredAt   time.Time
	CreatedAt   time.Time
	CreatedBy   string
	Type        string
}

func newTerraformToken[T TokenConstraint](a T) *TerraformToken {
	switch t := any(a).(type) {
	case *tfe.OrganizationToken:
		// Description for an org token may be empty, e.g. if created in UI
		var description string
		if t.Description == "" {
			description = "<Organization Token>"
		}
		return &TerraformToken{ID: t.ID, Description: description, ExpiredAt: t.ExpiredAt, CreatedAt: t.CreatedAt, CreatedBy: getCreatedBy(t.CreatedBy), Type: "org"}
	case *tfe.TeamToken:
		var description string
		if t.Description != nil {
			description = *t.Description
		}
		return &TerraformToken{ID: t.ID, Description: description, ExpiredAt: t.ExpiredAt, CreatedAt: t.CreatedAt, CreatedBy: getCreatedBy(t.CreatedBy), Type: "team"}
	case *tfe.UserToken:
		return &TerraformToken{ID: t.ID, Description: t.Description, ExpiredAt: t.ExpiredAt, CreatedAt: t.CreatedAt, CreatedBy: getCreatedBy(t.CreatedBy), Type: "user"}
	default:
		return &TerraformToken{}
	}
}

func (tp *TerraformProvider) checkExpiry(cfg *config.Config, span trace.Span, token *TerraformToken) (unhappy bool) {
	expiration := token.ExpiredAt
	expirationDuration := time.Until(expiration)
	attributes := []attribute.KeyValue{
		attribute.String("tokmon.token.expiration", expiration.String()),
		attribute.Float64("tokmon.token.expiration_duration", expirationDuration.Seconds()),
	}
	details := []TokenDetail[any]{
		{Key: "Type", Value: token.Type},
		{Key: "ID", Value: token.ID},
		{Key: "Description", Value: token.Description},
		{Key: "CreatedAt", Value: token.CreatedAt},
		{Key: "CreatedBy", Value: token.CreatedBy},
	}
	attributes = append(attributes, tp.generateDetailAttributes(details...)...)
	span.AddEvent("check_terraform_token", trace.WithAttributes(attributes...))

	if expiration.IsZero() {
		fmt.Printf("  [%s] (id=%s): expiration: NEVER\n", token.Description, token.ID)
		return unhappy
	}
	fmt.Printf("  [%s] (id=%s): expiration: %s (%.1f days)\n",
		token.Description, token.ID, expiration.Format(time.RFC3339), expirationDuration.Hours()/24)

	if time.Until(token.ExpiredAt) < cfg.ExpirationThreshold {
		if time.Until(token.ExpiredAt) < 0 {
			fmt.Printf("  ALERT: Terraform %s token %q (id=%s) has expired!\n", token.Type, token.Description, token.ID)
		} else {
			fmt.Printf("  WARNING: Terraform %s token %q (id=%s) expiring soon!\n", token.Type, token.Description, token.ID)
		}
		unhappy = true
	}
	return unhappy
}

func getCreatedBy(cbc *tfe.CreatedByChoice) string {
	// Returning IDs here; at least in the case of User,
	// all other fields appear to be empty/nil, presumably a security default.
	// TODO: call respective 'Get<type>' API to get full details and then
	// return names instead of IDs
	if cbc != nil {
		if cbc.Organization != nil {
			return cbc.Organization.ExternalID
		}
		if cbc.Team != nil {
			return cbc.Team.ID
		}
		if cbc.User != nil {
			return cbc.User.ID
		}
	}
	return ""
}
