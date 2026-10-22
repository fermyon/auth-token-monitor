package providers

import (
	"net/url"
	"regexp"
)

type GithubProvider struct {
	Provider
}

var Github = &GithubProvider{
	Provider: Provider{
		Name:       "github",
		AuthHeader: "github-authentication-token-expiration",
		BaseURL: &url.URL{
			Scheme: "https",
			Host:   "api.github.com",
		},
		ExpectedStatusCode: 200,
		TokenPatterns: []*regexp.Regexp{
			// classic
			regexp.MustCompile(`^ghp_`),
			// fine-grained
			regexp.MustCompile(`^github_pat_`),
			// ephemeral Action tokens eg GITHUB_TOKEN
			regexp.MustCompile(`^ghs_`),
		},
	},
}
