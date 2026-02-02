package providers

import "net/url"

var Github = Provider{
	Name:       "github",
	AuthHeader: "github-authentication-token-expiration",
	BaseURL: &url.URL{
		Scheme: "https",
		Host:   "api.github.com",
	},
	ExpectedStatusCode: 200,
}
