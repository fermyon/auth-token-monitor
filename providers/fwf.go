package providers

import "net/url"

var Fwf = Provider{
	Name:       "fwf",
	AuthHeader: "neutrino-authentication-token-expiration",
	BaseURL: &url.URL{
		Scheme: "https",
		Host:   "zar.infra.fermyon.tech",
	},
	Path:               "/tokens.v1.TokenService/ListTokens",
	ExpectedStatusCode: 403,
}
