package providers

import (
	"net/url"
	"regexp"
)

type FwfProvider struct {
	Provider
}

var Fwf = &FwfProvider{
	Provider: Provider{
		Name:       "fwf",
		AuthHeader: "neutrino-authentication-token-expiration",
		BaseURL: &url.URL{
			Scheme: "https",
			Host:   "zar.infra.fermyon.tech",
		},
		Path:               "/tokens.v1.TokenService/ListTokens",
		ExpectedStatusCode: 403,
		TokenPatterns: []*regexp.Regexp{
			regexp.MustCompile(`^pat_[A-Z2-7]{26}$`),
		},
	},
}
