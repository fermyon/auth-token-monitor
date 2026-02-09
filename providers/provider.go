package providers

import (
	"fmt"
	"net/url"

	"github.com/alecthomas/kong"
)

func (p *Provider) Decode(ctx *kong.DecodeContext) error {
	value := ctx.Scan.Pop().String()
	provider, ok := Providers[value]
	if !ok {
		return fmt.Errorf("unsupported provider: %q", value)
	}
	*p = provider
	return nil
}

type Provider struct {
	Name               string
	AuthHeader         string
	BaseURL            *url.URL
	Path               string
	ExpectedStatusCode int
}

var Providers = map[string]Provider{
	"github": Github,
	"fwf":    Fwf,
	"linode": Linode,
}
