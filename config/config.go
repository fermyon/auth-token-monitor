package config

import (
	"net/url"
	"time"
)

type Config struct {
	TokenEnvVars []string `name:"token-env-vars" help:"Comma-separated list of token env var(s)"`
	TokensDir    string   `name:"tokens-dir" help:"Directory containing mounted secret tokens"`

	BaseURL             *url.URL      `name:"base-url" help:"Token API base URL (overrides provider default)"`
	ExpirationThreshold time.Duration `name:"expiration-threshold" default:"360h" help:"Minimum duration until token expiration"`
	Provider            string        `name:"provider" hidden:"" type:"" help:"Deprecated: the auth provider is now auto-detected from token(s)" `
}

var TimestampLayouts = []string{
	// Sometimes Github returns an abbreviated timezone name, sometimes a numeric offset 🙄
	"2006-01-02 15:04:05 MST",
	"2006-01-02 15:04:05 -0700",
	// This is the current layout for FwF
	"2006-01-02 15:04:05.999999 -0700 MST",
}
