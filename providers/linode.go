package providers

import "net/url"

var Linode = Provider{
	Name: "linode",
	BaseURL: &url.URL{
		Scheme: "https",
		Host:   "api.linode.com",
	},
}
