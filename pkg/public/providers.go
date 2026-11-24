package public

import (
	"fmt"
	"sort"
	"strings"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/azuredns"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/desec"
	"github.com/go-acme/lego/v4/providers/dns/digitalocean"
	"github.com/go-acme/lego/v4/providers/dns/exec"
	"github.com/go-acme/lego/v4/providers/dns/gandiv5"
	"github.com/go-acme/lego/v4/providers/dns/gcloud"
	"github.com/go-acme/lego/v4/providers/dns/godaddy"
	"github.com/go-acme/lego/v4/providers/dns/hetzner"
	"github.com/go-acme/lego/v4/providers/dns/httpreq"
	"github.com/go-acme/lego/v4/providers/dns/infomaniak"
	"github.com/go-acme/lego/v4/providers/dns/inwx"
	"github.com/go-acme/lego/v4/providers/dns/ionos"
	"github.com/go-acme/lego/v4/providers/dns/linode"
	"github.com/go-acme/lego/v4/providers/dns/namecheap"
	"github.com/go-acme/lego/v4/providers/dns/netcup"
	"github.com/go-acme/lego/v4/providers/dns/ovh"
	"github.com/go-acme/lego/v4/providers/dns/pdns"
	"github.com/go-acme/lego/v4/providers/dns/porkbun"
	"github.com/go-acme/lego/v4/providers/dns/rfc2136"
	"github.com/go-acme/lego/v4/providers/dns/route53"
)

// providers are the supported DNS Providers, by lego name. Each reads its
// credentials from the environment variables documented by lego
// (https://go-acme.github.io/lego/dns/). Adding one is a one-line change.
var providers = map[string]func() (challenge.Provider, error){
	"gcloud":       func() (challenge.Provider, error) { return gcloud.NewDNSProvider() },
	"azuredns":     func() (challenge.Provider, error) { return azuredns.NewDNSProvider() },
	"cloudflare":   func() (challenge.Provider, error) { return cloudflare.NewDNSProvider() },
	"route53":      func() (challenge.Provider, error) { return route53.NewDNSProvider() },
	"digitalocean": func() (challenge.Provider, error) { return digitalocean.NewDNSProvider() },
	"hetzner":      func() (challenge.Provider, error) { return hetzner.NewDNSProvider() },
	"ovh":          func() (challenge.Provider, error) { return ovh.NewDNSProvider() },
	"desec":        func() (challenge.Provider, error) { return desec.NewDNSProvider() },
	"rfc2136":      func() (challenge.Provider, error) { return rfc2136.NewDNSProvider() },
	"exec":         func() (challenge.Provider, error) { return exec.NewDNSProvider() },
	"httpreq":      func() (challenge.Provider, error) { return httpreq.NewDNSProvider() },
	"porkbun":      func() (challenge.Provider, error) { return porkbun.NewDNSProvider() },
	"namecheap":    func() (challenge.Provider, error) { return namecheap.NewDNSProvider() },
	"gandiv5":      func() (challenge.Provider, error) { return gandiv5.NewDNSProvider() },
	"infomaniak":   func() (challenge.Provider, error) { return infomaniak.NewDNSProvider() },
	"godaddy":      func() (challenge.Provider, error) { return godaddy.NewDNSProvider() },
	"pdns":         func() (challenge.Provider, error) { return pdns.NewDNSProvider() },
	"linode":       func() (challenge.Provider, error) { return linode.NewDNSProvider() },
	"ionos":        func() (challenge.Provider, error) { return ionos.NewDNSProvider() },
	"netcup":       func() (challenge.Provider, error) { return netcup.NewDNSProvider() },
	"inwx":         func() (challenge.Provider, error) { return inwx.NewDNSProvider() },
}

// SupportedDNSProviders lists the DNS Provider names acme-proxy accepts.
func SupportedDNSProviders() []string {
	names := make([]string, 0, len(providers))
	for n := range providers {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func newDNSProvider(name string) (challenge.Provider, error) {
	ctor, ok := providers[strings.ToLower(name)]
	if !ok {
		return nil, fmt.Errorf("unsupported DNS provider %q (supported: %s)", name, strings.Join(SupportedDNSProviders(), ", "))
	}
	return ctor()
}
