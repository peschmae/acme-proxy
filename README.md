# acme-proxy

acme-proxy is an ACME server for the hosts of one **Internal Domain**. Internal hosts (Traefik, Caddy, certbot, acme.sh, …) request certificates from it over plain ACME, and get **publicly trusted** certificates without ever holding DNS credentials.

```
Requester (Traefik, Caddy, …)          acme-proxy                         Public CA (Let's Encrypt)
        │  ACME, HTTP-01 on the          │  ACME, DNS-01 through the            │
        │  internal network              │  DNS Provider's API                  │
        └──────────── Internal ─────────►└──────────── Public ───────────────►└
```

1. A Requester places an **Internal Order** with acme-proxy.
2. acme-proxy checks control of each name with an **HTTP-01 Internal Challenge**: it fetches `http://<name>/.well-known/acme-challenge/<token>` over the internal network, resolving the name through internal DNS.
3. When the Requester finalizes, acme-proxy places exactly one **Public Order** with the Public CA. It forwards the Requester's CSR unchanged and answers the **DNS-01 Public Challenge** by writing a TXT record through the DNS Provider's API.
4. The Requester polls, then downloads the certificate. acme-proxy never sees a certificate's private key.

The DNS-API credentials live in one place, acme-proxy, instead of on every host. Terms are defined in [CONTEXT.md](CONTEXT.md). Design decisions are recorded in [docs/adr](docs/adr).

## DNS setup

acme-proxy serves exactly **one** Internal Domain, e.g. `example.biz`. To serve several domains, run several instances. See [ADR-0002](docs/adr/0002-internal-domain-publicly-delegated-for-dns01.md).

The Internal Domain is reserved for internal workloads:

| Where | Records |
|---|---|
| **Public DNS** (at the DNS Provider) | Only `NS` and `SOA`. acme-proxy adds and removes `_acme-challenge` TXT records there temporarily. |
| **Internal DNS** | The real host records (`app.example.biz A 10.0.0.12`, …). Internal resolvers must answer for the Internal Domain themselves, not forward to the public zone. |

acme-proxy needs to reach:

- every Requester on **port 80**, using internal DNS, for Internal Challenges;
- the Public CA and the DNS Provider's API over HTTPS;
- public DNS resolvers (default `1.1.1.1`, `8.8.8.8`) to check that the TXT record has propagated. If outbound DNS is blocked, set `ACME_PROXY_PUBLIC_PROPAGATION_WAIT` instead.

## Configuration

Everything is configured with environment variables.

| Variable | Default | Meaning |
|---|---|---|
| `ACME_PROXY_INTERNAL_DOMAIN` | *required* | The Internal Domain, e.g. `example.biz`. Only names inside it (or the domain itself) are accepted. |
| `ACME_PROXY_WILDCARD_BASES` | none | Comma-separated Wildcard Bases, e.g. `apps.example.biz`. `*.apps.example.biz` is then allowed, proven by HTTP-01 against the host `apps.example.biz`. The Internal Domain itself is never allowed. See [ADR-0003](docs/adr/0003-wildcards-via-http01-on-wildcard-base.md). |
| `ACME_PROXY_LISTEN` | `:443` | Listen address of the ACME server. |
| `ACME_PROXY_TLS_CERT`, `ACME_PROXY_TLS_KEY` | *required* | Certificate and key that acme-proxy itself serves. Requesters must trust it. |
| `ACME_PROXY_STATE_DIR` | `./data` | Holds the database (`acme-proxy.db`) and the Public Account (`public-account-*.json`). Back it up. |
| `ACME_PROXY_CHALLENGE_RESOLVER` | system resolver | DNS server (`host:port`) used to resolve Requesters for Internal Challenges. Must be internal DNS. |
| `ACME_PROXY_ORDER_LIFETIME` | `24h` | How long an Internal Order and its authorizations stay usable before finalize. |
| `ACME_PROXY_CHALLENGE_TIMEOUT` | `10s` | Timeout of one Internal Challenge attempt. |
| `ACME_PROXY_PUBLIC_ORDER_TIMEOUT` | `10m` | Maximum time for one Public Order, including DNS propagation. |
| `ACME_PROXY_PUBLIC_CA_DIRECTORY` | Let's Encrypt **staging** | Public CA directory URL. Use `https://acme-v02.api.letsencrypt.org/directory` for trusted certificates. Each directory gets its own Public Account. |
| `ACME_PROXY_PUBLIC_CONTACT` | *required* | Email address of the Public Account. |
| `ACME_PROXY_PUBLIC_AGREE_TOS` | *required* | Must be `true`: you agree to the Public CA's terms of service. |
| `ACME_PROXY_DNS_PROVIDER` | *required* | DNS Provider name (see below). |
| `ACME_PROXY_PUBLIC_RESOLVERS` | `1.1.1.1:53,8.8.8.8:53` | **Public** DNS resolvers used to find the public zone and check propagation. Never use internal resolvers here: on a split-horizon network they would never see the public TXT record. |
| `ACME_PROXY_PUBLIC_PROPAGATION_WAIT` | off | If set (e.g. `60s`), skip the propagation check and wait this long instead. |

### DNS Providers

The DNS Provider's credentials are read from the environment variables that [lego documents for that provider](https://go-acme.github.io/lego/dns/), e.g. `CLOUDFLARE_DNS_API_TOKEN` for `cloudflare`.

Supported: `azuredns`, `cloudflare`, `desec`, `digitalocean`, `exec`, `gandiv5`, `gcloud`, `godaddy`, `hetzner`, `httpreq`, `infomaniak`, `inwx`, `ionos`, `linode`, `namecheap`, `netcup`, `ovh`, `pdns`, `porkbun`, `rfc2136`, `route53`.

`rfc2136` covers BIND, Knot and PowerDNS through dynamic updates. `exec` and `httpreq` let you plug in anything. To add another lego provider, add one line to `pkg/public/providers.go`.

### Example

```sh
export ACME_PROXY_INTERNAL_DOMAIN=example.biz
export ACME_PROXY_WILDCARD_BASES=apps.example.biz
export ACME_PROXY_TLS_CERT=/etc/acme-proxy/tls.crt ACME_PROXY_TLS_KEY=/etc/acme-proxy/tls.key
export ACME_PROXY_STATE_DIR=/var/lib/acme-proxy
export ACME_PROXY_PUBLIC_CA_DIRECTORY=https://acme-v02.api.letsencrypt.org/directory
export ACME_PROXY_PUBLIC_CONTACT=ops@example.com ACME_PROXY_PUBLIC_AGREE_TOS=true
export ACME_PROXY_DNS_PROVIDER=cloudflare CLOUDFLARE_DNS_API_TOKEN=...
acme-proxy
```

Point Requesters at `https://<acme-proxy>/acme/directory`. For Traefik:

```yaml
certificatesResolvers:
  internal:
    acme:
      caServer: https://acme-proxy.example.biz/acme/directory
      email: ops@example.com
      storage: /data/acme.json
      httpChallenge:
        entryPoint: web   # must be reachable on port 80 from acme-proxy
```

Requesters need to trust acme-proxy's own TLS certificate (`ACME_PROXY_TLS_CERT`). For Traefik that means `LEGO_CA_CERTIFICATES` or the system trust store.

## Things to know

- **Every issued name becomes public.** Public CAs log every certificate in [Certificate Transparency](https://certificate.transparency.dev/), so all hostnames you issue for (e.g. `db01.example.biz`) can be found on sites like crt.sh, even though they don't resolve publicly. This is accepted by design; avoid sensitive hostnames.
- **Rate limits are shared.** All Requesters share one Public Account and one registered domain. Let's Encrypt allows [50 new certificates per registered domain every 7 days](https://letsencrypt.org/docs/rate-limits/), plus 5 per exact set of names. Renewals count too. Test against staging first.
- **One Public Order per Internal Order.** A Public Order is only placed after the Requester has passed every Internal Challenge and finalized ([ADR-0001](docs/adr/0001-public-order-created-at-internal-finalize.md)). A failure from the Public CA (rate limit, DNS problem) makes the Internal Order `invalid`, with the Public CA's error passed through, and is never retried. The Requester simply places a new order. Public Orders run one at a time.
- **Renewal is the Requester's job.** acme-proxy never renews on its own. It doesn't hold the private keys, so it can't.
- **Revocation** works only when signed by the Internal Account that ordered the certificate. acme-proxy forwards it through the Public Account. Revocation signed with the certificate's key, and account key-change, are not supported.
- **Wildcards** are proven with HTTP-01 against the Wildcard Base host, which is weaker than public practice ([ADR-0003](docs/adr/0003-wildcards-via-http01-on-wildcard-base.md)). Some clients, notably **Caddy**, assume wildcards need DNS-01 and may never try HTTP-01 for them. Test your client before relying on it.
- **Restarts**: Internal Orders that were waiting for the Public CA when acme-proxy stopped are marked `invalid` at startup, so Requesters start over.
- Internal Challenges follow redirects only to names in the Internal Domain (ports 80 and 443), and never echo the fetched content back to the Requester.
- Only DNS names are supported, no IP addresses. Only `http-01` is offered on the internal side. Registration is open to anything that can reach acme-proxy; the HTTP-01 check is the access control.

## Development

Requires Go 1.27 or newer.

```sh
go test ./...
```

The tests drive the Internal ACME API end to end with `golang.org/x/crypto/acme` as the Requester, using a fake Public side and fake Requester hosts. The lego-based Public side can be exercised against [Pebble](https://github.com/letsencrypt/pebble) and `pebble-challtestsrv` with the `exec` DNS Provider and `ACME_PROXY_PUBLIC_PROPAGATION_WAIT=1s`, because challtestsrv doesn't answer SOA queries.
