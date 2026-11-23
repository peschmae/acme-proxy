# Wildcards are proven by HTTP-01 against a configured Wildcard Base

acme-proxy issues `*.name` only when `name` is a configured Wildcard Base, and it proves the Requester's control with an HTTP-01 Internal Challenge against the host at `name`. This deliberately departs from public CA practice: Let's Encrypt and the CA/B Forum treat HTTP-01 as proving control of a single host, never of its subdomains. We accept that weaker proof because Requesters never hold DNS credentials, and HTTP-01 is the only Internal Challenge. The explicit list limits the risk to subtrees an operator has chosen to hand to whoever runs the base host.

## Considered Options

- **Reject all wildcards**: the safest choice, but it rules out legitimate wildcard use for internal subtrees.
- **Allow any wildcard at least one label below the Internal Domain**: needs no configuration, but whoever controls `app.example.biz` silently gets `*.app.example.biz`, even if other teams own hosts under it.
- **Allow `*.<Internal Domain>`**: never. A single certificate would let its holder impersonate every internal host.

## Consequences

- The Internal Domain itself can never be a Wildcard Base.
- Some ACME clients (e.g. Caddy) assume wildcards need DNS-01 and may not attempt HTTP-01 for them. Check each client before relying on this.
