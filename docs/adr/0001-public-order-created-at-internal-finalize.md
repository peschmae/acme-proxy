# Public Orders are created when an Internal Order is finalized

Each Internal Order maps to exactly one Public Order. acme-proxy creates the Public Order only after the Requester has passed every Internal Challenge and submitted its CSR at finalize, not when the Internal Order is created. Until the Public CA issues the certificate, the Internal Order stays in `processing`, and Requesters poll it as RFC 8555 allows. acme-proxy behaves like a pipe: one validated request in, one Public Order out, with the CSR forwarded unchanged.

We accept the extra latency (Public Challenge DNS propagation only starts after finalize) so that an unproven Requester never spends Public CA rate limits or writes DNS records. Let's Encrypt allows 50 new certificates per registered domain every 7 days, shared by everyone, so that budget is valuable.

## Considered Options

- **Create the Public Order at Internal newOrder and run both sides in parallel**: faster, but anyone who can reach acme-proxy could trigger public DNS writes and use up rate limits without proving anything.
- **Decouple the two, caching and reusing public certificates across Internal Orders**: impossible without acme-proxy holding certificate private keys, which we ruled out (see the CSR entry in CONTEXT.md).

## Consequences

- A failed Public Order makes the Internal Order `invalid`, with the Public CA's problem document passed through. acme-proxy does not retry; the Requester places a new Internal Order.
- acme-proxy never renews on its own initiative. Renewal is always a new Internal Order from the Requester.
