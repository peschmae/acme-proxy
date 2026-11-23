# One Internal Domain per instance, publicly delegated with only NS and SOA

Each acme-proxy instance serves exactly one Internal Domain (e.g. `example.biz`), which is reserved for internal workloads. The domain is registered and delegated publicly, but its public zone contains only NS and SOA records. The real host records live only in internal DNS. The public delegation exists purely so that acme-proxy can answer DNS-01 Public Challenges through the DNS Provider's API. This lets a Public CA issue for names that nobody outside can resolve, with DNS credentials held in one place instead of on every host.

acme-proxy rejects any Identifier outside its Internal Domain at Internal newOrder with `rejectedIdentifier`, because it could never complete a Public Challenge for it. Serving several domains means running several instances. That keeps configuration flat: one Internal Domain, one DNS Provider, one Public CA and one Public Account per instance.

## Consequences

- Every issued name appears in public Certificate Transparency logs, so internal hostnames become publicly discoverable even though they don't resolve publicly. This is accepted.
- The Internal Domain is a single registered domain for Public CA rate limits (Let's Encrypt: 50 new certificates every 7 days, across all accounts), shared by every Requester.
- Internal DNS must not delegate to, or fall back to, the public zone, or internal names stop resolving.
