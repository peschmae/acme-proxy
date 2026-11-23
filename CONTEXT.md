# acme-proxy

acme-proxy is an ACME server for the hosts of one Internal Domain. It gets publicly trusted certificates for them from a Public CA, using its own DNS-01 credentials, so the hosts never need DNS-API credentials. It works like a pipe: each validated internal request becomes exactly one public request.

## Sides

**Internal**:
The side facing internal hosts. Here acme-proxy is an ACME server.
_Avoid_: downstream, inside, local

**Public**:
The side facing the Public CA. Here acme-proxy is an ACME client.
_Avoid_: upstream, outside, external

**Requester**:
An internal host (Traefik, Caddy, certbot, etc.) that gets certificates from acme-proxy over ACME.
_Avoid_: client, host, consumer

**Public CA**:
The one publicly trusted ACME certificate authority (e.g. Let's Encrypt, or its staging environment) that an acme-proxy instance gets certificates from.
_Avoid_: upstream provider, ACME provider, issuer

## Domains

**Internal Domain**:
The single domain an acme-proxy instance serves (e.g. `example.biz`). It is reserved for internal workloads, and its public DNS has only NS and SOA records, so that Public Challenges can be answered. Serving several domains means running several instances.
_Avoid_: internal zone, private domain, managed zone

**DNS Provider**:
The service hosting the Internal Domain's public zone. acme-proxy holds the only API credentials for it, and uses them solely to answer Public Challenges.
_Avoid_: DNS backend, registrar

**Wildcard Base**:
A configured name inside the Internal Domain, never the Internal Domain itself, under which wildcard Identifiers are allowed. Controlling the host at a Wildcard Base counts as controlling every name beneath it.
_Avoid_: wildcard zone, wildcard domain

## Accounts

**Internal Account**:
A Requester's ACME account with acme-proxy. Anyone who can reach acme-proxy may create one. It is only known to acme-proxy and is never registered with the Public CA.
_Avoid_: downstream account, client account

**Public Account**:
The single ACME account that acme-proxy holds with the Public CA and uses for every Public Order.
_Avoid_: upstream account, proxy account

## Ordering

**Identifier**:
A DNS name within the Internal Domain that a certificate is requested for. A wildcard Identifier (`*.name`) is only allowed when `name` is a Wildcard Base. IP addresses and names outside the Internal Domain are never Identifiers.

**Internal Order**:
A Requester's request to acme-proxy for a certificate covering a set of Identifiers.
_Avoid_: downstream order, local order

**Public Order**:
The order acme-proxy places with the Public CA on behalf of exactly one Internal Order. It only exists once that Internal Order has been finalized.
_Avoid_: upstream order

**Internal Challenge**:
acme-proxy's HTTP-01 check, over internal DNS on port 80, that a Requester currently controls the host an Identifier points to. For a wildcard Identifier, the check is made against the Wildcard Base host. It is never reused across Internal Orders, and it is the only proof a Requester gives.
_Avoid_: downstream challenge, local validation

**Public Challenge**:
The DNS-01 challenge acme-proxy answers for the Public CA by writing a TXT record through the DNS Provider.
_Avoid_: upstream challenge

**CSR**:
The certificate signing request a Requester submits at finalize. acme-proxy forwards it to the Public CA unchanged, so it never holds a certificate private key.

**Certificate**:
The chain the Public CA issues for one Public Order, belonging to exactly one Internal Order. It is never shared or reused across Internal Orders. Renewal is always a new Internal Order from the Requester. Only the Internal Account that ordered it can revoke it, and acme-proxy forwards the revocation through the Public Account.
_Avoid_: cert bundle
