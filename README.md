# ACME proxy

Goal of this project is to implement a ACME proxy, which can be used to create valid certificates for an internal domain.

The proxy should implement HTTP-01 ACME challenges, to verify cert requests, and will itself use DNS-01 challenges
against trusted ACME providers (e.g. Let'sEncrypt), to create the certificates.

The internal facing ACME server will be rather bare bones, but should enable usage of a traefik or caddy server,
which only communicates with the proxy, to get a valid certificate.

The advantage of using this proxy is that you only have one place where you need to configure the API credentials for the
DNS service, and don't need to configure each host with valid credentials.
