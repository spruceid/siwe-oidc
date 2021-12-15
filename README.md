# OpenID Connect Identity Provider for Sign-In with Ethereum

## Getting Started

### Dependencies

Redis, or a Redis compatible database (e.g. MemoryDB in AWS), is required.

### Starting the IdP

The Docker image is available at `ghcr.io/spruceid/siwe_oidc:0.1.0`. Here is an
example usage:
```bash
docker run -p 8000:8000 -e SIWEOIDC_ADDRESS="0.0.0.0" -e SIWEOIDC_REDIS_URL="redis://redis" ghcr.io/spruceid/siwe_oidc:latest
```

It can be configured either with the `siwe-oidc.toml` configuration file, or
through environment variables:
* `SIWEOIDC_ADDRESS` is the IP address to bind to.
* `SIWEOIDC_REDIS_URL` is the URL to the Redis instance.
* `SIWEOIDC_BASE_URL` is the URL you want to advertise in the OIDC configuration
  (e.g. `https://oidc.example.com`).
* `SIWEOIDC_RSA_PEM` is the signing key, in PEM format. One will be generated if
  none is provided.

## Development

A Docker Compose is available to test the IdP locally with Keycloak.

1. You will first need to run:
```bash
docker-compose up -d
```

2. And then edit your `/etc/hosts` to have `siwe-oidc` point to `127.0.0.1`.
   This is so both your browser, and Keycloak, can access the IdP.

3. In Keycloak, you will need to create a new IdP. You can use
   `http://siwe-oidc:8000/.well-known/openid-configuration` to fill the settings
   automatically. As for the client ID/secret, you can use `sdf`/`sdf`.
