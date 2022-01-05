# OpenID Connect Identity Provider for Sign-In with Ethereum

## Getting Started

Two versions are available, a stand-alone binary (using Axum and Redis) and a
Cloudflare Worker. They use the same code base and are selected at compile time
(compiling for `wasm32` will make the Worker version).

### Cloudflare Worker

You will need [`wrangler`](https://github.com/cloudflare/wrangler).

Then copy the configuration file template:
```bash
cp wrangler_example.toml wrangler.toml
```

Replacing the following fields:
- `account_id`: your Cloudflare account ID;
- `zone_id`: (Optional) DNS zone ID; and
- `kv_namespaces`: a KV namespace ID (created with `wrangler kv:namespace create SIWE-OIDC`).

At this point, you should be able to create/publish the worker:
```
wrangler publish
```

The IdP currently only supports having the **frontend under the same subdomain as
the API**. Here is the configuration for Cloudflare Pages:
- `Build command`: `cd js/ui && npm install && npm run build`;
- `Build output directory`: `/static`; and
- `Root directory`: `/`.
And you will need to add some rules to do the routing between the Page and the
Worker. Here are the rules for the Worker (the Page being used as the fallback
on the subdomain):
```
siweoidc.example.com/s*
siweoidc.example.com/u*
siweoidc.example.com/r*
siweoidc.example.com/a*
siweoidc.example.com/t*
siweoidc.example.com/j*
siweoidc.example.com/.w*
```

### Stand-Alone Binary

#### Dependencies

Redis, or a Redis compatible database (e.g. MemoryDB in AWS), is required.

#### Starting the IdP

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

### OIDC Functionalities

The current flow is very basic -- after the user is authenticated you will
receive an Ethereum address as the subject (`sub` field).

For the core OIDC information, it is available under
`/.well-known/openid-configuration`.

### TODO Items

* Additional information, from native projects (e.g. ENS domains), to more
  traditional ones (e.g. email).
* PKCE support (code challenge).
* Browser session support for the Worker version.

## Development

### Cloudflare Worker

```bash
wrangler dev
```
You can now use http://127.0.0.1:8787/.well-known/openid-configuration.

> At the moment it's not possible to use it end-to-end with the frontend as they
> need to share the same host (i.e. port), unless using a local load-balancer.

### Stand Alone Binary

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
