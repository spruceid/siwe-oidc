# Demo Single Page Application for the OIDC IdP

This demo's purpose is to display the claims that are shared with Relying
Parties. It is currently deployed at https://demo-oidc.login.xyz.

## Dependencies

```sh
$ cargo install trunk
$ rustup target add wasm32-unknown-unknown
```

## Development

```sh
trunk serve --open
```

## Deploy

```sh
cp wrangler_example.toml wrangler.toml
```
And fill in `account_id` and `zone_id`.

```sh
$ source .env
$ trunk build
$ wrangler publish
```
