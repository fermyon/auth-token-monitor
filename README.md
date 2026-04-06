Monitor auth tokens for problems like upcoming expiration

# Supported Providers

Currently supported providers:
 - `github` : [GitHub](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
 - `fwf` : [Fermyon Wasm Functions](https://www.fermyon.com/wasm-functions)
 - `linode` : [Linode](https://techdocs.akamai.com/linode-api/reference/get-personal-access-tokens)
 - `tailscale`: [Tailscale](https://tailscale.com/docs/reference/key-secret-management#key-and-secret-types)

The provider will be auto-detected for each provided token.

# Usage

## GitHub

```console
$ TOKEN=$(gh auth token) auth-token-monitor --token-env-vars TOKEN
Checking "TOKEN"...
Token user login: your-github-username
Token expiration: NONE
Rate limit usage: 6 / 5000 (~0%)
OAuth scopes: gist, read:org, repo, workflow

$ OLD_TOKEN="<some expiring token>" auth-token-monitor --token-env-vars OLD_TOKEN
Checking "OLD_TOKEN"...
Token user login: your-github-username
Token expiration: 2025-07-09 21:27:10 +0000 UTC (9.1 days)
WARNING: Expiring soon!
Rate limit usage: 9 / 5000 (~0%)
OAuth scopes: read:packages

Error: checks failed for token(s): OLD_TOKEN
exit status 1
```

## FwF

Here we assume `TOKEN` in the shell environment holds the value of a FwF auth token,
e.g. procured via `spin aka auth tokens create --name mytoken`:

```console
$ ./auth-token-monitor --token-env-vars TOKEN
Checking "TOKEN" with provider "fwf"...
Token expiration: 2026-02-14 00:04:38.312316 +0000 UTC (15.1 days)
```

## Linode

The Linode provider uses the [linodego](https://github.com/linode/linodego) SDK
to call the [List Personal Access Tokens](https://techdocs.akamai.com/linode-api/reference/get-personal-access-tokens)
API. It checks the expiration of all tokens returned by the API, not just the
token used to authenticate.

```console
$ LINODE_TOKEN="<your linode personal access token>" auth-token-monitor --token-env-vars LINODE_TOKEN
Checking "LINODE_TOKEN" with provider "linode"...
Found 3 Linode personal access token(s)
  [my-cli-token] (id=123456): expiration: 2026-03-15T00:00:00Z (33.9 days)
  [ci-deploy-token] (id=123457): expiration: 2026-02-12T00:00:00Z (3.1 days)
  WARNING: Token "ci-deploy-token" expiring soon!
  [long-lived-token] (id=123458): expiration: NEVER

Error: checks failed for token(s): ci-deploy-token
exit status 1
```

## Tailscale

The Tailscale provider uses the [tailscale v2](https://github.com/tailscale/tailscale-client-go-v2) SDK
to call the [List and Get Keys](https://tailscale.com/api#tag/keys) APIs. In contrast to the other providers
supported by this program, Tailscale does not inform on the expiration date of the key/token used to query the API.
Rather, either all keys are returned that are accessible to the provided API token (or OAuth client;
see [Auth Credentials](#auth-credentials) below) or a specific key can be viewed when its key ID is provided.

Therefore, the current default is to list (and check expiration of) *all* keys in the tailnet, assuming sufficient
privileges of the supplied token or auth credentials. However, the list of keys to be checked can be filtered
via a list of IDs; see [Filtering](#filtering-by-key-ids) below.

### Auth Credentials

There are a few authentication modes for this provider:

- if `TS_API_KEY` is set, this value will be used instead of the supplied token (if different) for API requests
- if `TS_OAUTH_CLIENT_ID` and `TS_OAUTH_CLIENT_SECRET` are set, an ephemeral access token generated from the
  OAuth credentials will be used instead of the supplied token (if different) for API requests
- if there there are no credentials in the env, the supplied token will be used

Additionally, a specific tailnet can be supplied via `TAILNET`. Otherwise, `-` is used, which represents the
default tailnet associated with the API credential.

For example:

```console
$ export TS_API_KEY='...'
$ ./auth-token-monitor --token-env-vars TS_API_KEY
Checking token "TS_API_KEY" with provider "tailscale"...
No TAILNET supplied; using default tailnet associated with supplied credential
Using TS_API_KEY for API requests
Found 2 Tailscale key(s) in the - Tailnet
  [test] (id=kB45wP7bzx11CNTRL): expiration: NEVER
  [test2] (id=kVbFQqaG6F11CNTRL): expiration: 2026-03-31T18:48:44Z (1.0 days)
    Scopes: [all all:read]
  WARNING: Key "test2" (id=kVbFQqaG6F11CNTRL) expiring soon!

Error: checks failed for token(s): test2
```
```console
$ unset TS_API_KEY
$ export TS_OAUTH_CLIENT_ID='...' TS_OAUTH_CLIENT_SECRET='...'
$ export TAILNET='mytailnet'
$ ./auth-token-monitor --token-env-vars TS_OAUTH_CLIENT_SECRET
Checking token "TS_OAUTH_CLIENT_SECRET" with provider "tailscale"...
Using OAuth client to generate an access token for API requests
Found 2 Tailscale key(s) in the mytailnet Tailnet
  [test] (id=kB45wP7bzx11CNTRL): expiration: NEVER
  [test2] (id=kVbFQqaG6F11CNTRL): expiration: 2026-03-31T18:48:44Z (1.0 days)
    Scopes: [all all:read]
  WARNING: Key "test2" (id=kVbFQqaG6F11CNTRL) expiring soon!

Error: checks failed for token(s): test2
```

### Filtering by Key ID(s)

To filter which Tailscale keys are checked, supply `TS_KEY_IDS` in the environment.
The value should be a comma-delimited string of key ID(s).

For example:

```console
$ export TS_TOKEN='...'
$ export TS_KEY_IDS='kVbFQqaG6F11CNTRL'
$ ./auth-token-monitor --token-env-vars TS_TOKEN
Checking token "TS_TOKEN" with provider "tailscale"...
Using the provided token for Tailscale API requests, as neither TS_API_KEY nor OAuth credentials (TS_OAUTH_CLIENT_ID, TS_OAUTH_CLIENT_SECRET) are set
Filtering Tailscale key(s) to only include the following IDs: [kVbFQqaG6F11CNTRL]
  [test2] (id=kVbFQqaG6F11CNTRL): expiration: 2026-03-31T18:48:44Z (0.9 days)
    Scopes: [all all:read]
  WARNING: Key "test2" (id=kVbFQqaG6F11CNTRL) expiring soon!

Error: checks failed for token(s): test2
```

# Container

This repo publishes a lightweight container with
[`ko`](https://github.com/ko-build/ko).

You can build the image locally after `ko` is installed on your system via:

```bash
KO_DOCKER_REPO=<registry>/auth-token-monitor ko build --bare
```

## Github Actions

You can check expiration for a token in a Github Actions job directly using the
container, e.g. for a secret named `TEST_TOKEN`:

```yaml
jobs:
  test_token_expiration:
    runs-on: ubuntu-latest
    steps:
      - uses: docker://ghcr.io/fermyon/auth-token-monitor:latest
        with:
          args: "--token-env-vars TEST_TOKEN"
        env:
          TEST_TOKEN: ${{ secrets.TEST_TOKEN }}
```

## Tokens Dir

You can point to a directory with `--tokens-dir`, which can be convenient when
using this as an e.g. Kubernetes CronJob to mount existing Secrets to be
checked. All files in the directory will be parsed as either bare tokens or
dockerconfig JSON.
