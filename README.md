Monitor auth tokens for problems like upcoming expiration

Currently supported providers:
 - `github` : [GitHub](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
 - `fwf` : [Fermyon Wasm Functions](https://www.fermyon.com/wasm-functions)
 - `linode` : [Linode](https://techdocs.akamai.com/linode-api/reference/get-personal-access-tokens)

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
