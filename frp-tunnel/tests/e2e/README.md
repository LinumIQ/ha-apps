# FRP Tunnel add-on - E2E harness

`run.sh` runs the add-on image **outside Supervisor** against a real LinumIQ
stack (normally the dev environment) and verifies the complete path:

```
harness ──docker exec──> add-on panel (:8099) ──> APP_BASE /api/device/*
                              │
                              └─ frpc ──TLS──> frps (SERVER_ADDR:SERVER_PORT)
https://<sub>.<DOMAIN_BASE> ──> edge proxy ──> frps vhost ──> frpc ──> LOCAL_HOST:LOCAL_PORT
```

The server repository calls it from `bin/stack test addon`; it can also be run
by hand from any host with a Docker-compatible CLI.

## Interface

The harness takes no arguments (`--help` prints a summary) and is configured
through the environment only. There are **no defaults for the stack**: if any
required variable is missing it prints the usage and exits `2`, so it can
never silently run against production.

### Required environment

| Variable      | Example (dev stack)            | Meaning |
| ------------- | ------------------------------ | ------- |
| `APP_BASE`    | `https://app-dev.linumiq.net`  | Dashboard (device API). Written to the add-on's `app_base` option. |
| `API_BASE`    | `https://api-dev.linumiq.net`  | Supabase API. Written to `api_base`; used for GoTrue approval. |
| `SERVER_ADDR` | `linumiq.net`                  | Expected frps host. |
| `SERVER_PORT` | `7001`                         | Expected frps control port. |
| `DOMAIN_BASE` | `dev.linumiq.net`              | Expected public domain suffix. |
| `LOCAL_HOST`  | `whoami-e2e`                   | Service the tunnel exposes (e.g. a `traefik/whoami` container on `NETWORK`). |
| `LOCAL_PORT`  | `80`                           | Its port. |

### Approval (one of)

- `E2E_APPROVE_CMD` - a command (string, run by `bash -c`) that approves the
  pairing server-side. The `user_code` (`XXXX-XXXX`) is appended as its last
  argument and is also exported as `E2E_USER_CODE`. It must exit 0 on success.
- `E2E_EMAIL` + `E2E_PASSWORD` + `E2E_ANON_KEY` - the harness approves as that
  (existing, confirmed) user via `approve.py` (stdlib Python, no pip): password
  login at `API_BASE/auth/v1`, TOTP step-up to `aal2` (RFC 6238 implemented in
  the helper), then `POST APP_BASE/api/device/approve` with
  `Authorization: Bearer <aal2 access token>` (falls back to the `@supabase/ssr`
  session cookie for pre-2.1 dashboards).
  - `E2E_TOTP_SECRET` (base32) is required if the user already has a verified
    TOTP factor; without one, a factor is enrolled and verified on the fly and
    its secret is written to `E2E_TOTP_SECRET_FILE` (mode 600) if that is set
    (the file is also read when `E2E_TOTP_SECRET` is empty).
  - `E2E_SUBDOMAIN`: subdomain to claim. Default: keep the account's tunnel, or
    claim `e2e-addon` when it has none (a fixed name, so the edge certificate
    is reused across runs).
  - `E2E_AUTH_COOKIE_NAME`: cookie name for the fallback (default
    `sb-<first label of the API_BASE host>-auth-token`).

### Server verification (contract v2.2)

| Variable | Default | Meaning |
| -------- | ------- | ------- |
| `E2E_FRPS_CA_FILE` | - | Path (on the harness host) of the PEM CA that signed the frps certificate - what the dashboard returns as `server_ca_pem`. When set, the harness asserts that the add-on received and pinned it: `tls_mode=verified` in `/api/status`, `server_ca_pem` in the state file and `/data/frps-ca.pem` equal to this file (compared as base64, line wrapping ignored), `frps-ca.pem` is `root:frpc` 640, `frpc.toml` has `transport.tls.trustedCaFile = "/data/frps-ca.pem"` and `transport.tls.serverName = "<server_name>"`, frpc logged in (`login to server success`) without any `x509:` / `tls: failed to verify` error, and a v2.2 server sent `account_email_masked`. Without it these checks are skipped (`SKIP`, with the panel's `tls_mode`). |
| `E2E_FRPS_SERVER_NAME` | the server-provided `server_name` | Expected `server_name` (the name in the frps certificate). Without it the harness only requires a non-empty `server_name` and uses it for the `serverName` check. |
| `E2E_TLS_NEGATIVE` | `1` | With `E2E_FRPS_CA_FILE`: temporarily set `server_name` in the state to `wrong-name.invalid`, restart frpc and require that it refuses the server (`... not wrong-name.invalid`, no new login), then restore the state and require a new login. Proves the pin is enforced by frpc. `0` skips it. |
| `E2E_ACCOUNT_EMAIL_MASKED` | - | Expected `account_email_masked` (e.g. `e***@example.com`); otherwise only its presence is checked (required when `E2E_FRPS_CA_FILE` is set). |

### Optional environment

| Variable | Default | Meaning |
| -------- | ------- | ------- |
| `DOCKER` | `docker` | Container CLI (`podman` works). |
| `E2E_CREATE_ARGS` | - | Extra arguments for `$DOCKER create` of the add-on container (word-split), e.g. `--security-opt apparmor=frp_tunnel` after `sudo apparmor_parser -r -W frp-tunnel/apparmor.txt`, to run the whole flow confined by the add-on's AppArmor profile (then check `dmesg \| grep DENIED`). |
| `ADDON_IMAGE` | - | Use this image; otherwise build `frp-tunnel-e2e` with `$DOCKER build --build-arg BUILD_FROM=ghcr.io/hassio-addons/base:21.0.10 --build-arg BUILD_ARCH=<amd64\|aarch64> -t frp-tunnel-e2e frp-tunnel/`. |
| `NETWORK` | default bridge | Docker network to attach the add-on container to (must reach `LOCAL_HOST`). |
| `E2E_PIN_SERVER` | `1` | `1`: also write `server_addr`/`server_port`/`domain_base` overrides (= `SERVER_*`/`DOMAIN_BASE`) into `options.json`. `0`: leave them unset so the **server-provided** values drive `frpc.toml` (also verifies the dashboard's `FRP_SERVER_*`/`TUNNEL_DOMAIN_BASE`). Running both is recommended. |
| `E2E_PUBLIC_FROM` | `host` | Where the public HTTPS request is made from: `host` (the harness host) or `addon` (inside the add-on container). |
| `E2E_CURL_ARGS` | - | Extra curl args for the public request, e.g. `--resolve e2e-addon.dev.linumiq.net:443:127.0.0.1` or `-k`. |
| `E2E_EXPECT` | first line of `http://LOCAL_HOST:LOCAL_PORT/` | Text the public page must contain (whoami: `Hostname: <id>`). |
| `E2E_KEEP_PAIRED` | `0` | `1`: skip the final unpair (leaves a valid device token server-side). |
| `E2E_KEEP_CONTAINER` | `0` | `1`: do not remove the add-on container (debugging). |
| `E2E_ALLOWED_INGRESS_IPS` | `127.0.0.1` | Passed to the panel as `ALLOWED_INGRESS_IPS` (IPs/CIDRs). The harness drives the panel with `docker exec ... curl http://127.0.0.1:8099`, so loopback must be allowed explicitly (the add-on's default is the Supervisor ingress proxy `172.30.32.2` only - checked in a second container, see below). State-changing requests carry `Sec-Fetch-Site: same-origin` (the panel's CSRF guard refuses them otherwise). |
| `E2E_BOOT_TIMEOUT` / `E2E_PAIR_TIMEOUT` / `E2E_FRPC_TIMEOUT` / `E2E_PUBLIC_TIMEOUT` | `90` / `180` / `60` / `180` s | Timeouts. The public timeout covers on-demand certificate issuance for a new subdomain. |
| `E2E_BUILD_ARCH`, `E2E_BUILD_FROM`, `E2E_BUILD_TAG` | auto / base 21.0.10 / `frp-tunnel-e2e` | Build knobs. |

Host requirements: bash 4.4+, curl, the container CLI, python3 (GoTrue mode
only). `jq` is not needed on the host (it runs inside the add-on container).

### Exit status

`0` all checks passed - `1` at least one check failed (the last 80 container
log lines are printed with known secrets masked) - `2` usage/configuration
error. Containers are always removed (unless `E2E_KEEP_CONTAINER=1`), after a
best-effort unpair if the run stopped while paired.

## What it checks

Each check prints `PASS`, `FAIL` or `SKIP`:

1. Image built/available; container starts outside Supervisor (temporary
   `/data/options.json`; bashio's option cache is pre-seeded because the base
   image's log-level oneshot would otherwise ask the missing Supervisor API).
2. Panel healthy; fresh add-on unpaired; frpc waits; the ingress guard answers
   403 to a non-allowed client address, also with a crafted `Host: x/_health?a=`
   header and for `/_health` (no exemption). A second, unpaired container of
   the same image with the **default** allow-list (no `ALLOWED_INGRESS_IPS`)
   must answer 403 on `127.0.0.1:8099` - to root and to the unprivileged user
   `frpc` (`GET /api/status`, same-origin `POST /unpair`). A POST without
   `Sec-Fetch-Site`/`Origin` and a cross-site POST are refused (CSRF) and
   start nothing.
3. `POST /pair/start` -> `user_code` from `GET /api/status` -> approval ->
   `POST /pair/poll` until `paired`. The user code appears neither in the
   redirect URL nor in the container log.
4. `/api/status` (paired, subdomain, `public_url`, tls, `account_email_masked`);
   state file has `subdomain`, `token`, `device_token` and the server-provided
   `domain_base` (= `DOMAIN_BASE`) - plus `server_addr`/`server_port` when not
   pinned; the state is mode 600, `frpc.toml` `root:frpc` 640.
5. `frpc.toml` contains `serverAddr = "<SERVER_ADDR>"`, `serverPort = <SERVER_PORT>`,
   `customDomains = ["<sub>.<DOMAIN_BASE>"]`, `transport.tls.enable = true`,
   `loginFailExit = false`, the state's token, `localIP`/`localPort`, and passes
   `frpc verify`. With `E2E_FRPS_CA_FILE`: the server verification checks
   listed above.
6. frpc is up (`s6-svstat` up and the PID is `frpc`) as the unprivileged user
   `frpc`, logged `login to server success` (over TLS; verified when
   `E2E_FRPS_CA_FILE` is set) without certificate errors, and
   `start proxy success`. With `E2E_FRPS_CA_FILE`, `/api/status` reports
   `tls_verified=true` / `tls_login=ok` (set only after that login). The
   container is started with a dummy `SUPERVISOR_TOKEN` (as Supervisor sets a
   real one): it must be in the add-on environment
   (`/run/s6/container_environment`) but not in frpc's
   (`/proc/<frpc pid>/environ`, read as user `frpc`), which may only contain
   `PATH`, `HOME` and `TZ`.
7. `https://<sub>.<DOMAIN_BASE>/` returns the local service's content.
8. **Refresh tunnel config** works and leaves `frpc.toml` unchanged; deleting
   `frpc.toml` and restarting the frpc service re-renders it identically from
   the state. With `E2E_FRPS_CA_FILE` (and `E2E_TLS_NEGATIVE=1`): a wrong
   `serverName` is refused by frpc and the panel reports `tls_login=failed`,
   `tls_verified=false` and a red banner; the restored one logs in again
   (`tls_verified=true`). Then fail-closed: with an invalid CA in the state
   and no `/data/frps-ca.pem`, frpc is **not** started (`frpc is NOT
   started`, no `frpc.toml`, `tls_mode=blocked`, no login); restoring the
   state brings it back.
9. Neither the tunnel token nor the device token appears in the container log.
10. `POST /unpair` removes state, `frpc.toml` and the pinned CA and stops frpc,
    and revokes the device token server-side (the panel answers `ok=` only
    when the server confirmed the revocation, `error=` otherwise - which fails
    this check).

Tokens are never printed and never put on a command line (where `ps` would
show them): expected `frpc.toml` lines are matched in-shell, and the
"never logged" checks read their pattern from files in the harness's private
work directory (mode 700, files 600, removed on exit). No curl call of the
harness carries a token; should one ever need to, pass it with
`-H @file` / `--config file` from that directory, not as an argument. Do not
run the harness with `bash -x`.

## Examples

Against the dev stack, from the server (the `whoami` container must be on
`NETWORK`; the approval command is whatever the server repo provides - it
receives the user code as its last argument):

```sh
APP_BASE=https://app-dev.linumiq.net API_BASE=https://api-dev.linumiq.net \
SERVER_ADDR=linumiq.net SERVER_PORT=7001 DOMAIN_BASE=dev.linumiq.net \
LOCAL_HOST=whoami-e2e LOCAL_PORT=80 NETWORK=addon-e2e \
E2E_APPROVE_CMD="/path/to/approve-user-code" \
frp-tunnel/tests/e2e/run.sh
```

Same, approving as a test user through GoTrue:

```sh
... E2E_ANON_KEY=... E2E_EMAIL=addon-e2e@example.com E2E_PASSWORD=... \
E2E_TOTP_SECRET_FILE=/root/.addon-e2e-totp frp-tunnel/tests/e2e/run.sh
```

## Unit tests

`python3 -m unittest discover -s frp-tunnel/tests/unit -v` runs the pure logic
tests (`test_config.py`, `test_totp.py`) anywhere; the panel flow tests
(`test_app.py`, including ASGI-level tests of the ingress guard and the CSRF
check) need the panel's dependencies: `pip install --require-hashes
--only-binary=:all: -r frp-tunnel/requirements.txt` (Python 3.14, as in the
image), or run them inside the image. `FRP_MGR_DIR` points the tests at the
panel code installed in the image, and `FRP_TESTS_REQUIRE_PANEL=1` turns
missing dependencies into a failure. This is what CI runs (besides the host
run with the pinned dependencies):

```sh
docker build --build-arg BUILD_FROM=ghcr.io/hassio-addons/base:21.0.10 \
    --build-arg BUILD_ARCH=amd64 -t frp-tunnel-test frp-tunnel
docker run --rm -v "$PWD/frp-tunnel/tests:/tests:ro" \
    -e FRP_MGR_DIR=/usr/lib/frp-mgr -e FRP_TESTS_REQUIRE_PANEL=1 \
    --entrypoint python3 frp-tunnel-test \
    -m unittest discover -s /tests/unit -v
```

Without bind mounts (e.g. a remote podman):

```sh
c=$(docker create -e FRP_MGR_DIR=/usr/lib/frp-mgr -e FRP_TESTS_REQUIRE_PANEL=1 \
    --entrypoint python3 frp-tunnel-test -m unittest discover -s /tests/unit -v)
docker cp frp-tunnel/tests "$c:/tests" && docker start -a "$c"; docker rm "$c"
```

## AppArmor smoke test

`frp-tunnel/tests/apparmor-smoke.sh <image> frp-tunnel/apparmor.txt` (needs
sudo, docker and a kernel with AppArmor) loads the profile in enforce mode,
boots the image confined by it and exercises start-up, the panel, the
renderer with a pinned CA, frpc as user `frpc` with its log watcher, unpair
and `docker stop` without any backend; it fails on any `apparmor="DENIED"`
for the profile. CI
runs it on every push. For the full flow under the profile, run `run.sh` with
`E2E_CREATE_ARGS="--security-opt apparmor=frp_tunnel"`.
