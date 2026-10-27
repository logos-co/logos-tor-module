# logos-tor-module

`tor_module`: Tor for Logos modules, so no one has to install or run Tor themselves. It
runs [Arti](https://gitlab.torproject.org/tpo/core/arti), the Tor Project's Tor in Rust,
inside the module's own process. Modules make their requests through it over IPC: the
module learns who is asking, keeps each module's circuits apart, and opens no port. Other
programs can reach it through a SOCKS port, which the user turns on in the Tor app.

## Requests over IPC

List `tor_module` in your module's `dependencies`; the host loads it with yours. Start a
request, then ask for its response until it is done:

```text
request(spec, body) -> { "ok": true, "request": "9f1c…" }
response("9f1c…")   -> { "ok": true, "state": "pending" }
response("9f1c…")   -> { "ok": true, "state": "done", "status": 200, "headers": [["content-type", "application/grpc"]],
                         "trailers": [["grpc-status", "0"]], "body": "<base64>", "http2": true }
```

`spec` is JSON and `body` is bytes:

```json
{ "method": "POST", "url": "https://zec.rocks/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLightdInfo",
  "headers": [["content-type", "application/grpc"], ["te", "trailers"]],
  "http2": true, "isolation": "sync-3", "timeoutMs": 60000 }
```

- **https anywhere, plain http to onion services only**: Tor encrypts an onion service's
  traffic end to end, while anywhere else the exit relay would read plain http. TLS is
  checked against the Mozilla roots. Nothing on this computer or its network is reached.
- **HTTP/1.1, or HTTP/2** where the server offers it. `http2: true` asks for HTTP/2 alone,
  as gRPC needs; to an onion service it is spoken from the start (h2c). Trailers come back,
  so a gRPC client reads `grpc-status` from them.
- **Circuits:** requests with the same `isolation` may share a circuit, and an HTTP/2
  connection, as a gRPC client's calls do; with none, each request gets its own. Two
  modules never share a circuit, whatever keys they pick.
- A finished request is answered once, as `done` or `{ state: "failed", error }`, then
  forgotten. Only the module that started it may ask for it or `cancel(request)` it.
- Limits: 64 requests in flight per module, 8 MB of request body, 64 MB of response body,
  timeouts from 1 s to 10 min (60 s when unset).
- **Why ask rather than wait:** the module runs with `concurrency: "single"`, so each reply
  goes to its caller alone. A `multi` module's results travel as events that reach every
  module connected to it. Every call returns at once and requests run in the background.
- A Reconnect or Forget in the Tor app ends requests in flight: they answer
  `interrupted: Tor restarted`.

## Status

`status()` answers:

```json
{ "ok": true, "state": "ready", "progress": 100, "detail": "…", "socks": null,
  "since": 1793098512345, "joinMs": 13712, "blockage": null }
```

- `state` is `idle`, `connecting`, `ready`, `blocked` (no progress for a while) or `failed`
  (Tor could not start, or joining failed; it is tried again every minute). `detail` is
  Arti's own description.
- `blockage` names what Arti judges is in the way, while it reports something: `offline`
  (no connection opens), `filtering` (connections open, but no Tor handshake completes),
  `clock` (this computer's clock is off), `cantReachTor`, or `directory` (directory
  downloads keep failing or stalling). During the first join a stuck directory reads as
  `connecting` for 3 minutes before `blocked`: on a slow connection its downloads time out
  again and again before one completes, which Arti counts as stalls.
- **Tor starts when an app needs it.** Loaded, the module reads `idle` and makes no
  connection, so a user whose apps all skip Tor shows no Tor traffic on the network. A
  request, a `status()` call from another module, or a SOCKS client starts the join, so a
  module never reads `idle` itself. Once started, Tor runs until the module unloads.
- `socks` is the SOCKS port, `socks5h://IP:PORT`, while the user has it on; else null.
- `since` is when the state began (unix ms); `joinMs`, how long the last start took to
  be ready.
- `status_changed(payload)` carries the same reply whenever the state, the progress or
  the SOCKS port changes.
- A module that asks or makes a request counts as an app following Tor for 90 s: the Tor
  app lists it.

## The SOCKS port

Off unless the user turns it on in the Tor app, for programs outside Logos. It listens at
`127.0.0.1:9250` unless the user names another IP and port, clear of a system Tor's 9050
and Tor Browser's 9150. The choice is saved in `settings.json` in the instance directory.

- SOCKS4, 4a and 5, `CONNECT` only. Names are resolved by Tor at the exit, so use
  `socks5h` or 4a: resolving locally would leak them.
- **Circuits follow the SOCKS credentials**, as with Tor's `IsolateSOCKSAuth`: streams
  whose username and password differ never share a circuit. Streams without credentials
  can share circuits with each other.
- Onion services are reachable. A failure answers with the status Arti's own SOCKS port
  gives, onion service codes included (Tor proposal 304).
- No authentication is required, as with a system Tor: any program on this computer can
  use the port, and on an address other than loopback, any computer that reaches it.
- The port stays the same through a Reconnect. Nothing about a connection's target is
  logged.

## Managing it

The Tor app (`tor_ui`) manages it; these calls are refused to every other caller. A
`callers.json` in the instance directory, `{"modules": [...], "allowHost": true}`, admits
more, for tests; `allowHost` also lets `logosctl call` make requests.

- `usage()`: `{ ok, startedAt, sent, received, streams: { open, total }, files, memory,
  apps: [{ module, seenAt, active, sent, received, requests }], socks: { sent, received } }`.
  Bytes into Tor and out of it and the Tor streams opened since the module started; each
  module's share, and the SOCKS port's; the bytes in Arti's files; this process's memory.
  `active` is true for a module seen in the last 90 s.
- `settings()` and `set_socks(enabled, address)`: `{ ok, socks: { enabled, address,
  listening, error } }`. An address that cannot be listened on is refused, and the port
  stays as it was.
- `log_tail(lines)`: `{ ok, entries: [{ at, level, target, message }] }`, Arti's last
  log entries at INFO and up. The log is kept in memory only (500 entries), and Arti
  scrubs addresses from it.
- `reconnect()`: stops Arti and starts it again, an idle Tor included. Requests and SOCKS
  streams in flight end; their apps try again.
- `forget_data()`: the same, with Arti's state (the entry guards it picked) and its
  directory cache deleted in between. Tor picks new guards and downloads the directory
  again, about 7 MB. It fixes a join stuck on guards that stopped answering, but new
  guards also give an observer a new chance to sit at your entry, so it is no routine
  step.

## Files and cost

Arti keeps its state and its directory cache in `arti/` under the module's instance
directory, readable by the user alone. Measured on macOS with a release build:

| | |
|---|---|
| First join of the Tor network | about 14 s; 6.7 MB down, 0.6 MB up |
| Later joins, from the cached directory | under 1 s |
| Memory | about 80 MB while joining, 40–50 MB after |
| Disk | about 40 MB of directory cache |

## Building and testing

```bash
nix build .#lgx .#default        # the plugin and its package, as the host loads them

# Offline: unit tests, the SOCKS port, and requests against a fake Tor whose far side is
# an in-process TLS, HTTP/1.1 and HTTP/2 server
cargo test --manifest-path rust-lib/Cargo.toml --no-default-features

# Joins the real Tor network: a site and an onion service through the SOCKS port, a gRPC
# call to testnet.zec.rocks and the onion service with requests, then a reconnect and a
# forget (a second cold join, about 7 MB)
cargo test --manifest-path rust-lib/Cargo.toml --no-default-features --test live -- --ignored --nocapture
```

Plain `cargo` reads the optional SDK path dependency's manifest, so check out
logos-rust-sdk at the revision `flake.lock` pins into `logos-rust-sdk-src/` first, as
the unit-test workflow does.
