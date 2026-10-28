# logos-tor-module

`tor_module`: Tor for Logos modules, so no one has to install or run Tor themselves. It
runs [Arti](https://gitlab.torproject.org/tpo/core/arti), the Tor Project's Tor in Rust,
inside the module's own process, and offers it as a SOCKS port on loopback. Any module
that can use a SOCKS proxy can go through it: the wallets' lightwalletd, Electrum, node
and RPC connections all can.

## Using it

List `tor_module` in your module's `dependencies`; the host loads it with yours. Ask for
`status()` and use its `socks` URL as your proxy:

```json
{ "ok": true, "state": "ready", "progress": 100, "detail": "…", "socks": "socks5h://127.0.0.1:53171",
  "since": 1793098512345, "joinMs": 13712 }
```

- `state` is `connecting`, `ready`, `blocked` (no progress for a while: no network, or
  Tor blocked on this one) or `failed` (Tor could not start, or joining failed; it is
  tried again every minute). `detail` is Arti's own description.
- **Tor starts when an app asks.** Loaded, the module only opens its port: it reads
  `idle` and makes no connection, so a user whose apps all skip Tor shows no Tor traffic
  on the network. The first `status()` call from another module, or the first connection
  to the port, starts the join, so a module never reads `idle` itself. Once started, Tor
  runs until the module unloads.
- `socks` is chosen when the module loads and kept until it unloads, through reconnects.
  Ask for it each time the module loads rather than storing it.
- `since` is when the state began (unix ms); `joinMs`, how long the last start took to
  be ready.
- A connection made while Tor is still connecting waits for it.
- `status_changed(payload)` carries the same reply whenever the state, the progress or
  the port changes.
- A module that asks counts as an app following Tor, for 90 s: the Tor app lists it.

## The SOCKS port

- SOCKS4, 4a and 5, `CONNECT` only, on 127.0.0.1. Names are resolved by Tor at the exit,
  so use `socks5h` or 4a: resolving locally would leak them.
- **Circuits follow the SOCKS credentials**, as with Tor's `IsolateSOCKSAuth`: streams
  whose username and password differ never share a circuit. Send fresh random
  credentials for a fresh circuit, and different ones per purpose, so that your traffic
  and other modules' cannot be linked by a shared circuit. Streams without credentials
  can share circuits with each other.
- Onion services are reachable. A failure answers with the status Arti's own SOCKS port
  gives, onion service codes included (Tor proposal 304).
- No authentication is required, as with a system Tor: any program on this computer
  could use the port.
- Nothing about a connection's target is logged.

## Managing it

The Tor app (`tor_ui`) manages it; these calls are refused to every other caller. A
`callers.json` in the instance directory, `{"modules": [...], "allowHost": true}`, admits
more, for tests.

- `usage()`: `{ ok, startedAt, sent, received, streams: { open, total }, files, memory,
  apps: [{ module, seenAt }] }`. Bytes the apps sent into Tor and received from it, and
  the streams it opened, since the module started; the bytes in Arti's files; this
  process's memory; the modules that asked for `status()` in the last 90 s.
- `log_tail(lines)`: `{ ok, entries: [{ at, level, target, message }] }`, Arti's last
  log entries at INFO and up. The log is kept in memory only (500 entries), and Arti
  scrubs addresses from it.
- `reconnect()`: stops Arti and starts it again on the same port, an idle Tor included.
  Open streams end; their apps reconnect.
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

# Unit and SOCKS tests: no network, no module glue
cargo test --manifest-path rust-lib/Cargo.toml --no-default-features

# Joins the real Tor network and reaches a site and an onion service through the port,
# then reconnects and forgets Tor's data (a second cold join, about 7 MB)
cargo test --manifest-path rust-lib/Cargo.toml --no-default-features --test live -- --ignored --nocapture
```

Plain `cargo` reads the optional SDK path dependency's manifest, so check out
logos-rust-sdk at the revision `flake.lock` pins into `logos-rust-sdk-src/` first, as
the unit-test workflow does.
