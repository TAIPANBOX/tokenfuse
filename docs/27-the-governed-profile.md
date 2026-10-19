# The governed profile

`TOKENFUSE_PROFILE` decides what an unconfigured gateway does. It has two values:

- **`governed`**, the default. The gateway enforces what it advertises.
- **`observe`**, the v1.18.0 defaults, byte for byte, with one startup line saying the
  gateway enforces nothing that is not set explicitly.

The profile supplies defaults only. Every variable you set still wins over it, and
so does a policy file's own `mode`. Any other value of `TOKENFUSE_PROFILE` makes the
gateway refuse to start, naming both values (CLAUDE.md invariant 136).

## What each profile does with an unset variable

| Setting | `governed` (default) | `observe` (v1.18.0) |
|---|---|---|
| `TOKENFUSE_MODE`, the run budget | `enforce`: a call over its cap gets `402` | `shadow`: recorded, never refused |
| The agent firewall (`TOKENFUSE_FIREWALL`) | `enforce`, unless `TOKENFUSE_FIREWALL` or a policy file names a mode | `shadow` |
| The policy hook (`TOKENFUSE_WARDRYX_MODE`) | `enforce` with a closed failmode, **once `TOKENFUSE_WARDRYX_URL` is set**; off without a URL | off |
| Declassification (`/v1/fuse/declassify`) | closed unless `TOKENFUSE_DECLASSIFY_KEY` is set | open to whoever can reach it |
| The admin routes (`/v1/runs`, kill, `/v1/keys`, `/v1/policy-plane`, `/v1/agent-ids`) | refused with `403 admin_keys_required` on loopback too, until `TOKENFUSE_ADMIN_KEYS` is set | open on loopback, refused on a wide bind |
| A listener beyond loopback with nothing authenticating its callers | **refuses to start** (exit 2) | starts, with the invariant 119 warning |

The rest of the gateway is the same under both profiles. Secret scanning
(`TOKENFUSE_DLP=block`) and the metering requirement (`TOKENFUSE_REQUIRE_RUN_ID`) were
already on by default, and they stay as they are.

`TOKENFUSE_ALLOW_OPEN_OBS=1` still opens the admin routes under either profile. It is
the explicit word for "these routes are open on purpose".

## Refusing to start on a wide bind

The shipped image listens on `0.0.0.0`. Under `governed`, a listener that is not on
loopback starts only if something authenticates its callers:

- `TOKENFUSE_CLIENT_KEYS`, static keys each attributed to an agent, or
- `TOKENFUSE_AGENT_TOKENS=accept` or `require`, each agent's own short-lived token.

Otherwise the gateway exits 2, and the message names all three ways out, including
`TOKENFUSE_PROFILE=observe`.

## Reading the profile at runtime

At startup one line lists the profile and each governed setting, with where its value
came from (`profile` or `env`):

```
governance profile=governed budget=enforce(profile) firewall=enforce(profile) policy_hook=off(no-url) declassify=closed(profile) admin_routes=refused(profile) client_auth=off(profile)
```

`GET /healthz?detail=1` answers the same facts as JSON, including `"profile"`. A plain
`GET /healthz` still answers `ok`, because launchers probe it.

## Upgrading from v1.18.0

An unconfigured gateway now enforces. If you want v1.18.0's behaviour, set
`TOKENFUSE_PROFILE=observe`. A gateway that listens beyond loopback with nothing
authenticating its callers will not start until you either set `TOKENFUSE_CLIENT_KEYS`
or `TOKENFUSE_AGENT_TOKENS`, or set `TOKENFUSE_PROFILE=observe`.

A policy file that names no `mode` now runs in enforce under `governed`, where it
ran off before. Name `mode` in the file to choose, or set `TOKENFUSE_PROFILE=observe`
to keep it off.

## Limits

- The MCP credential broker reads the same profile in its own process. Under
  `governed` its policy hook is enforce with a closed failmode once
  `TOKENFUSE_WARDRYX_URL` is set, and off otherwise; under `observe` it keeps the
  defaults it has always had. The broker's startup line names only what it governs.
- A policy hook without a `TOKENFUSE_WARDRYX_URL` has nothing to call, so it stays off.
  The startup line says `no-url`.
- A policy file that names no `mode` takes the profile's firewall mode: enforce under
  `governed` (`firewall=enforce(profile)` in the startup line), off under `observe`, as
  it always was. A file that names a mode keeps it, and `TOKENFUSE_FIREWALL` still wins
  over both.
- The gate that checks the documented commands reads the documents in this repository.
  It cannot see a port a container publishes on every interface.
