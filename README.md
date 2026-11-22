# keep

Self-hosted single pane of glass for home tech: inventory, updates, vulnerabilities and health across every device.

Keep is read-only. It reads each source's API, joins the records into devices, and shows one list of what needs attention, worst first. Where a fix exists it links out to it.

## What works today

- Action1: managed endpoints, missing updates, vulnerability counts, reboot state, online state.
- UniFi Network, local console API: adopted network devices with firmware state, and connected clients.
- One page with a source status panel, a worst-first list, and folded lists for unknown, healthy and network-only devices.
- A read-only JSON API for agents: `GET /api/v1/devices` and `GET /api/v1/sources`.
- Sign-in by Tailscale identity.

Device readings live in memory, so a restart clears them until the next collection. Postgres, device history, scheduled Jobs, antivirus and the other planned sources are not built yet.

## How missing data shows up

A source that is unconfigured, unreachable, refused or malformed is labeled on the page with its reason. Its devices are never called healthy: a device is healthy only when every signal it should have was read successfully. A partial response fails the whole source, and an unknown count stays unknown rather than becoming zero.

## Running it

Keep needs Python 3.12 or later. Copy `.env.example`, fill in your own values, and export them.

```
uv sync
PYTHONPATH=src uv run uvicorn --factory keep.web:from_env --port 8080 --no-access-log --no-proxy-headers
```

A deployment installs `requirements.txt`, which pins every dependency by hash. `/livez` and `/readyz` need no sign-in.

## Security

The Security page shows operator-verified breach exposure and protective controls for each enrolled person. Keep reads them from a separate SQLite database. If `KEEP_SECURITY_DB` is unset, the section shows that it is unconfigured.

Choose a database path in a private directory outside the checkout, then initialize the database once and point `KEEP_SECURITY_DB` at it:

```sh
umask 077
sqlite3 "$KEEP_SECURITY_DB" < src/keep/security.sql
```

Use a local database editor with foreign keys enabled (`PRAGMA foreign_keys = ON`) to add enrolled people and record verifications. The `people` table holds a display name and the latest breach review. In `controls`, use the person ID and one of `equifax_freeze`, `experian_freeze`, `transunion_freeze`, `irs_ip_pin`, `ssa_lock`, `e_verify_self_lock`, `email_mfa`, or `watchtower_review`. Status is `in place`, `missing`, or `unknown`, and known statuses require a check date in `YYYY-MM-DD` format. Leave unverified values empty. Keep personal details in the database and omit credentials.

Link existing devices to a person in `device_owners`. Set `source` to `Action1` and `source_ref` to the endpoint ID, or use `UniFi` and the lowercase MAC address with colon separators. Use `label` to identify the device when there is no matching reading. The roll-up uses the inventory page's worst-first order and shows patch and firmware status from current readings. Antivirus and OS support are unknown because the existing collectors do not report them.

Record services in `services` and link their users in `service_accounts`. Enter notices in `incidents` with a report date, severity, short title, and concrete action. A `vendor` incident, including a supply-chain notice, uses `service_id` and appears for everyone linked to that service. A `breach` notice uses `person_id` and can also reference a known `service_id`. Enter `open`, `done`, or `dismissed` with its `state_checked_on` date. Update both fields together when the operator confirms a change.

## JSON API

All routes take the same sign-in as the page and answer 403 with a reason to anyone the page refuses. The API is read-only.

- `GET /api/v1/devices`: every device in page order (needs attention worst first, then unknown, healthy, and network-only clients). Each has a `status`, its findings, what is unknown about it, and the raw reading from each source.
- `GET /api/v1/sources`: each source's state and reason, matching the page's source panel.
- `GET /api/v1/security`: the Security page's per-person breach summary, dated protective controls, device roll-up, and matched incident feed. Unknown readings, counts, and dates are `null`.

An unknown count is `null`, never `0`, and a device read only from a failed source is never `healthy`.

## Sign-in

Keep expects a reverse proxy on the tailnet edge, and a mounted tailscaled socket. The proxy must overwrite two request headers:

- `X-Forwarded-For`: the client's tailnet address, one value, replacing anything the client sent.
- `X-Keep-Proxy-Token`: the shared secret in `KEEP_PROXY_TOKEN`.

With Caddy:

```
reverse_proxy http://keep.example.internal:8080 {
    header_up X-Forwarded-For {remote_host}
    header_up X-Keep-Proxy-Token {env.KEEP_PROXY_TOKEN}
}
```

`KEEP_TRUSTED_PROXY_CIDRS` lists the addresses the proxy reaches Keep from. Keep then resolves the client through tailscaled's whois and admits only `KEEP_ALLOWED_LOGINS` and `KEEP_ALLOWED_NODES`. If any of these settings is missing, nobody signs in, and the page shows source health with no device data and names what is missing.

## Requirements

- Network reach from Keep to each source. The local UniFi API needs a route to the console.
- An Action1 API credential, and a UniFi Network API key. Keep only sends read requests apart from the Action1 token exchange, but neither vendor's key is restricted to reads by this app, so scope them as tightly as your plan allows.
- This repository has no CI of its own yet. Tests and lint run by hand.
