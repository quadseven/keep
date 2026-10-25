# What each data source can tell Keep

Research for [keep#3](https://github.com/quadseven/keep/issues/3). Read from
official API docs, OpenAPI specs and source code on 2026-10-25. No live API was
called. Where a claim could not be traced to a primary source, it says so.

## Short answer

No single source covers a device end to end. Action1 is the only source that
reports CVEs and antivirus status, and only for machines running its agent
(Windows, macOS, Linux). Beszel, Proxmox, Kubernetes, Unraid and SSH probes
cover Linux hosts, VMs and containers with versions, pending update counts and
health, but no CVEs and no antivirus. UniFi and OpenWrt/GL.iNet routers see
every client by MAC and report their own firmware and update state. Tailscale
reports OS, client version and (opt-in) serial number for every tailnet node.
muster reports only managed-app versions and identity state for Android
handsets, with no hardware identifier at all.

Joining records needs more than one key. MAC joins network views (UniFi,
router leases) to hosts (Action1, Proxmox, Unraid, SSH). Hostname is the only
key nearly every source carries, and it is the weakest. Machine ID or SMBIOS
UUID joins Kubernetes, Proxmox guests, Unraid, Beszel and SSH. Serial number
joins Action1, Tailscale posture and Unraid. Tailscale node ID lives only in
Tailscale (and in `tailscale status` on the host itself).

## Capability table

Legend: Y = exposed, P = partial or indirect, - = not exposed.

| Source | Identity | OS / firmware version | Installed software | Pending updates | Vulns (CVE) | Health | Antivirus |
|---|---|---|---|---|---|---|---|
| Action1 API | Y: name, MAC, serial, user, manufacturer | Y: OS, agent version | Y: installed software report, per-endpoint apps | Y: missing updates, reboot required | Y: CVEs, per-endpoint, remediations | P: online status, last seen, last boot | Y: Antivirus Status report (Windows) |
| UniFi Site Manager (api.ui.com) | Y: device MAC, model, host hardwareId | Y: device firmware version | - | Y: `firmwareStatus`, `updateAvailable` | - | P: status, startup time | - |
| UniFi Network API (per console) | Y: device and client MAC, IP, name | Y: device `firmwareVersion` | - | Y: device `firmwareUpdatable` | - | Y: CPU, memory, load, uptime, heartbeat | - |
| Proxmox VE API | Y: node name, VM name, VM MACs, SMBIOS UUID | Y: Proxmox package versions; guest OS via agent | P: Proxmox packages only | Y: `apt/update` list on each node | - | Y: node status, disk SMART, guest status | - |
| Kubernetes API | Y: node name, machineID, systemUUID, addresses | Y: osImage, kernel, kubelet, runtime | P: container images and digests | - | - | Y: node conditions, pod status | - |
| Tailscale API | Y: nodeId, hostname, serial (opt-in posture) | Y: os, distro name/version, client version | - | P: Tailscale client `updateAvailable` only | - | P: lastSeen, connectedToControl, key expiry | - |
| muster (Android) | P: key_id (SPKI hash), admin name, role | P: agent version only | P: versionCode of managed packages | - | - | P: last seen, check-in interval, step concerns | - |
| Beszel | Y: hostname, fingerprint (hashed host ID) | Y: OS, kernel, arch, agent version | - | Y: package update count, security count; container image updates | - | Y: CPU, mem, disk, temps, SMART, failed systemd units, battery | - |
| OpenWrt ubus/rpcd (GL.iNet) | Y: hostname, model, board; client MACs via leases | Y: release distribution/version/revision, kernel | P: via `opkg`/`apk` over rpcd file/exec ACLs | P: package upgrades; firmware check via GL.iNet API (unverified) | - | P: `system info` uptime, memory, load | - |
| SSH probe | Y: hostname, machine-id, MACs, DMI serial (root) | Y: `/etc/os-release`, `uname`, `sw_vers` | Y: package manager queries | Y: package manager queries | - (needs matching) | Y: anything a shell can read | P: ClamAV logs, XProtect version |
| Docker Engine API | P: host `/info` name and ID | Y: engine version, host OS | Y: images, tags, digests | - (needs registry compare) | - | Y: container state, health check status | - |
| Unraid API (GraphQL) | Y: hostname, serial, SMBIOS UUID, machineId, MAC | Y: Unraid version, kernel | Y: Docker containers, images | Y: container `UPDATE_AVAILABLE`; OS update via Unraid | - | Y: array, disks, containers, VMs | - |

"Vulns" means a source that itself names CVEs. Matching versions against a
vulnerability feed is a separate question (see the vulnerability-matching
research).

## Auth, rate limits and cost

| Source | Auth | Rate limit | Cost |
|---|---|---|---|
| Action1 | OAuth2 client credentials: POST `client_id` and `client_secret` to `/api/3.0/oauth2/token`, bearer token, 3600 s lifetime | Not found in a reachable primary source | Free for the first 200 endpoints, fully featured |
| UniFi Site Manager | `X-API-Key` header, key made at unifi.ui.com, read-only today | v1: 10,000 req/min; EA: 100 req/min; 429 with retry header | Free with a UI account |
| UniFi Network API | Same `X-API-Key`, either through the Site Manager connector or directly on the console | Through the connector: 100 req/min per console, 25 s timeout, 10 MB body | Free |
| Proxmox VE | API token header `PVEAPIToken=USER@REALM!TOKENID=UUID`, privileges per token | None documented | Free (AGPL); subscription only for the enterprise repo |
| Kubernetes | Service account bearer token, RBAC `get/list/watch` on nodes and pods | API Priority and Fairness on the server | Free |
| Tailscale | API access token (`tskey-api-`, 1 to 90 days) or OAuth client (`tskey-client-`) for short-lived scoped tokens | 429 "too many requests"; no published number | Personal plan free (up to 6 users, unlimited user devices) |
| muster | Administrator session from the estate IdP; devices prove a client certificate | Device report and diagnostics: once per minute per device | Free, self-hosted |
| Beszel | PocketBase auth token for a user or superuser | PocketBase rate limiter, configurable | Free (MIT), self-hosted |
| OpenWrt ubus | JSON-RPC 2.0 to `/ubus`; `session.login` returns `ubus_rpc_session`, 300 s idle timeout; rpcd ACLs | None | Free |
| GL.iNet 4.x API | JSON-RPC to `/rpc`, challenge then login returns `sid` | None found | Free |
| SSH probe | SSH key for a read-only user; root only for DMI serial | None | Free |
| Docker Engine | Unix socket (root-equivalent) or TLS client cert on TCP | None | Free |
| Unraid | `x-api-key` header, scoped keys; built in from Unraid 7.2, Connect plugin before | None documented | Included with Unraid license |

## Per-source notes

### Action1

- Endpoint record fields include `name`, `address`, `OS`, `platform`,
  `agent_version`, `user`, `MAC`, `serial`, `manufacturer`, `reboot_required`,
  `last_seen`, `last_boot_time`, `update_status` and `vulnerability_status`.
  The sample shows `serial : 0` for a VM, so serial is not always useful.
  Source: PSAction1 README, "Get-Action1 -Query Endpoints".
- Query types include `Endpoints`, `EndpointApps`, `MissingUpdates`,
  `Vulnerabilities`, `Reports`, `ReportData` and `ReportExport`. Paths:
  `/endpoints/managed/{org}`, `/updates/{org}`, `/vulnerabilities/{org}`,
  `/vulnerabilities/{org}/{cve}/endpoints`, `/reportdata/{org}/{report}/data`.
  Source: PSAction1 source and README.
- Regional base URLs: `app.action1.com`, `app.na-2.action1.com`,
  `app.eu.action1.com`, `app.au.action1.com`, `app.uk.action1.com`, each with
  `/api/3.0`. Source: PSAction1 `Private/Configuration/Action1.Hosts.ps1`.
- Antivirus: a built-in "Antivirus Status" report under Endpoint Security
  detects most major products on Windows 10/11 plus Defender, and some on
  Windows Server. The agent's data-collection page lists Antivirus Status as
  Windows data. No macOS or Linux antivirus field was found. Keep would read
  it through `ReportData`. Source: Action1 service releases and "Data
  Collected by Action1 Agent" pages (found by search; the site blocks
  automated fetches, so read the page before relying on column names).
- Platforms: Windows, macOS 12 to 26, and Linux (Debian, Ubuntu, RHEL family,
  SUSE and others, added from late 2025). Source: Action1 supported operating
  systems page.

### UniFi Site Manager API and Network API

- Site Manager `GET /v1/devices` returns, per host, devices with `id`, `mac`,
  `name`, `model`, `shortname`, `ip`, `productLine`, `status`, `version`,
  `firmwareStatus`, `updateAvailable`, `isConsole`, `isManaged`,
  `startupTime`, `adoptionTime`. `GET /v1/hosts` gives `hardwareId`,
  `ipAddress`, `type`, `reportedState`, `latestBackupTime`. Only UniFi gear;
  no client devices. Source: Site Manager OpenAPI v1.0.0.
- The Network API runs on each console. Base URL is
  `https://api.ui.com/v1/connector/consoles/{consoleId}/proxy/network/integration`
  through the cloud, or `https://{console}/proxy/network/integration` on the
  LAN. Adopted device details: `macAddress`, `model`, `firmwareVersion`,
  `firmwareUpdatable`, `state`, `ipAddress`. Latest statistics: CPU, memory,
  load averages, uptime, heartbeat. Clients (wired, wireless, VPN, Teleport):
  `macAddress`, `ipAddress`, `name`, `connectedAt`, `uplinkDeviceId`. No OS or
  software for clients. Source: Network OpenAPI v10.6.106.
- The connector needs console firmware 5.0.3 or later. A non-organization key
  only reaches the key owner's consoles. Source: Site Manager OpenAPI,
  connector description.

### Proxmox VE API

- `GET /nodes/{node}/apt/update`: "List available updates."
  `GET /nodes/{node}/apt/versions`: "Get package information for important
  Proxmox packages." `GET /nodes/{node}/status`, `GET /nodes/{node}/disks/list`
  and `GET /nodes/{node}/disks/smart` give node and disk health.
  `GET /cluster/resources` lists every node, VM and container.
- With the QEMU guest agent: `agent/get-osinfo`, `agent/get-host-name` and
  `agent/network-get-interfaces` (guest MACs and IPs). LXC:
  `lxc/{vmid}/interfaces`. VM config carries `netN` MACs and `smbios1`
  ("Specify SMBIOS type 1 fields"), whose UUID is the guest's product UUID.
- Source: Proxmox VE API viewer (`apidoc.js`) and the "Proxmox VE API" wiki
  page for token auth.

### Kubernetes API

- Node `status.nodeInfo`: `machineID` ("preferred" for unique machine
  identification), `systemUUID`, `bootID`, `kernelVersion`, `osImage` (from
  `/etc/os-release`), `kubeletVersion`, `containerRuntimeVersion`.
  `status.addresses` (Hostname, InternalIP), `status.images` (images on the
  node), and conditions. Pod `status.containerStatuses[].imageID` gives the
  running digest. Source: Kubernetes API reference, Node v1.
- Nothing about pending OS updates or CVEs.

### Tailscale API

- Device fields: `nodeId` (preferred ID), `id` (legacy), `hostname` (machine
  name), `name` (MagicDNS), `os`, `distro.name`/`version`/`codeName`,
  `clientVersion`, `updateAvailable` (Tailscale client only), `lastSeen`,
  `connectedToControl`, `expires`, `keyExpiryDisabled`, `addresses`, `tags`,
  `user`, `postureIdentity.serialNumbers`, `isExternal`.
- `postureIdentity` holds serial numbers only when the device opted in to
  posture identity collection; otherwise `{"disabled": true}`. Device
  attributes such as `node:os`, `node:osVersion`, `node:tsVersion` are also
  readable.
- Source: Tailscale API OpenAPI spec (`api.tailscale.com/api/v2`), pricing
  page for plan limits.

### muster

- The administrator API exposes `GET /v1/kith` (the roll) and
  `GET /v1/kith/{key_id}` (one device with its last report and drift). Device
  fields: `key_id` (SHA-256 of the public key), `fingerprint`, `name`,
  `admin_name`, `role`, `first_seen`, `last_seen`, `check_in_interval_s`,
  `revoked_at`, `wipe_pending_at`, and `serial`, which is the current
  certificate serial, not a hardware serial.
- `POST /v1/device/report` stores step outcomes, concerns and the
  `version_code` of managed packages. The Android agent shows its own
  `versionName` and restriction state on screen.
- No OS version, security patch level, hardware serial, MAC or IMEI is
  reported today. Answering "what Android patch level is this phone on" would
  need a muster change (the agent can read `Build.VERSION.SECURITY_PATCH`).
- Source: quadseven/muster at 694fcf2, `server/muster/api.py`,
  `server/muster/sql/0001_kith.sql`, `agent/android/.../DeviceStatus.kt`.

### Beszel

- Built on PocketBase, so the PocketBase REST API and SDKs read its
  collections: `systems`, `system_stats`, `system_details`, `containers`,
  `container_stats`, `smart_devices`, `alerts`, `alerts_history`. Beszel warns
  the data shape may change in minor releases. Source: beszel.dev REST API
  guide, Beszel migrations.
- System info: hostname, kernel, OS, arch, CPU model, cores, agent version,
  uptime, CPU/memory/disk percent, load average, battery, Wi-Fi, systemd
  service totals and failures, and `PackageUpdates` as
  `[totalUpdates, securityUpdates]`. The agent checks apt, dnf, zypper,
  pacman and apk. The Docker collector also checks image updates against
  registries. Source: Beszel `internal/entities/system/system.go`,
  `agent/package_updates.go`, `agent/docker.go` at 07e42d6.
- The agent fingerprint is a truncated SHA-256 of the gopsutil host ID, or of
  hostname plus CPU model when that fails. It is stable per machine but not
  directly comparable with other sources unless Keep hashes the same input.
  Source: `agent/fingerprint.go`.

### OpenWrt ubus/rpcd on GL.iNet routers

- `uhttpd-mod-ubus` serves JSON-RPC 2.0 at `/ubus`. `session.login` returns
  a `ubus_rpc_session`; rpcd ACLs in `/usr/share/rpcd/acl.d/` limit what a
  login can call. `system board` returns kernel, hostname, model, board name
  and `release` (distribution, version, revision, target). `system info`
  covers uptime, memory and load. Client MACs come from DHCP leases (the
  OpenWrt page shows an ACL granting read of `/tmp/dhcp.leases`). Source:
  OpenWrt ubus technical reference.
- GL.iNet 4.x firmware also has its own JSON-RPC API at `/rpc` with a
  challenge and login that returns a `sid`. The official API guide
  (dev.gl-inet.com) blocked automated fetches, so its firmware-check and
  client-list methods are unverified here. Community clients show
  `router_info` returning model and firmware version.

### SSH probes

- Whatever a shell can read: `/etc/os-release`, `uname -r`, `sw_vers` on
  macOS, `/etc/machine-id`, `ip link` MACs, DMI serial and product UUID
  (root), package lists and pending updates (`apt`, `dnf`, `brew`,
  `softwareupdate -l`), failed units, disk SMART, ClamAV scan logs, XProtect
  version. The operator's existing inventory script is this source.
- No standard schema or CVE data. Cost is per-host credentials and the code
  to parse each OS.

### Docker Engine and Unraid

- Docker Engine API (`/containers/json`, `/images/json`, `/info`) gives
  container state, health check status, image tags and digests, and the
  engine and host OS version. It has no notion of an available update; that
  needs a registry digest compare, as Beszel and the prototype script do.
  Source: Docker Engine API reference.
- Unraid's GraphQL API (`x-api-key`) exposes `InfoOs` (hostname, distro,
  release, kernel, serial), `InfoSystem` (manufacturer, model, serial, uuid,
  virtual), `machineId`, network interface `mac`, `DockerContainer` (image,
  imageId, state, status) and per-container `UpdateStatus`
  (`UP_TO_DATE`, `UPDATE_AVAILABLE`, `REBUILD_READY`, `UNKNOWN`). Source:
  unraid/api `api/generated-schema.graphql`, docs.unraid.net API pages.

## Join keys

| Key | Carried by | Caveats |
|---|---|---|
| MAC address | Action1 (`MAC`), UniFi Site Manager (`mac`, UniFi gear), UniFi Network (devices and clients), Proxmox (VM `netN`, guest agent), OpenWrt (DHCP leases), Unraid (`mac`), SSH (`ip link`) | Phones and recent OSes randomize Wi-Fi MACs per network; hosts have several NICs; VMs share a host's uplink. Best for joining network views to hosts. |
| Serial number | Action1 (`serial`), Tailscale (`postureIdentity.serialNumbers`, opt-in), Unraid (`InfoOs.serial`, `InfoSystem.serial`), SSH (DMI, root) | VMs report `0` or empty. Strongest key for physical machines, including family laptops. |
| Hostname | Action1 (`name`), Tailscale (`hostname`), Kubernetes (node name, Hostname address), Beszel (hostname), Proxmox (node, VM name, guest `get-host-name`), OpenWrt (`system board`), Unraid (`InfoOs.hostname`), UniFi clients (`name`), SSH | Nearly universal and the weakest: renamed, duplicated across households, DHCP names differ from OS names. Use as a hint, not a join. |
| Machine ID / SMBIOS UUID | Kubernetes (`machineID`, `systemUUID`), Proxmox (`smbios1` UUID), Unraid (`machineId`, `InfoSystem.uuid`), SSH (`/etc/machine-id`, product UUID), Beszel (hashed host ID) | Best key for Linux hosts and VMs. Cloned VM images can share a machine-id. |
| Tailnet node ID | Tailscale (`nodeId`); the host itself via `tailscale status --json` | Stable per node key, changes on re-authentication as a new node. |
| UniFi device/host ID | UniFi APIs only | Joins Site Manager to the per-console API, nothing else. |
| muster key_id | muster only | A new key is a new device by design; no hardware link. Join to other sources by manual mapping or by adding a hardware field to the muster report. |

A practical join order: serial, then machine ID or SMBIOS UUID, then MAC
(non-randomized), then Tailscale node ID as a stable alias once linked, and
hostname only to suggest matches for a human to confirm.

## Sources

- Action1: [PSAction1](https://github.com/Action1Corp/PSAction1) (Action1's own module, commit 6df6630); [API authentication](https://www.action1.com/api-documentation/authentication/); [Data collected by the agent](https://www.action1.com/documentation/data-collected-by-action1-agent/); [Service releases](https://www.action1.com/service-releases/); [Supported operating systems](https://www.action1.com/patch-management/operating-system-patching/); [Free edition](https://www.action1.com/free)
- UniFi: [developer.ui.com llms.txt](https://developer.ui.com/llms.txt); [Site Manager getting started](https://developer.ui.com/site-manager/v1.0.0/gettingstarted); [Site Manager OpenAPI](https://developer.ui.com/site-manager/v1.0.0/openapi.json); [Network OpenAPI](https://developer.ui.com/network/v10.6.106/openapi.json)
- Proxmox: [API viewer](https://pve.proxmox.com/pve-docs/api-viewer/); [Proxmox VE API wiki](https://pve.proxmox.com/wiki/Proxmox_VE_API)
- Kubernetes: [Node v1 reference](https://kubernetes.io/docs/reference/kubernetes-api/cluster-resources/node-v1/)
- Tailscale: [API OpenAPI spec](https://api.tailscale.com/api/v2?outputOpenapiSchema=true); [Pricing](https://tailscale.com/pricing)
- muster: [quadseven/muster](https://github.com/quadseven/muster) at 694fcf2
- Beszel: [REST API guide](https://beszel.dev/guide/rest-api); [henrygd/beszel](https://github.com/henrygd/beszel) at 07e42d6
- OpenWrt: [ubus reference](https://openwrt.org/docs/techref/ubus)
- GL.iNet: [Router 4.x API](https://dev.gl-inet.com/router-4.x-api/) (not fetched; blocked)
- Docker: [Engine API](https://docs.docker.com/reference/api/engine/)
- Unraid: [API docs](https://docs.unraid.net/API/); [generated schema](https://github.com/unraid/api/blob/main/api/generated-schema.graphql)
