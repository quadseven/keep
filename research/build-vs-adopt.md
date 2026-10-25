# Build Keep or adopt existing open-source tools

Research for [quadseven/keep#2](https://github.com/quadseven/keep/issues/2), part of the map in [quadseven/keep#1](https://github.com/quadseven/keep/issues/1). Facts checked 2026-10-25 against official docs, repos, release pages and published container manifests. Each claim names its source. Unverified items say so.

## Question

Which open-source tools already cover most of Keep, what does each cover per front (hosts, containers, Kubernetes, routers, phones, family Windows/macOS machines), what does each cost to run on a small ARM+x86 cluster, and is Keep better as its own app, a thin layer over one tool, or a mix?

## Answer

A mix. Keep should be its own small app (data model, history, the single view, tailnet identity) that pulls from adopted collectors instead of reimplementing them:

- Fleet (free tier, osquery agents) for operator-owned Linux, macOS and Windows hosts: inventory, software, CVEs, REST API.
- Trivy Operator for Kubernetes workload vulnerabilities and SBOMs, read as CRDs.
- Action1 and UniFi Site Manager APIs for family machines and routers (already decided in the map Notes).
- The phone source named in the map (muster) for phones.

No candidate covers more than two fronts, none models "behind for N days" history across fronts, and none covers routers or unmanaged phones. A thin layer over any one tool would leave most fronts empty. A from-scratch build would reimplement endpoint agents and CVE matching, which Fleet and Trivy already do well under permissive licenses.

## Scorecard

Coverage legend: Y = native, P = partial, N = none. Fronts: H = Linux/macOS/Windows hosts, C = containers, K = Kubernetes, R = routers, Ph = phones, F = family machines in other households.

| Tool | H | C | K | R | Ph | F | License | Activity (latest release) | ARM64 server image | API | Auth |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Fleet + osquery | Y | P | N | N | P (MDM only) | P (needs agent) | MIT outside `ee/`; osquery Apache-2.0 OR GPL-2.0 | fleet-v4.93.2, 2026-10-21; osquery 5.24.0, 2026-10-09 | No (amd64 only) | REST, free | SSO free |
| Wazuh | Y | P | N | P (syslog) | N | P (needs agent) | GPL-2.0, engine AGPL-3.0 | v4.14.9, 2026-10-15 | Yes | REST | Built-in users |
| NetBox | N (manual) | N | N | N (manual) | N | N | Apache-2.0 | v4.7.3, 2026-10-13 | Yes | REST + GraphQL | Built-in, SSO |
| Homepage | P (widgets) | P | P | P (UniFi widget) | N | N | GPL-3.0 | v2.7.0, 2026-10-23 | Yes | None of its own | Password or OIDC gate |
| Glance | P (widgets) | P | N | N | N | N | AGPL-3.0 | v0.8.7, 2026-10-15 | Yes | Custom API widget | Username/password |
| Dependency-Track | N | P (SBOM upload) | P (SBOM upload) | N | N | N | Apache-2.0 | 5.2.1 and 4.14.6, 2026-10-25 | Yes | REST | Built-in, OIDC |
| Trivy Operator | N | Y (in-cluster) | Y | N | N | N | Apache-2.0 | v0.35.0, 2026-10-05 | Yes | Kubernetes CRDs | Kubernetes RBAC |
| Uptime Kuma | P (reachability) | P | N | P (ping) | N | N | MIT | 2.5.7, 2026-10-23 | Yes | No documented REST API | Password + 2FA |
| Beszel (extra) | P (metrics, SMART) | P (Docker/Podman stats) | N | N | N | N | MIT | v0.21.1, 2026-10-22 | Yes | REST | OAuth2 providers |
| Diun (extra) | N | P (image update notices) | P | N | N | N | MIT | v4.33.1, 2026-10-24 | Yes | Notifiers only | None |

Activity sources: GitHub repo and latest-release API for each repo, read 2026-10-25. Licenses: each repo's LICENSE file. ARM64: `docker manifest inspect` on the published images (fleetdm/fleet:v4.93.2 resolves to linux/amd64 only; netboxcommunity/netbox, ghcr.io/gethomepage/homepage, glanceapp/glance, dependencytrack/apiserver, louislam/uptime-kuma:2, wazuh/wazuh-manager:4.14.9, henrygd/beszel and crazymax/diun list arm64; the Trivy Operator image lists amd64 and arm64 on the mirror.gcr.io/aquasec copy).

## Per-tool findings

### Fleet and osquery

- Platforms: macOS 15+, iOS/iPadOS 17+, Windows 10 21H2+ and Server 2012+, Ubuntu 20.04+, Debian 11+, RHEL 7+, ChromeOS, Android 14+ ([Fleet FAQ](https://fleetdm.com/docs/get-started/faq)). Arm Linux and Windows agents are built with `--arch=arm64` ([enroll-hosts](https://github.com/fleetdm/fleet/blob/main/articles/enroll-hosts.md)).
- CVE detection: macOS, Windows and Linux cover apps, OS and packages from NVD, OVAL, MSRC and VulnCheck data. Android is matched on security patch level via OSV. iOS/iPadOS is not covered ([vulnerability processing](https://fleetdm.com/guides/vulnerability-processing)).
- Free vs Premium, from Fleet's own feature table ([pricing-features-table.yml](https://github.com/fleetdm/fleet/blob/main/handbook/company/pricing-features-table.yml)): Free includes device inventory, search inventory, continuous scanning, policies, reports, labels, webhooks, REST API, API-only users, SSO, multi-platform MDM and BYOD Android work profiles. Premium ($7 per host per month, [pricing](https://fleetdm.com/pricing)) adds vulnerability scores, CISA KEVs, OS update enforcement, disk encryption enforcement, and account-based iOS user enrollment. Keep needs only Free features, and can compute its own severity from OSV or NVD data if scores matter.
- Cost: needs MySQL 8.0.44+ and Redis. The smallest published reference is up to 1,000 hosts on 2 instances of 1 CPU and 2 GB RAM plus small managed MySQL and Redis ([reference architectures](https://fleetdm.com/docs/deploy/reference-architectures)). Vulnerability processing "requires considerably more resources than just running the Fleet server alone" (same vulnerability page). The server image is amd64-only, so it must schedule on x86 nodes.
- Fit: best collector for hosts the operator can install an agent on. Phones only through MDM enrollment, which an unmanaged family iPhone will not have.

### Wazuh

- Covers inventory and CVEs on Windows, macOS (NVD-based) and many Linux distributions ([vulnerability detection compatibility](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/how-it-works.html)), plus SIEM, FIM and log analysis.
- Cost: all-in-one for 1 to 25 agents needs 4 vCPU, 8 GiB RAM, 50 GB disk ([quickstart](https://documentation.wazuh.com/current/quickstart.html)). The indexer alone needs 4 GB RAM and 2 cores minimum, 16 GB and 8 cores recommended ([indexer](https://documentation.wazuh.com/current/installation-guide/wazuh-indexer/index.html)). ARM64 is supported.
- Fit: a security operations platform. Its host coverage overlaps Fleet at several times the memory, and it adds an OpenSearch-based indexer Keep does not need.

### NetBox

- A network "source of truth" for "modeling and documenting modern networks" ([NetBox docs](https://netboxlabs.com/docs/netbox/)). Requires Python 3.12+, PostgreSQL 15+, Redis 6+ ([installation](https://netboxlabs.com/docs/netbox/installation/)).
- The core docs describe no discovery. Data is entered by people or pushed by integrations. It records intended state, not observed versions, updates or CVEs.
- Fit: wrong shape. Keep observes; NetBox documents.

### Homepage and Glance

- Homepage: dashboard with service widgets, an optional password or OIDC gate since v2.0, and `HOMEPAGE_ALLOWED_HOSTS` ([installation](https://gethomepage.dev/installation/)).
- Glance: dashboard with Custom API and Extension widgets and username/password auth; it keeps only an in-memory cache cleared on config reload ([configuration](https://github.com/glanceapp/glance/blob/main/docs/configuration.md)).
- Fit: neither stores history or models devices. Either could later show a Keep tile; neither can be Keep.

### Dependency-Track

- SBOM-driven component and vulnerability analysis. v4 API server needs 2 GB RAM and 2 cores minimum, 8 GB and 4 cores recommended ([deploy-docker](https://docs.dependencytrack.org/getting-started/deploy-docker/)). v4 and v5 both ship (4.14.6 and 5.2.1 on 2026-10-25, [releases](https://github.com/DependencyTrack/dependency-track/releases)).
- It does not inventory hosts. Something must generate and upload SBOMs.
- Fit: heavy JVM service for a job Trivy Operator already does in-cluster. Revisit only if SBOM policy becomes a goal.

### Trivy Operator

- Produces VulnerabilityReport, ConfigAuditReport, ExposedSecretReport, RbacAssessmentReport, InfraAssessmentReport, ClusterComplianceReport, ClusterVulnerabilityReport and SbomReport CRDs; scans start when pods are created ([docs](https://aquasecurity.github.io/trivy-operator/latest/)). The docs flag the project as incubating with CRDs that may change.
- Fit: the Kubernetes and container-image collector. Keep reads the CRDs through the Kubernetes API; no extra database.

### Uptime Kuma

- Reachability monitors (HTTP, TCP, ping, DNS, push, Docker containers), 2FA. The README states a WebSocket SPA design instead of a REST API, and documents no REST API ([repo](https://github.com/louislam/uptime-kuma)).
- Fit: health signal only, and awkward to read programmatically. Keep's "health" front is better served by its own simple probes or by the planned metrics stack.

### Extra candidates

- Beszel: lightweight host metrics, Docker/Podman stats, SMART disk health, GPU; OAuth2 login and a REST API ([what is Beszel](https://beszel.dev/guide/what-is-beszel)). A possible health source; it does not do versions or CVEs.
- Diun: notifies when a running image has a newer tag ([repo](https://github.com/crazy-max/diun)). Useful as a pattern for "pending container updates"; Keep can do the same registry check itself, as the existing prototype already does.
- OSV-Scanner (Apache-2.0, v2.7.0, 2026-10-12, [repo](https://github.com/google/osv-scanner)): library and CLI for matching package lists to OSV data. A candidate for Keep's own CVE matching on sources that report versions but not CVEs (routers, the SSH probe).

## Auth on a tailnet

Tailscale Serve adds `Tailscale-User-Login`, `Tailscale-User-Name` and `Tailscale-User-Profile-Pic` headers on tailnet traffic, strips client-supplied copies, omits them for Funnel and tagged devices, and recommends the backend listen only on localhost ([Serve docs](https://tailscale.com/kb/1312/serve)). An own app can trust these headers directly with no login screen. Adopted tools keep their own login (Fleet SSO, Wazuh users, Homepage OIDC), so each adopted UI is one more account; Keep avoids that by reading their APIs with service tokens and showing the result itself.

## Recommendation and evidence

Build Keep as its own app over adopted collectors:

1. Coverage: the best single tool (Fleet) covers hosts well, phones only under MDM, and nothing for routers, Kubernetes or family machines without its agent. The scorecard has no row with more than two Y cells.
2. Cost: Fleet Free plus MySQL and Redis is the only sizable adoption, sized in Fleet's own references at about 2 x (1 CPU, 2 GB) for 1,000 hosts, pinned to x86 nodes. Trivy Operator is in-cluster. Wazuh (8 GiB all-in-one) and Dependency-Track (2 to 8 GB JVM) are rejected on cost against their marginal coverage.
3. License: Fleet core (MIT), osquery (Apache-2.0 OR GPL-2.0), Trivy Operator (Apache-2.0) and OSV-Scanner (Apache-2.0) are free to use behind Keep. Only Fleet Free features are needed; nothing in `ee/` is required.
4. Maintenance: every adopted project shipped a release in October 2026.
5. API: Fleet REST (free) and Trivy CRDs give Keep clean pull points; Uptime Kuma's lack of a documented REST API rules it out as a source.
6. Auth: only an own app can use Tailscale identity headers end to end with one view and no extra logins.

Open points handed to later tickets: whether Fleet runs at all in v1 or the SSH probe prototype stays the host collector until Fleet is justified; what muster reports for phones; how antivirus status maps per OS.
