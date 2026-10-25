# Matching versions to known vulnerabilities for free

Ticket: [quadseven/keep#4](https://github.com/quadseven/keep/issues/4). Map: [quadseven/keep#1](https://github.com/quadseven/keep/issues/1).

Researched 2026-10-25. Claims marked "probed" were checked by a live request on that date; the rest cite the owning project's docs or source.

## Question

How can Keep turn "package X version Y on host Z" and "image A at digest B" into known CVEs with severity and fix version, using only free data and tools? Compare coverage for OL9/RHEL, Debian/Ubuntu, Alpine, Proxmox, Windows, macOS, container images and Android, plus accuracy, update cadence, rate limits, offline use and license.

## Short answer

Keep stores an SBOM (package list) per host and per image digest, then matches it centrally and offline with Grype against its daily database. That one engine covers OL9, RHEL, Debian, Ubuntu, Alpine, the Debian half of Proxmox, and container images, using each distro's own advisories, so backported fixes match correctly. Windows comes from Action1's vulnerability API (free for 200 endpoints), cross-checked against the MSRC CVRF API. macOS comes from the SOFA feed, Android from the security patch level compared with the Android Security Bulletins in OSV. NVD is used only to enrich severity, never to match distro packages.

## The core accuracy rule: match against the distro, not upstream

Enterprise and stable distros backport security fixes into old version numbers. Red Hat fixed CVE-2023-0464 in RHEL 9 as `openssl-3.0.7-16.el9_2`, while upstream fixed it in 3.0.9 and 3.1.1. A matcher using NVD's upstream ranges flags the patched RHEL package as vulnerable. Trivy's docs say NVD "usually lists only upstream fix information" and can mislead for RHEL ([Trivy RHEL coverage](https://trivy.dev/latest/docs/coverage/os/rhel/)). The same holds for Debian: the security tracker records fixes as distro versions such as `3.0.22-1~deb12u1` (probed, [Debian tracker JSON](https://security-tracker.debian.org/tracker/data/json)).

Two consequences for Keep:

- Distro packages must be matched against the distro's own feed (Red Hat CSAF/VEX, Oracle ELSA, Debian tracker, Ubuntu CVE tracker, Alpine secdb), compared with that distro's version rules (rpm, dpkg, apk).
- Severity should prefer the distro's rating. Trivy uses Red Hat's Impact and falls back to NVD only when it is missing; CVE-2023-0464 is HIGH in NVD and Low at Red Hat ([Trivy RHEL coverage](https://trivy.dev/latest/docs/coverage/os/rhel/)).

## Sources compared

### OSV (osv.dev API and data dumps)

- Coverage: aggregates Debian, Ubuntu, Alpine, Red Hat, AlmaLinux, Rocky, SUSE, Android, Linux kernel, and language ecosystems (npm, PyPI, Go, Maven, crates.io and others) ([OSV data sources](https://google.github.io/osv.dev/data/)). Oracle Linux is absent from both the docs and the live `ecosystems.txt` (probed).
- Red Hat in OSV is RHSA-only (fixed advisories) and keyed by repository: a query for `openssl` in `Red Hat:enterprise_linux:9::appstream` returned nothing, while `...::baseos` returned 12 RHSAs (probed). A collector would need to know each package's repo. Red Hat itself says customers should consume its OSV records from OSV.dev ([Red Hat security data](https://access.redhat.com/security/data)).
- API: `POST /v1/query` and `/v1/querybatch`; "Currently there are no limits on the API"; 32 MiB response cap on HTTP/1.1 only ([OSV API](https://google.github.io/osv.dev/api/)). No key needed (probed).
- Offline: full and per-ecosystem zips at `gs://osv-vulnerabilities/<ECOSYSTEM>/all.zip`, plus `modified_id.csv` for incremental sync ([OSV data sources](https://google.github.io/osv.dev/data/)). Debian's zip is about 79 MB and Red Hat's about 28 MB (probed). osv-scanner reads these with `--offline` ([osv-scanner offline mode](https://google.github.io/osv-scanner/usage/offline-mode/)).
- License: per source. Red Hat and Android CC-BY 4.0, Ubuntu and Alpine CC-BY-SA 4.0, Debian and NVD conversions unlisted, Chainguard CC-BY-NC-ND 4.0 ([OSV data sources](https://google.github.io/osv.dev/data/)).
- Fit: best free source for language packages and Android bulletins; a useful second opinion for Debian, Ubuntu and Alpine. Unusable for OL9.

### NVD (CVE API 2.0 and 2.0 JSON feeds)

- Coverage: every CVE with CVSS and CPE ranges, but ranges are upstream, so it gives false positives on backported distro packages (see above).
- Rate limits: 5 requests per rolling 30 seconds without a key, 50 with a free key, with a recommendation to sleep several seconds between requests ([NVD start here](https://nvd.nist.gov/developers/start-here)).
- Feeds: 1.x JSON feeds are retired; 2.0 JSON feeds are still published, with the modified feed refreshed every two hours and covering the last eight days. NVD says the file feeds will retire "until further notice" once bulk download improves ([NVD data feeds](https://nvd.nist.gov/vuln/data-feeds), [NVD changes timeline](https://nvd.nist.gov/general/news/changes-to-feeds-and-apis)).
- License: US government work, no fee.
- Fit: severity enrichment (CVSS) and CPE matching for things with no package manager, such as router firmware. Not a matcher for OS packages.

### Trivy and Trivy DB

- Coverage: Oracle Linux, RHEL, Debian, Ubuntu, Alpine, Alma, Rocky, Amazon, SUSE and more ([Trivy OS coverage](https://trivy.dev/latest/docs/coverage/os/)). The docs table lists Oracle Linux 5 to 8, but the detector source carries an OL9 end-of-life date (2032-07-18), so OL9 is supported ([oracle.go](https://github.com/aquasecurity/trivy/blob/main/pkg/detector/ospkg/oracle/oracle.go)). Proxmox is not listed.
- Accuracy: uses Red Hat advisories with backported fix versions, reports unfixed statuses (Affected, Will Not Fix, Fix Deferred, End of Life) for RHEL, and maps Red Hat image content manifests to CPEs ([Trivy RHEL coverage](https://trivy.dev/latest/docs/coverage/os/rhel/)). Oracle Linux gets fixed and affected only, no unfixed ([Trivy Oracle coverage](https://trivy.dev/latest/docs/coverage/os/oracle/)).
- Cadence: DB "built every 6 hours" ([trivy-db](https://github.com/aquasecurity/trivy-db)).
- Offline: DB is an OCI artifact on `mirror.gcr.io`, `ghcr.io/aquasecurity/trivy-db`, Docker Hub and ECR Public; can be mirrored into a private registry and pinned with `--db-repository` and `--skip-db-update` ([Trivy DB config](https://trivy.dev/latest/docs/configuration/db/), [Trivy air-gap](https://trivy.dev/latest/docs/advanced/air-gap/)). Trivy warns the public hosts may rate limit under load.
- License: Apache-2.0 for code and the DB repo ([trivy-db](https://github.com/aquasecurity/trivy-db)); DB content inherits upstream terms.
- Risk: in March 2026 an attacker published a malicious Trivy v0.69.4 release, hijacked trivy-action tags, and pushed malicious v0.69.5 and v0.69.6 Docker Hub images (CVE-2026-33634, [GHSA-69fq-xp46-6x23](https://osv.dev/vulnerability/GHSA-69fq-xp46-6x23)). Any scanner Keep runs should be pinned by digest or checksum.

### Grype, Syft and Vunnel

- Coverage: per-distro providers for Oracle Linux (ELSA), RHEL (Red Hat Security Data API), Debian (security tracker), Ubuntu (Ubuntu CVE tracker), Alpine (secdb), Alma, Amazon, SUSE, Wolfi, Chainguard, plus GitHub advisories and NVD for language packages, plus EPSS and CISA KEV for prioritization ([Grype data sources](https://oss.anchore.com/docs/reference/grype/data-sources/)).
- Input: scans images, directories, or a Syft SBOM (`grype sbom:./sbom.json`), so matching can run apart from collection ([Grype](https://github.com/anchore/grype)).
- Cadence: the DB listing at `https://grype.anchore.io/databases/v6/latest.json` showed a build from 2026-10-25 (probed); scans fail by default when the DB is older than 5 days, configurable with `db.max-allowed-built-age` ([Grype DB guide](https://oss.anchore.com/docs/guides/vulnerability/database/)).
- Offline: the DB is one SQLite archive (`.tar.zst`) with a published checksum (probed); Keep can fetch it once per day and run with updates disabled.
- License: Apache-2.0 ([Grype](https://github.com/anchore/grype)); DB content inherits upstream terms.

### Distro security trackers (direct)

- Oracle Linux: ELSA OVAL per release, for example `com.oracle.elsa-ol9.xml.bz2` (3.5 MB, updated 2026-10-23, probed at `linux.oracle.com/security/oval/`), plus the el-errata mailing list ([el-errata archive](https://oss.oracle.com/pipermail/el-errata/)). Fixed advisories only.
- RHEL: CSAF advisories and per-CVE VEX files covering fixed and unfixed components, with a `changes.csv` for incremental sync (probed); OVAL v2 is "in maintenance mode and will be deprecated"; CC-BY 4.0 ([Red Hat security data](https://access.redhat.com/security/data)).
- Debian: one JSON of package to CVE to release with status, fixed version and urgency, about 86 MB, refreshed several times a day (probed). Includes open and unfixed CVEs.
- Alpine: `secdb.alpinelinux.org/<release>/main.json` and `community.json`, mapping each package's fixed version to CVEs (`secfixes`) for v3.2 through v3.24 and edge (probed). Fixed-only: an unfixed CVE does not appear.
- Proxmox: no machine-readable feed found. Proxmox posts PSA advisories (IDs `PSA-YEAR-COUNTER-REVISION`) in per-product forum threads after fixed packages reach the enterprise repo ([Proxmox security advisories FAQ](https://forum.proxmox.com/threads/general-faq-about-proxmox-security-advisories.149328/latest)).
- Fit: these are what Grype and Trivy already ingest. Reading them directly only pays off if Keep drops the scanner, which means reimplementing rpm, dpkg and apk version comparison.

### Microsoft (MSRC CVRF API)

- `https://api.msrc.microsoft.com/cvrf/v3.0/updates` lists monthly documents; each `cvrf/<yyyy-Mon>` document maps CVEs to products (with CPEs), KB articles and fixed builds. No key needed (probed; the 2026-Oct document had 3,012 vulnerability entries).
- Fit: an independent check that a Windows build is at or past the fixed build for each CVE. It does not see third-party apps.

### Apple

- Apple publishes no CSAF or OSV feed. Its `gdmf.apple.com/v2/pmv` endpoint lists current OS versions only ([Apple developer forums](https://developer.apple.com/forums/thread/729310)).
- SOFA, a community feed (Apache-2.0), publishes JSON per OS with each security release's version, build, CVEs and actively exploited CVEs, plus XProtect versions; it refreshes every 6 hours ([SOFA](https://github.com/macadmins/sofa), [SOFA resources](https://sofa.macadmins.io/essential-resources)). Probed: `v2/macos_data_feed.json` carries `CVEs` and `ActivelyExploitedCVEs` per release.
- Fit: macOS and iOS version to CVE list, with no agent. Third-party Mac apps need Action1.

### Android

- OSV carries the Android Security Bulletins as an `Android` ecosystem (`ASB-A-*` IDs, probed), CC-BY 4.0 ([OSV data sources](https://google.github.io/osv.dev/data/)).
- A phone reports only its security patch level (a date). Every bulletin CVE published after that date applies to the AOSP portion; vendor and chipset parts need the vendor's own bulletin. Keep can count those CVEs but cannot claim per-component precision.

### Action1

- The REST API (`https://app.action1.com/api/3.0`, OAuth bearer token) exposes `/vulnerabilities/{orgId}`, `/vulnerabilities/{orgId}/{cveId}/endpoints` and `/remediations`, with CVSS score and severity per CVE, and returns HTTP 429 with a 30-second `retry_after` when rate limited ([Action1 API docs](https://app.action1.com/apidocs/), read from the published spec bundle).
- Coverage: missing OS patches and third-party apps on Windows, macOS and Linux, based on NVD and CISA KEV; free with no feature limits for the first 200 endpoints ([Action1 vulnerability management](https://www.action1.com/documentation/vulnerability-management/), [Action1 free edition](https://www.action1.com/free-edition/)). These terms come from Action1's own pages.
- Fit: the only free source for Windows third-party app CVEs. Because it leans on NVD, Linux findings may carry the backport problem, so Keep should prefer Grype for Linux hosts that also run Action1.

## Coverage matrix

| Target | Primary (free) | Cross-check | Notes |
|---|---|---|---|
| OL9 | Grype (Oracle ELSA) | Trivy | Not in OSV. Fixed-only data. |
| RHEL 9 | Grype (Red Hat CSAF/VEX) | Trivy, OSV (RHSA) | Unfixed CVEs via VEX. OSV needs the repo name. |
| Debian | Grype (Debian tracker) | OSV, tracker JSON | Includes open CVEs. |
| Ubuntu | Grype (Ubuntu CVE tracker) | OSV | |
| Alpine | Grype (secdb) | OSV, Trivy | Fixed-only. |
| Proxmox | Grype as Debian for Debian packages | PSA forum threads | Proxmox's own packages (kernel, QEMU, pve-*) have no feed; show pending updates instead. |
| Container images | Grype on the image digest or its Syft SBOM | Trivy | Distro layer plus language packages. |
| Windows | Action1 API | MSRC CVRF | Third-party apps only via Action1. |
| macOS, iOS | SOFA feed | Action1 (macOS apps) | Matching by OS version. |
| Android | OSV Android bulletins against the patch level | | AOSP precision only. |
| Router firmware | NVD CPE match (API key) | Vendor notes | Upstream ranges; mark as low confidence. |

## Update cadence and rate limits

| Source | Cadence | Limit | Offline |
|---|---|---|---|
| Grype DB | Daily build (observed) | CDN download | Yes, one SQLite archive |
| Trivy DB | Every 6 hours | Public registries may throttle | Yes, mirror the OCI artifact |
| OSV | Continuous; `modified_id.csv` | None stated | Yes, per-ecosystem zips |
| NVD | Modified feed every 2 hours | 5 or 50 requests per 30 s | Feeds, retirement pending |
| Red Hat CSAF/VEX | Continuous; `changes.csv` | None stated | Yes |
| Debian tracker | Several times a day | None stated | Yes, one JSON |
| Alpine secdb | Daily (`last-update`) | None stated | Yes |
| MSRC CVRF | Monthly plus revisions | None stated | Yes, cache monthly docs |
| SOFA | Every 6 hours | None stated | Yes, cache JSON |
| Action1 | Agent-driven | 429, retry after 30 s | No, SaaS |

## Recommendation for Keep

1. Collect SBOMs, not verdicts. Collectors record package lists (Syft output or the raw `rpm -qa`, `dpkg-query`, `apk info` list converted to an SBOM) per host and per image digest, plus the OS release.
2. Match centrally with Grype. Keep downloads the Grype DB once a day, verifies its checksum, and re-matches every stored SBOM. A new CVE then shows up on the next DB refresh without re-probing hosts. Pin the Grype binary by checksum.
3. Use distro severity first and keep NVD CVSS, EPSS and KEV as extra fields (the Grype DB already carries EPSS and KEV).
4. Pull Windows findings from the Action1 API, honoring its 429 `retry_after`, and confirm OS patch state against MSRC CVRF.
5. Match macOS and iOS versions against SOFA, and Android patch levels against OSV's Android bulletins.
6. For Proxmox, match Debian packages through Grype and show Proxmox's own pending updates as the signal for its packages, linking the PSA threads.
7. Keep Trivy as an optional second opinion only, run from a pinned digest, given the March 2026 compromise.
8. Record each finding's source and confidence (distro feed, vendor API, or upstream NVD range) so the UI can tell a backport-aware match from a guess.
