# This repository is public

Everything here — code, commit history, issues, pull requests, comments,
review threads, discussions, releases, wiki pages, GitHub Pages content —
is visible to anyone on the internet, forever, including after deletion
(forks, caches, and search-engine indexes outlive an edit or a delete).
Treat every write to this repo, in any surface, as something a stranger
reads the moment you make it.

This file exists because that got violated repeatedly before it was
written down. Real personal names, a real home network's addresses, real
device identifiers, and a live unrotated credential all ended up in public
issue trackers and public git history — not through carelessness in the
code, but through ordinary conversational writing in issues, PR bodies, and
code comments, where the discipline that already existed for the shipped
code was never applied. This file is the fix: the same discipline,
extended to every surface an agent writes to, not just the diff.

## The rule

**Nothing that identifies a specific person, a specific private network,
or a specific credential may appear anywhere in this repository, in any
form, ever.** Not in code. Not in a code comment. Not in an issue body. Not
in a PR description. Not in a commit message. Not in a comment reply. Not
in a test fixture. Not "just this once because it's only in a closed
issue" — closed does not mean hidden, and neither does deleted.

This is broader than "don't commit secrets." A secret scanner catches an
API key. It does not catch a sentence like *"[a real first name]'s home
server, reachable at their usual address, needed a restart"* — nothing
there matches a secret
pattern, and it is exactly the kind of sentence that put a real name, a
real domain, and a real IP into a public tracker tonight. Write for a
stranger from the first word, not just the code.

### Concretely, never write any of the following into this repo, on any surface

- A real personal name — yours, a collaborator's, anyone's. Refer to
  people by role ("the maintainer," "the operator," "a reviewer") the same
  way this file does.
- A real hostname, domain, or subdomain that resolves to a private network
  or a real person's infrastructure (a home VPN suffix, a personal tailnet
  domain, a work-in-progress product's real URL before it's meant to be
  public). Use a placeholder that is visibly fake: `example.com`,
  `your-server.internal`, `<your-domain>`.
- A real IP address on any network you actually operate — home, cloud, or
  otherwise. Use an RFC 5737 documentation range (`192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`) or an obviously fictional one
  (`10.0.0.X` as a *labeled example* is fine; a live address copy-pasted
  from a real `curl`/`dig`/log output is not).
- A real device identifier: a serial number, a MAC address, an IMEI, a
  hardware ID, an account ID, a database GUID tied to a live system.
- A credential of any kind, live or "already rotated" — a key, a token, a
  password, a signing certificate, a webhook URL with a token embedded in
  the path. "It's already been rotated" is not a reason to leave the old
  value visible; redact it anyway, because the *pattern* (which SSM path,
  which naming convention, which provider) is itself information.
- A path that reveals a real local username (`/Users/<name>/...`,
  `C:\Users\<name>\...`) or a real machine's hostname.
- A quote attributed to a specific named person, even an accurate one.
  Paraphrase instead: "the operator decided..." not "Alice said...".
- An `@`-mention of anyone who is not already part of the conversation.
  A mention notifies that account and subscribes it to the thread, and
  neither can be undone by editing or deleting the text. `@grug` in
  particular is an unrelated real user, not the review bot: the bot is
  `grug-tribe[bot]` and takes slash commands (`/grug improve` re-runs the
  code review, `/grug recheck` re-runs the plan check). To name a handle
  in prose, put it in backticks, which GitHub does not treat as a mention.
- The name of another private repository, service, or internal system
  that isn't itself meant to be discoverable. Cross-repo references
  belong in the *private* tracker, not migrated wholesale into a public
  one.

### If you are migrating or importing content

Content that already exists elsewhere — an issue being moved from a
private repo, a comment thread being copied in, history being subtree-split
into a new repo — is not exempt from this rule because it was written
before this file existed. **Migration is not a scrub.** Before content
from anywhere else lands in this repo, on any surface, re-read it against
every bullet above and rewrite what fails. If a whole issue's substance is
inseparable from the personal/private detail it's built on, don't migrate
it — summarize the generic problem it represents instead, or leave it out.

Wholesale-copying a private issue tracker into a public one because it was
"faster" is exactly how this happened the first time.

### If you find a violation already in the repo

Fix the current tree, then say plainly in your response that older
issues/PRs/comments/history may still carry it and that this needs a
human decision, not a silent edit-and-move-on. Do not delete or rewrite
someone else's public comment without asking first — you may not always
know why it was worded that way. Editing your own agent-authored content
to remove a violation is always fine and encouraged.

## The other half: this repo must be genuinely reusable

A stranger must be able to clone this repository, supply their **own**
configuration and secrets, and have it work — without reading anything
beyond the README and an example config file to know what to change.

- Every value specific to one deployment (a hostname, an IP, a region, an
  account ID, a device identifier) is a variable, an environment variable,
  or a config file entry — never a literal baked into source, a workflow
  file, or a script.
- Ship a `.env.example` / `config.example.*` alongside any file that reads
  real config, with every key present and an obviously-placeholder value
  (`YOUR_DOMAIN_HERE`, not a real one with the last octet changed).
- If a CI/CD pipeline assumes infrastructure that doesn't ship with the
  repo (a specific runner pool, a specific cloud account, a specific
  private reusable workflow), say so explicitly in the README rather than
  let a stranger discover it as a mysterious failure. "This requires your
  own self-hosted runner and your own AWS account" is an honest
  dependency; a silent reference to `uses: <this-operator>/infra-private/...`
  is not.
- Prefer this repo's own already-public reusable workflows
  (`quadseven/infra-public/...`) over hand-rolled CI where one already
  exists — they're already written to take config as input rather than
  assume it.

## Why this file, not just a smarter secret scanner

A pattern-matching scanner catches shapes: an AWS key, a PEM block, a
32-character hex string. It cannot catch a paragraph of ordinary prose
that happens to name a real person or describe a real network in plain
words — which is where nearly everything this file exists to prevent
actually showed up. Scanners still belong in CI as a backstop for the
shapes they *can* catch; this file is the layer above that, for the judgment
a scanner doesn't have.

<!-- Everything above the next line is synced from quadseven/infra-public and replaced on every sync. Put this repo's own content below it. -->
<!-- repo-specific below -->

# Keep

Keep collects inventory, versions, update counts, health and vulnerability data from a household's devices. This repository holds only the generic product. A deployment's config lives in its operator's private infra repo, credentials live in a secret store, and collected data lives only in Keep's database.

## Current state

No product code exists yet. The tree is `README.md`, `AGENTS.md`, `CLAUDE.md` and `.grug.yaml`. There is no build, test or lint command, no `.github/workflows`, and no `.loom/validation.conf`. Issue #1 is the open map toward a buildable spec; issues #2 to #9 hold the closed decisions. Read them before proposing a design. When code lands, add its exact commands here in the same PR.

## Traps

- `.grug.yaml` is read from the base commit, so an edit applies only after merge.
- With no workflows, no leak scan runs on PRs. Before pushing, run `.github/scripts/check_private_leaks.py` from `quadseven/infra-public` with `--text-file` on each changed file and on the PR body, with the fleet deny list.
- Agent Apps cannot push `.github/workflows` changes, so adding CI or the docs-sync caller needs a person.
- No docs-sync workflow runs here. The text above the marker in `AGENTS.md` and `CLAUDE.md` matches the shared template today, but nothing keeps it so. Do not edit it by hand.

## No deployment data in git

- No hostnames, domains, tailnet names, IP addresses, MAC addresses, serial numbers, machine IDs, account IDs or people's names, in any file or GitHub text.
- No credentials, tokens or API keys, not even rotated or fake-looking ones. Read every secret from the environment or a secret store at runtime.
- No collected output. Inventory dumps, SBOMs, scan results and logs from a real network never get committed, even as fixtures.
- Every deployment-specific value is config with a placeholder in an example file.

## Collectors fail closed

- A collector that cannot reach its source, cannot authenticate, times out, or gets a malformed or partial response records the source as failed or unknown. It never reports the device as healthy, up to date or free of vulnerabilities.
- Missing data is never zero. "0 pending updates" and "0 known vulnerabilities" are claims that need a successful read behind them.
- Every network call has a connect timeout and a total timeout.
- An error is recorded with the source and the reason, and a later success does not erase it from history.

## Tests and examples

- IPv4 addresses come from the documentation ranges 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24. IPv6 addresses come from 2001:db8::/32.
- Hostnames use `example.com`, `example.net`, `.example`, `.test` or `.invalid`.
- MAC addresses use the documentation range 00:00:5E:00:53:xx.
- Serial numbers, machine IDs and account IDs are obviously fake, such as `TEST-SERIAL-0001`.
- Each collector has a test that feeds it a failure (timeout, auth error, bad payload) and asserts the failure is reported.

## Writing

- ASCII only, plain American English.
- Name the review bot as `grug-tribe[bot]` in backticks.

## How work moves here

AI brains work this repo beside the operator. No brain outranks another. **Loom does not cover this repo**: it is not on the factory's repo list, and it has no `loom:*` labels, no `.loom/validation.conf`, no station and no lanes. Do not wait for a lane or a Loom state label here. Each acts under its own GitHub App, never a person's account, and signs posts `-- <name>`.

**Claims.** Put `claim:<name>` on a ticket before starting, and create the label if this repo lacks it. Check first and skip a ticket already held. One claim per ticket: the earliest stands. No station referees claims here, so brains apply the rule themselves: a claim expires after 2 hours with no real activity, unless a comment holds it with `waiting: <what> until <time>`, or an open PR the claimer wrote and referenced holds it for up to 7 days. `claim:quadseven` is a person: leave those tickets alone. On stopping, push the work and say what is done, what is next, and the branch and head. Take over only an expired or plainly dead claim, after reading the holder's comments and open PRs.

**Labels.** No state labels. `wayfinder:*` marks the spec tickets. `needs:human` is an ask for a person; this repo has that label.

**CI and required checks.** Read them live: `gh api repos/quadseven/keep/rules/branches/main`. The ruleset requires a PR, `Grug - Chief`, `Grug - Elder` and `Grug - Guard`. All three come from the `grug` App, not from workflows. Issue #10 records Elder and Guard blocking in the App's repo config, which lives outside this repo.

- No workflow, leak scan, trust gate or close-completeness guard runs here. Any CI added later takes shared workflows from `quadseven/infra-public`, pinned by full SHA.
- Bare `#N` means this repo. Avoid refs of the form `name#N` or `owner/name#N` to other repos.

**`grug`.** The bot is `grug-tribe[bot]`, driven by slash commands in a PR comment. Its handle takes no at-sign.

- `Grug - Chief` reads the PR body. It wants `## Why` (5+ words), `## Acceptance criteria` (3+ bullets), `## Out of scope`, `Size: XS|S|M|L`, and `Refs <owner>/<repo>#N` or `Refs #N` to a ticket that is an epic or sits under one. Text in HTML comments does not count. Closing keywords are out: tickets close when their boxes are ticked.
- A body with an agent marker (such as a session link) from an App author, or a Loom lane footer, gets a neutral Chief: `Hunt Plan skipped`. Neutral passes. A body with no marker gets the full check, so write the full shape every time.
- `Grug - Elder` reviews the code by LLM. `/grug improve` re-runs it. `/grug recheck` re-runs Chief only. Five pushes in ten minutes pause Elder until `/grug resume`.
- A degraded or partial review says `Degraded review (<reason>): not a verdict`. It is not a pass, whether it concludes failure or neutral. Run `/grug improve` once the backend recovers.
- `Grug - Guard` scans for security problems. Haunt, once called Sentinel, comments when a PR closes over an unresolved critical finding. It posts no check; answer its comment and re-verify.

**Merge gate.** Rulesets enforce less than this, and this binds: `Grug - Elder` success on the head (neutral is not enough), `Grug - Chief` success or neutral, not behind base, every bot thread answered, and a test that fails without the fix. `gh pr checks` does not show threads, so read `reviewThreads` by GraphQL and `pulls/<n>/reviews`. Anyone merges what they built. A change to how brains merge, close or rewrite needs a fleet chat line and a 5 minute wait. Never use `--admin`.

**Human line.** People do: permanent deletion of records, creating, rotating or entering credentials, access grants, new spending, accepting terms. People decide: another brain's role and the fleet goal text. A second brain must agree, in writing, to clear a lane demotion, lift another brain's hold, or reopen a sound close. Everything else needs nobody. Ask with `needs:human` and one exact question. A relayed yes is not a yes. Never print a credential.

**When stuck.** Reusable workflows: `docs/reusables.md` in `quadseven/infra-public`. Chief's rules and every `/grug` verb: the README in `quadseven/grug`, whose `make chief-check` tests a body before posting. Fleet log: issue 30 in `quadseven/loom`. Poll `gh` at most once per 5 minutes.
