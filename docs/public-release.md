# Public release operations

This repository distributes Salt Recovery Tool through **GitHub Releases**:
<https://github.com/salt-space/salt-recovery-tool/releases>.

Users download the platform installer or portable GUI/CLI binary plus the
matching checksums and licence notices. IPFS and a browser-hosted recovery app
are not part of this release. A website may link to the official release page.

## Initial v0.2.3 snapshot

The initial public `main` commit contains the tracked v0.2.3 source, public
release configuration and documentation. It has no parent commit. The original
development history, tags, Git configuration, local recordings, build outputs,
installed dependencies and environment files must not be imported.

All app manifests and lock files remain at **0.2.3**. Creating the `v0.2.3`
release tag does not create another Git commit. Later development can add new
commits normally; do not merge the private development branch into this repo.

## Administrator setup before the first push

The JSON files in `.github/` are configuration payloads, not automatically
applied GitHub settings. An administrator must apply and verify them.

### Block external pull-request CI

1. Open **Settings → Actions → Policies** and create an **Active** policy for
   **all workflows**, including workflow paths added in future pull requests.
2. Restrict allowed events to **push**, **workflow_dispatch**, and
   **workflow_call** only. PR, PR-target, PR-review, comment, workflow-run and
   other events must not be allowed. Limit actors to trusted repository roles
   (Write, Maintain and Admin) if configuring an actor restriction.
3. The equivalent event policy is [actions-policy.json](../.github/actions-policy.json).
   With an administrator-authenticated GitHub CLI:

   ```bash
   gh api --method POST \
     -H 'X-GitHub-Api-Version: 2026-03-10' \
     repos/salt-space/salt-recovery-tool/actions/policies \
     --input .github/actions-policy.json
   ```

4. Verify the policy is active, targets all workflows, and has exactly the
   allowed events above. Check inherited organization policies too.
5. Under **Actions → General**, keep default workflow permissions read-only and
   disable **Allow GitHub Actions to create and approve pull requests**. As
   additional protection, require approval for all outside collaborators;
   approval settings alone are not a permanent ban on external PR runs.
6. Keep automatic CodeQL/default-setup CI and third-party PR-triggered CI apps
   disabled if the requirement is no CI jobs from external PRs at all. These
   services must be checked separately from this repository's workflow YAML.

The checked-in workflows have no PR or comment triggers. Their jobs also require
`salt-space/salt-recovery-tool` and `main`; builds run on trusted pushes or manual
requests, and a manual release reuses the build workflow. A repository-wide
policy is necessary because an outsider can propose a *new* workflow in a PR.
The policy does not control workflows someone runs in their own public fork.

GitHub documents the policy UI and permission requirements in
[Controlling workflow execution](https://docs.github.com/en/actions/how-tos/administer/control-workflow-execution)
and the [Actions policies API](https://docs.github.com/en/rest/actions/policies).
Repository administrators or organization owners are required; Maintain access
alone is insufficient to apply this policy.

### Repository features

Keep Code, Actions and Releases available. GitHub Issues is the single public
feedback channel; usage and reporting guidance are in [SUPPORT.md](../SUPPORT.md).

Apply [repository-settings.json](../.github/repository-settings.json) to disable
Wiki, Projects and Discussions and set the download link in the repository About
section:

```bash
gh api --method PATCH repos/salt-space/salt-recovery-tool \
  --input .github/repository-settings.json
```

In the repository About/sidebar settings, hide **Packages** and retain
**Releases**. Hiding the Packages section is a presentation setting, not an
organization-wide package ban. This app publishes no npm/crates/container
packages: npm is private, Cargo publishing is disabled, and workflows have no
package publication steps or package-write permission. Leave GitHub Pages
disabled; no website deployment is needed for the app.

Protect `main` using [main-branch-ruleset.json](../.github/main-branch-ruleset.json).
This active branch ruleset blocks deletion and force pushes, with no bypass
actors. Normal fast-forward pushes by authorized maintainers remain allowed.
It does not require PR approvals or status checks; the Actions event policy
separately blocks PR-triggered workflows.

Create the branch ruleset once with administrator credentials:

```bash
gh api --method POST \
  -H 'X-GitHub-Api-Version: 2026-03-10' \
  repos/salt-space/salt-recovery-tool/rulesets \
  --input .github/main-branch-ruleset.json
```

If `Protect main` already exists, edit that ruleset instead of creating another.
Verify it under **Settings → Rules → Rulesets** and check the effective branch
rules with `gh api repos/salt-space/salt-recovery-tool/rules/branches/main`.
The response should contain `deletion` and `non_fast_forward` rules.

Maintainers must review workflow changes before merging. The release job alone
receives `contents: write` so it can create a draft and attach release files.

The target repository was already public when this checkout was prepared. Check
visibility before the first push: pushing to a public repository publishes the
source immediately. This procedure does not require a visibility change.

### Licence notices

The app's own source uses the existing MIT declaration. The pinned
`sl-dkls23` and `sl-mpc-mate` components have separate upstream terms, included
under `licenses/`; the root MIT licence does not override them. Maintainers must
ensure releases remain covered by the applicable redistribution agreement.
Installers include the licence notices as application resources. The release
workflow also attaches `THIRD_PARTY_LICENSES.zip` alongside the binaries.

## Validate and publish

Run from this checkout with Node 24 and the documented Rust/Linux prerequisites:

```bash
npm ci
npm run typecheck
cargo fmt --all -- --check
cargo test --locked -p salt-recovery-core -p salt-recovery-tool
npm run build:web
bash .github/scripts/release-info.sh version
bash .github/scripts/release-info.sh notes 0.2.3
```

The version command must print `0.2.3`. Before the first push, verify the initial
snapshot has exactly one commit and no parent:

```bash
git rev-list --count main                 # 1
git show -s --format='%P' main             # empty
git remote -v                            # salt-space/salt-recovery-tool only
git status --short                       # empty
```

Once the administrator setup above is confirmed:

```bash
git push -u origin main
```

Do not use `--mirror`, `--all`, `--tags` or a force push. The push starts **Build
desktop apps** for the trusted `main` snapshot. It does not publish a release.

For the release, open **Actions → Release → Run workflow**, select `main`, and
leave **Create a draft release** enabled. The workflow:

1. Checks the version/changelog and rejects an existing `v0.2.3` tag or release.
2. Tests and builds Linux x64, macOS universal and Windows x64.
3. Creates a draft release with the matching changelog, installers, portable
   binaries, licence notices and `SHA256SUMS.txt`.
4. Targets the exact commit that the workflow built.

Review the three platform assets, checksums and notes, then publish the draft.
Do not create the version tag manually before running the workflow. Publishing
the release creates the tag when GitHub has not already created it; neither the
tag nor the release adds a commit. The launch repository can still contain just
the initial commit.

The macOS release is ad-hoc signed and not notarized; Windows does not yet use a
publisher signing certificate. State that in the download instructions. After
publication, check that the Releases page and `releases/latest` point to the
intended release and that all listed downloads are accessible without signing in.
