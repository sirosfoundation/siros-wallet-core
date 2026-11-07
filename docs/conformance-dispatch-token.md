# CONFORMANCE_DISPATCH_TOKEN — creation and setup

The engine repo's conformance workflow (`.github/workflows/conformance.yml`)
publishes release-tag conformance reports to **conformance.siros.org** by
dispatching the conformance repo's own publish workflow (`repository_dispatch`,
event `conformance-wallet`). The dispatch needs a token — this one.

## What it is

A **GitHub fine-grained personal access token (PAT)** with exactly one
permission: **Actions: write** (the repository-dispatch right) on
**`sirosfoundation/siros-conformance`** — nothing else. It cannot read code,
cannot merge, cannot touch anything outside that one repo's dispatch
endpoint. (A classic PAT with the full `repo` scope would also work but grants
far more than the job needs; the fine-grained form is the least privilege.)

## Creating it

1. Sign in to GitHub as yourself (or the service account the org uses for
   automation), then:

   **Settings → Developer settings → Personal access tokens → Fine-grained tokens → Generate new token**

2. Fill in:

   | Field | Value |
   |---|---|
   | **Token name** | `conformance-dispatch` |
   | **Expiration** | 90 days (GitHub's cap for fine-grained tokens; set a calendar reminder to rotate — the workflow will start failing with 401/403 when it expires, which is the rotation signal) |
   | **Resource owner** | `sirosfoundation` |
   | **Repository access** | **Only select repositories** → `sirosfoundation/siros-conformance` |
   | **Permissions → Repository permissions → Actions** | **Read and write** |

   Leave every other permission **No access**. The token preview should show
   exactly one line: "Actions (read and write) — 1 repository".

3. **Generate token** — copy the value immediately (`github_pat_…`). It is
   shown once.

## Setting it in the engine repo

**`sirosfoundation/siros-wallet-core` → Settings → Secrets and variables →
Actions → New repository secret**:

| Field | Value |
|---|---|
| **Name** | `CONFORMANCE_DISPATCH_TOKEN` |
| **Secret** | *(the pasted token value)* |

No environment needed — plain repository secret, so the `conformance.yml`
workflow (no environment declared) reads it directly.

## Verifying it

Once set, trigger a release-tag conformance run (or wait for the next
release push):

```
gh run list -R sirosfoundation/siros-wallet-core --workflow conformance.yml
```

The run's **Trigger the conformance repo's publish** step should show the
dispatch succeeding (HTTP 204), and a run of the conformance repo's
**Wallet Conformance** workflow (`repository_dispatch`) should appear in
that repo's Actions tab — that's the publish landing on gh-pages /
conformance.siros.org under the tag's name.

A quick manual check without a release:

```bash
# Should list workflow runs (read is included in Actions: rw):
GH_TOKEN=<the token> gh run list -R sirosfoundation/siros-conformance --limit 1
```

## Failure modes

| Symptom | Cause |
|---|---|
| The dispatch step 403s with "Resource not accessible by integration" | The token's repository list does not include `siros-conformance` |
| The dispatch 401s | The token expired — regenerate, re-set the secret, rotate the reminder |
| The conformance repo's workflow never appears | The secret name in the engine repo is misspelled (`CONFORMANCE_DISPATCH_TOKEN` exactly) |

## Rotation

Fine-grained tokens die at their expiration date. The 90-day reminder from
step 2 is the whole procedure: regenerate a token with the same single
permission, update the one repository secret in `siros-wallet-core`. The
workflows themselves never change.