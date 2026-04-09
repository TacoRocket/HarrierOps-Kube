# Harrier Ops Kube

Harrier Ops Kube is a Go CLI for operator-first Kubernetes recon.
It helps operators and testers answer the questions that matter fastest:

- what foothold am I really using
- what looks reachable
- which workload matters first
- which identity, secret, or escalation path should I inspect next

## Why Harrier Ops Kube

Most Kubernetes tooling is built for cluster administration, object management, or raw inventory.

Harrier Ops Kube is built for operator triage:

- ground the current session before trusting deeper output
- rank the workload, identity, and exposure paths that actually matter
- keep output readable enough that the next command is obvious

## Install

Download the right binary for your platform from GitHub Releases and extract it.

## Run It

Start with the current foothold and the cluster shape:

```bash
harrierops-kube whoami
harrierops-kube inventory
```

Then move into the visible edge and the running things that matter:

```bash
harrierops-kube exposure
harrierops-kube workloads
```

## Example Output

`harrierops-kube service-accounts`

| priority | service account | workloads | power | token posture |
| --- | --- | --- | --- | --- |
| `high` | `default/fox-admin` | `default/fox-admin` | `has cluster-wide admin-like access` | `token auto-mount is visible on 1 attached workload; legacy token secret is visible` |
| `medium` | `storefront/web` | `storefront/web-5d4f6` | `can change workloads` | `visible workloads disable token auto-mount` |

Harrier Ops Kube is not just listing Kubernetes objects.
It ranks the paths that matter, explains why they matter, and points to the next review surface.

## What Makes This Different

- Foothold-first, not just object-first
- Focused on attack paths and consequence, not raw cluster data
- Output designed for operators who need to decide what matters next

## Currently Supported Commands

| Section | Commands |
| --- | --- |
| `core` | `inventory` |
| `identity` | `whoami`, `rbac`, `service-accounts`, `permissions`, `privesc` |
| `workload` | `workloads` |
| `exposure` | `exposure` |
| `secrets` | `secrets` |

Later depth surface:

- `images`

## Kubernetes Access

Harrier Ops Kube expects existing Kubernetes access.
It is not a login manager or a custom auth flow.

The intended operator path is the Kubernetes access you already have:

- the current working `kubectl` context
- a `kubeconfig` file, usually from `~/.kube/config`
- `KUBECONFIG` when it points to a different config path

It also assumes the current machine can reach the Kubernetes API it is trying to use.
If the `kubeconfig` points to a private endpoint, you still need network reachability from the
current host.

## Current Runtime Note

The current build is fixture-backed while the live `kubectl` collectors are rebuilt.
If you want repeatable local output today, set `HARRIEROPS_KUBE_FIXTURE_DIR`:

```bash
HARRIEROPS_KUBE_FIXTURE_DIR=testdata/fixtures/lab_cluster \
  go run ./cmd/harrierops-kube whoami --output table
```

The command surface and output contracts match the operator-facing command set above.

## CLI Invocation

Shared flags include `--context`, `--namespace`, `--output`, `--outdir`, and `--debug`.
Commands come first, then shared flags or `help`.

```bash
harrierops-kube <command> [global options]
```

Examples:

```bash
harrierops-kube whoami --output json --outdir ./harrierops-kube-demo
harrierops-kube inventory --context prod-cluster --namespace payments
harrierops-kube permissions help
```

## Output Modes

- `--output table` (default)
- `--output json`
- `--output csv`

When `--outdir` is set, commands write artifacts under `<outdir>/`:

- `loot/<command>.json`
- `json/<command>.json`
- `table/<command>.txt`
- `csv/<command>.csv`

## Development

```bash
gofmt -w ./cmd ./internal
go test ./...
bash scripts/setup_local_guardrails.sh
```
