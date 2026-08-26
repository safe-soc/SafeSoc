# SafeSOC — Kubernetes Deployment (Helm)

## 1. Status

**Implemented (SS-079):** a Helm chart at `infrastructure/helm/safesoc/` that deploys the same six-service topology `docker-compose.yml` runs (OpenSearch, PostgreSQL, Redis, backend, Celery worker, Celery beat) onto a Kubernetes cluster, plus a migration Job, Kubernetes Secret, and optional Ingress/NetworkPolicy.

**What this is not:** a production-hardened, highly-available deployment. PostgreSQL, Redis, and OpenSearch each run as a single-replica `StatefulSet` — matching `docker-compose.yml`'s own single-instance-per-service setup, not a clustered/HA one. There is no chart for multi-node OpenSearch, no PgBouncer/connection pooling, no automated backups, and no Vertical/Horizontal Pod Autoscaling. Treat this chart as the Kubernetes-equivalent starting point that `docker-compose.yml` is for Docker — a working baseline to build a real production topology from, not that topology itself.

**Validation performed:** `helm lint` and `helm template` (full manifest render, including with `backend.ingress.enabled=true` and `networkPolicy.enabled=true` to exercise every conditional template), plus parsing the rendered output with PyYAML to confirm all 15 manifests are structurally valid YAML with the expected `kind`s. **No live cluster deployment was performed** — no Kubernetes cluster was available in the development environment (Docker Desktop's Kubernetes feature is not enabled here, and `kubectl cluster-info` fails to reach any API server). `kubectl apply --dry-run=client` requires a reachable API server to fetch its OpenAPI schema even in dry-run mode and could not be run either. Before a real rollout, run `helm install --dry-run` or `kubectl apply --dry-run=server` against an actual cluster.

## 2. Prerequisites

- A Kubernetes cluster (1.24+) and `kubectl` configured against it.
- Helm 3.
- A `StorageClass` capable of satisfying `ReadWriteOnce` `PersistentVolumeClaim`s (most managed clusters — EKS, GKE, AKS — provide a default one).
- A container image pushed somewhere the cluster can pull from. `values.yaml`'s default `image.repository` (`ghcr.io/safe-soc/safesoc/backend`) matches what `.github/workflows/release.yml` (SS-076) builds and pushes on a tagged release — set `image.repository`/`image.tag` to point at a self-built image instead if you're not using that workflow.

## 3. Quickstart

```bash
helm install safesoc infrastructure/helm/safesoc \
  --namespace safesoc --create-namespace
```

This works out of the box with every default value — including an auto-generated JWT secret (see §5) — but nothing is reachable from outside the cluster yet (`backend.ingress.enabled` defaults to `false`) and no AI-provider API key is set. At minimum, for a real deployment:

```bash
helm install safesoc infrastructure/helm/safesoc \
  --namespace safesoc --create-namespace \
  --set backend.ingress.enabled=true \
  --set backend.ingress.className=<your-ingress-class> \
  --set backend.ingress.host=safesoc.yourdomain.com \
  --set secrets.groqApiKey=<your-groq-key>
```

Or provide overrides via a values file:

```bash
helm install safesoc infrastructure/helm/safesoc -f my-values.yaml --namespace safesoc --create-namespace
```

To upgrade:

```bash
helm upgrade safesoc infrastructure/helm/safesoc --namespace safesoc
```

## 4. What gets deployed

| Kind | Name suffix | Purpose |
|---|---|---|
| `Deployment` | `-backend` | FastAPI app, `backend.replicaCount` replicas (default 2), liveness/readiness on `GET /health` |
| `Deployment` | `-worker` | Celery worker, `worker.replicaCount` replicas (default 2) |
| `Deployment` | `-beat` | Celery beat scheduler — **hardcoded to exactly 1 replica** in the template (not a `values.yaml` field); running more than one beat process duplicates every scheduled task (risk recalculation, weekly reports) |
| `StatefulSet` + headless `Service` | `-postgresql` | PostgreSQL 16, 1 replica, `PersistentVolumeClaim` per `postgresql.persistence.size` |
| `StatefulSet` + headless `Service` | `-redis` | Redis 7, 1 replica, PVC per `redis.persistence.size` |
| `StatefulSet` + headless `Service` | `-opensearch` | Single-node OpenSearch 2.x (`discovery.type=single-node`, matching `docker-compose.yml`), PVC per `opensearch.persistence.size` |
| `Service` (ClusterIP) | `-backend` | Stable in-cluster address for the backend Deployment |
| `Ingress` (optional) | `-backend` | Gated by `backend.ingress.enabled`, off by default |
| `NetworkPolicy` x2 (optional) | `-app-ingress`, `-backend-ingress` | Gated by `networkPolicy.enabled`, off by default — restricts postgres/redis/opensearch ingress to this release's own backend/worker/beat/migration pods, leaves backend ingress open (fronted by whatever Ingress controller the cluster provides) |
| `Job` (Helm hook) | `-migrate-<revision>` | Runs `alembic upgrade head` as a `pre-install,pre-upgrade` hook before backend/worker/beat roll out; deleted after success via `hook-delete-policy` |
| `Secret` (optional) | `-secrets` | Only created when `secrets.existingSecret` is unset — holds the Postgres password, JWT secret, and the four external API keys/tokens |

Any of `postgresql.enabled` / `redis.enabled` / `opensearch.enabled` can be set `false` to point the backend at an externally-managed instance instead (e.g. a managed RDS/ElastiCache/OpenSearch Service) — set the corresponding host via `extraEnv` (see `values.yaml`'s comment on that field) when doing so.

## 5. Secrets and the JWT secret specifically

By default the chart generates a `Secret` (`templates/secret.yaml`) from `values.yaml`'s `secrets.*` fields and `postgresql.auth.password`. Prefer `secrets.existingSecret` — a `Secret` you create and manage outside this chart (e.g. via your cluster's external-secrets integration) with the same key names (`postgres-password`, `jwt-secret`, `groq-api-key`, `virustotal-api-key`, `abuseipdb-api-key`, `telegram-bot-token`, `telegram-chat-id`) — over setting values directly for anything beyond evaluation.

If `secrets.jwtSecret` is left blank, `templates/_helpers.tpl`'s `safesoc.jwtSecret` helper generates a random 64-character value on first install. On `helm upgrade`, it reuses whatever is already in the cluster's `Secret` (via Helm's `lookup` function) rather than generating a new one — rotating the JWT secret on every upgrade would invalidate every previously-issued token. Note that `lookup` returns nothing during `helm template`/`helm lint` (no live cluster to query), so a local render always shows a freshly-generated value — this is expected, documented Helm behavior, not a bug in this chart.

## 6. LLM provider

`docker-compose.yml`'s default `OLLAMA_HOST=host.docker.internal` has no equivalent inside a real cluster, so this chart's default (`llm.provider: groq`) intentionally differs from the compose file's own default (`ollama`). To use a local model instead, set `llm.provider=ollama` and `llm.ollamaHost` to either an in-cluster Service name (if you deploy Ollama into the same cluster — not provided by this chart) or an externally-reachable address.

## 7. Limitations / not covered by this chart

- Single-replica Postgres/Redis/OpenSearch — no failover, no read replicas, no automated backup/restore.
- No multi-node OpenSearch (would require a discovery mechanism, dedicated master/data node roles, and inter-node TLS — a materially larger undertaking than this issue's scope).
- No `ServiceMonitor` bundled for Prometheus Operator users, though SS-077's `GET /metrics` endpoint on the backend Service makes adding one straightforward:
  ```yaml
  apiVersion: monitoring.coreos.com/v1
  kind: ServiceMonitor
  metadata:
    name: safesoc-backend
  spec:
    selector:
      matchLabels:
        app.kubernetes.io/name: safesoc
        app.kubernetes.io/component: backend
    endpoints:
      - port: http
        path: /metrics
  ```
- No pod autoscaling (`HorizontalPodAutoscaler`) — scale `backend.replicaCount`/`worker.replicaCount` manually or via `helm upgrade --set`.
- `cloud/` (CloudLens) is a separate application with its own Django/React stack and is not part of this chart, matching how it's a separate `docker-compose.yml` stack today (see `docs/deployment.md` §5).
