# Registry deployment

Q-Cap ships a multi-stage registry container, Docker Compose configuration for local or small single-host deployments, and a Helm chart for Kubernetes. The base deployment is cloud-neutral and uses the registry's current filesystem backend.

`.qcap` artifacts remain portable ZIP files with independently verifiable manifests and signatures. They can be copied to object storage, release systems, plain HTTP servers, or local disk and verified without this registry.

## Runtime configuration

| Variable | Default in the container | Purpose |
| --- | --- | --- |
| `QCAP_REGISTRY_ADDR` | `:8080` | HTTP listen address |
| `QCAP_REGISTRY_STORE` | `/var/lib/qcap` | Artifact and revocation storage directory |
| `QCAP_REGISTRY_INDEX` | `/var/lib/qcap/index.json` | Persisted JSON index |
| `QCAP_REGISTRY_TOKEN` | unset | Bearer token required for artifact and revocation publishing |

Reads are public. When `QCAP_REGISTRY_TOKEN` is unset or empty, writes are also unauthenticated. Do not expose an unauthenticated registry to an untrusted network.

## Local deployment with Docker Compose

Requirements: Docker Engine with Docker Compose v2.

```sh
cp .env.example .env
# Edit .env and replace QCAP_REGISTRY_TOKEN.
docker compose up --build -d
curl http://127.0.0.1:8080/health
```

The named volume `qcap-registry-data` persists artifacts, revocations, and `index.json`. Stop the service without deleting data:

```sh
docker compose down
```

`docker compose down --volumes` deletes the registry volume and all stored data.

The Compose setup uses a non-root container, a read-only root filesystem, dropped Linux capabilities, and a writable data volume. It is suitable for local development and controlled single-host deployments; it does not configure TLS, backups, monitoring, or external identity.

## Kubernetes deployment with Helm

The chart is located at `deploy/helm/qcap-registry` and supports Kubernetes 1.25 or newer.

Build the image and publish it to a registry accessible by your cluster, or load `qcap-registry:local` into a local kind/minikube cluster:

```sh
docker build -t qcap-registry:local services/qcap-registry
helm lint deploy/helm/qcap-registry
helm template qcap-registry deploy/helm/qcap-registry
```

Create the publishing token separately from Helm values:

```sh
kubectl create namespace qcap
kubectl -n qcap create secret generic qcap-registry-auth \
  --from-literal=token='replace-with-a-random-secret'

helm upgrade --install qcap-registry deploy/helm/qcap-registry \
  --namespace qcap \
  --set image.repository=qcap-registry \
  --set image.tag=local \
  --set auth.existingSecret=qcap-registry-auth
```

For a remote image, set `image.repository` and either an immutable `image.tag` or `image.digest`. Configure `imagePullSecrets` when the image registry is private.

The chart creates a `ReadWriteOnce` persistent volume claim by default. Set `persistence.existingClaim` to reuse a managed claim, or set `persistence.enabled=false` only for disposable testing. Readiness and liveness probes use `/health`.

## Production boundaries

The current registry is a hardened prototype, not a horizontally scalable production service:

- Run exactly one replica. The filesystem index and in-process locking are not safe across multiple pods.
- Put TLS and ingress or gateway authentication in front of the service.
- Store the bearer token in a secret manager and inject it through `auth.existingSecret`; do not commit it in a values file.
- Use durable storage with snapshots and test backup/restore procedures for the data volume.
- Apply network policies so only intended publishers can reach write endpoints.
- Add logs, metrics, alerting, resource requests/limits, retention policy, and disaster-recovery procedures for your environment.
- The base chart does not provision S3-compatible storage, Postgres, Redis, OIDC, certificates, ingress, or cloud resources. Those remain separate roadmap items.
