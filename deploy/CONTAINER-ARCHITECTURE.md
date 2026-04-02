# Container Architecture: Supply Chain Monitor

## Overview

This document describes the containerization strategy for the supply chain security
monitor. The design priorities are, in order: **security isolation** of extracted
malicious packages, **operational simplicity**, and **portability** across ECS Fargate,
EKS, and bare Docker on EC2.

---

## Architecture Decision: Single Container

**Decision:** Run download/extract/diff and LLM analysis in a single container
rather than splitting into separate microservices.

**Rationale:**

1. **The code never executes downloaded packages.** The risk surface is archive
   extraction (path traversal, symlink attacks, decompression bombs), not code
   execution. The existing Python-level guards in `_safe_tar_members` and
   `_safe_zip_members` handle path traversal. The container-level controls
   (read-only rootfs, tmpfs with noexec, dropped capabilities) provide defense
   in depth. This combination makes the extraction risk manageable within a
   single container.

2. **A two-container architecture adds operational complexity** (inter-container
   communication, shared volume coordination, deployment coupling) without
   proportional security benefit. The attack we are defending against is
   "extracted file escapes the temp directory" -- this is fully mitigated by
   tmpfs isolation with noexec, the read-only root filesystem, and the non-root
   user with no capabilities.

3. **If the threat model changes** (e.g., the tool starts executing package
   install scripts for dynamic analysis), then splitting into a sandboxed
   extraction worker and a clean analysis container would be warranted. That
   would use a message queue (SQS) between them rather than shared volumes.

---

## Security Model

### Layer 1: Application-Level Guards (existing)

- `_safe_tar_members()` in `package_diff.py` blocks path traversal in tar archives
- `_safe_zip_members()` blocks path traversal in zip/whl archives
- Symlink targets are validated to stay within the extraction directory
- No `subprocess` calls on extracted content; no `exec`/`eval` of package code

### Layer 2: Filesystem Isolation

| Mount Point   | Type    | Permissions              | Purpose                          |
|---------------|---------|--------------------------|----------------------------------|
| `/` (rootfs)  | overlay | **read-only**            | Immutable application + OS       |
| `/tmp/scm`    | tmpfs   | rw, **noexec**, nosuid, nodev | Package extraction sandbox |
| `/app/state`  | EFS/vol | rw                       | Persistent polling state         |
| `/app/logs`   | EFS/vol | rw                       | Application logs                 |
| `/app/config` | bind/secret | **read-only**        | Slack configuration              |

The critical insight: **`/tmp/scm` is tmpfs with noexec**. Even if an attacker
crafts an archive that bypasses the Python-level path guards, the extracted files:
- Cannot be executed (noexec mount)
- Cannot create device files (nodev)
- Cannot set setuid bits (nosuid)
- Are capped at 512MB (prevents decompression bombs from filling disk)
- Exist only in RAM and vanish when the container stops
- Are inaccessible from the read-only root filesystem

### Layer 3: Linux Security Controls

- **Capabilities:** ALL dropped. The monitor makes outbound HTTPS connections and
  does file I/O -- neither requires any Linux capability.
- **No-new-privileges:** Prevents privilege escalation via setuid binaries.
- **Non-root user:** UID 10001, no shell, no home directory.
- **setuid binaries stripped:** The Dockerfile removes suid/sgid bits from all
  system binaries during build.

### Layer 4: Network Isolation

The container needs outbound HTTPS (443) only. No inbound ports are exposed.

Required egress destinations:
- `pypi.org` -- PyPI JSON API and package downloads
- `registry.npmjs.org` -- npm registry API and tarball downloads
- `replicate.npmjs.com` -- npm CouchDB replication changes feed
- `hugovk.github.io` -- Top packages dataset
- `bedrock-runtime.*.amazonaws.com` -- AWS Bedrock API
- `slack.com` -- Slack API for alerts

In production, use security groups (ECS/EC2) or network policies (EKS) to
restrict egress to exactly these destinations. Deny all ingress.

### Layer 5: Resource Limits

| Resource | Limit  | Rationale                                         |
|----------|--------|---------------------------------------------------|
| Memory   | 1 GB   | Covers tmpfs (512MB) + Python overhead (512MB)    |
| CPU      | 1 vCPU | Sufficient for I/O-bound polling and diffing      |
| tmpfs    | 512 MB | Caps decompression bomb impact                    |
| PID      | (default) | No fork bombs possible -- no shell, no exec    |

---

## Temp Directory Security Deep Dive

The `TMPDIR=/tmp/scm` environment variable redirects all `tempfile.mkdtemp()` calls
in `monitor.py`, `package_diff.py`, and `analyze_diff.py` to the sandboxed tmpfs
mount.

**Lifecycle of extracted content:**

1. `tempfile.mkdtemp(prefix="scm_...")` creates a directory under `/tmp/scm/`
2. Archives are downloaded into subdirectories (`dl_old/`, `dl_new/`)
3. Archives are extracted into subdirectories (`ext_old/`, `ext_new/`)
4. Python reads extracted files to generate diff reports (text only)
5. `shutil.rmtree()` cleans up after each package is processed
6. On container restart, tmpfs is wiped completely (RAM-backed)

**What a malicious archive cannot do from `/tmp/scm`:**

- Execute code: `noexec` mount flag
- Escape to root filesystem: `read-only` root filesystem + path traversal guards
- Create device files: `nodev` mount flag
- Escalate privileges: `nosuid` + no-new-privileges + all capabilities dropped
- Fill the disk: tmpfs size capped at 512MB
- Persist across restarts: tmpfs is ephemeral

---

## AWS Credentials for Bedrock

**Preferred: IAM Task Role (ECS Fargate / EKS IRSA)**

The ECS task definition includes a `taskRoleArn` with Bedrock InvokeModel
permissions. The AWS SDK inside the container automatically picks up temporary
credentials from the ECS metadata endpoint -- no environment variables needed.

For EKS, use IAM Roles for Service Accounts (IRSA) to associate a Kubernetes
service account with the same IAM role.

**Fallback: Environment Variables**

For local development or non-AWS environments, inject:
```
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_SESSION_TOKEN=...     # if using STS temporary credentials
```

The `docker-compose.yml` passes these through from the host environment.
Never bake credentials into the image.

---

## State Persistence

The `last_serial.yaml` file tracks:
- PyPI changelog serial number (polling position)
- npm replication sequence number and epoch timestamp

**Path mapping:**

`monitor.py` writes to `Path(__file__).resolve().parent / "last_serial.yaml"` which
resolves to `/app/last_serial.yaml`. The Dockerfile creates a symlink:
`/app/last_serial.yaml -> /app/state/last_serial.yaml`

The `/app/state` directory is a volume mount:
- **docker-compose:** Named volume `scm-state`
- **ECS Fargate:** EFS volume with dedicated access point
- **EKS:** PersistentVolumeClaim backed by EFS or EBS

If state is lost, the monitor resets to the current PyPI/npm head serial and
begins watching from that point forward. No past events are re-processed.
This is acceptable for a security monitor -- a brief gap is preferable to
re-processing thousands of packages.

---

## Slack Configuration

`slack.py` reads `etc/slack.json` relative to its own `__file__` location, which
resolves to `/app/etc/slack.json`. The Dockerfile creates:
`/app/etc -> /app/config/etc` (symlink)

Provide the Slack config via:
- **docker-compose:** Bind-mount `./etc/slack.json` to `/app/config/etc/slack.json`
- **ECS Fargate:** AWS Secrets Manager injected as environment variable, or
  mounted via init container that writes to a shared volume
- **EKS:** Kubernetes Secret mounted as a file

The `slack.json` format:
```json
{
  "url": "https://slack.com/api",
  "bot_token": "xoxb-...",
  "channel": "C0123456789"
}
```

---

## Deployment Targets

### Docker Compose (local development)

```bash
# Build and run
docker compose up --build

# One-shot scan
docker compose run --rm monitor --once --debug

# PyPI only, no Slack
docker compose run --rm monitor --no-npm --interval 60
```

### ECS Fargate

Use the task definition in `deploy/ecs-task-definition.json` as a reference.
Key considerations:

1. **Service type:** Use an ECS Service (not a standalone task) with
   `desiredCount: 1` and `minimumHealthyPercent: 0`, `maximumPercent: 100`.
   This ensures exactly one instance runs, with replacement on failure.

2. **Platform version:** Use `1.4.0` or later for EFS support and tmpfs.

3. **EFS setup:** Create an EFS filesystem in the same VPC with an access point
   configured for UID/GID 10001. Security group on EFS must allow NFS (2049)
   from the Fargate security group.

4. **Networking:** Place in a private subnet with a NAT gateway for outbound
   internet access. Security group: allow all outbound on 443, deny all inbound.

5. **Secrets:** Store `slack.json` in AWS Secrets Manager. Reference it in the
   task definition's `secrets` block. The application will need a small wrapper
   script or init container to write the secret value to the filesystem, since
   `slack.py` reads from a file, not an environment variable.

6. **Auto-recovery:** ECS will restart the task if it exits or fails the health
   check. Configure CloudWatch alarms on ECS service events for operational
   awareness.

### EKS

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: supply-chain-monitor
  namespace: security
spec:
  replicas: 1
  strategy:
    type: Recreate  # Only one instance should run at a time
  selector:
    matchLabels:
      app: supply-chain-monitor
  template:
    metadata:
      labels:
        app: supply-chain-monitor
    spec:
      serviceAccountName: scm-service-account  # IRSA for Bedrock access
      automountServiceAccountToken: false
      securityContext:
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: monitor
          image: <ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com/supply-chain-monitor:latest
          args: ["--slack", "--interval", "300"]
          securityContext:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
          env:
            - name: TMPDIR
              value: /tmp/scm
            - name: AWS_REGION
              value: us-east-1
          volumeMounts:
            - name: tmp-scm
              mountPath: /tmp/scm
            - name: state
              mountPath: /app/state
            - name: logs
              mountPath: /app/logs
            - name: slack-config
              mountPath: /app/config/etc
              readOnly: true
          resources:
            requests:
              memory: "256Mi"
              cpu: "250m"
            limits:
              memory: "1Gi"
              cpu: "1000m"
          livenessProbe:
            exec:
              command:
                - python
                - -c
                - "import os,time,sys; f='/app/state/last_serial.yaml'; sys.exit(0 if os.path.exists(f) and time.time()-os.path.getmtime(f)<900 else 1)"
            initialDelaySeconds: 120
            periodSeconds: 60
      volumes:
        - name: tmp-scm
          emptyDir:
            medium: Memory
            sizeLimit: 512Mi
        - name: state
          persistentVolumeClaim:
            claimName: scm-state-pvc
        - name: logs
          persistentVolumeClaim:
            claimName: scm-logs-pvc
        - name: slack-config
          secret:
            secretName: scm-slack-config
            items:
              - key: slack.json
                path: slack.json
```

Note: EKS uses `emptyDir` with `medium: Memory` as the equivalent of Docker's
tmpfs. The `sizeLimit` is enforced by the kubelet. For the `noexec` equivalent,
apply a seccomp profile or use a PodSecurityPolicy/PodSecurityStandard that
enforces restricted mode.

### Plain Docker on EC2

```bash
docker run -d \
  --name supply-chain-monitor \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp/scm:size=512m,noexec,nosuid,nodev,uid=10001,gid=10001 \
  -v scm-state:/app/state \
  -v scm-logs:/app/logs \
  -v /path/to/etc:/app/config/etc:ro \
  -e TMPDIR=/tmp/scm \
  -e AWS_REGION=us-east-1 \
  --memory 1g \
  --cpus 1.0 \
  --restart unless-stopped \
  supply-chain-monitor:latest \
  --slack --interval 300
```

---

## When to Revisit: Two-Container Architecture

Split into separate containers if any of these conditions become true:

1. **Dynamic analysis is added** (executing install scripts, running test suites
   of downloaded packages). The extraction container would need gVisor/Firecracker
   isolation at that point.

2. **Different trust domains** emerge -- e.g., the analysis component needs access
   to internal systems that should never be reachable from the extraction sandbox.

3. **Independent scaling** is needed -- e.g., extraction is CPU-bound and analysis
   is GPU-bound, requiring different instance types.

The split architecture would look like:

```
[Extraction Worker]  --SQS-->  [Analysis Worker]  --SQS-->  [Alert Worker]
  (gVisor sandbox)              (Bedrock access)             (Slack access)
```

Each worker would have its own IAM role with minimal permissions.

---

## Build and Push

```bash
# Build
docker build -t supply-chain-monitor:latest .

# Tag for ECR
docker tag supply-chain-monitor:latest \
  <ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com/supply-chain-monitor:latest

# Authenticate and push
aws ecr get-login-password --region <REGION> | \
  docker login --username AWS --password-stdin \
  <ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com

docker push <ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com/supply-chain-monitor:latest
```
