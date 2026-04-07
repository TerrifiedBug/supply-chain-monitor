# Deploying Supply Chain Monitor on AWS ECS Fargate

This guide walks through deploying the monitor as a long-running ECS Fargate task with Bedrock for LLM analysis and Slack for alerts.

## Architecture

```
                  ECS Fargate Task
                  ┌─────────────────────────────────┐
                  │  supply-chain-monitor container  │
                  │                                  │
                  │  monitor.py (entrypoint)         │
                  │    ├─ PyPI polling thread         │
                  │    └─ npm polling thread          │
                  │                                  │
                  │  Volumes:                        │
                  │    /app/state ──► EFS (serial)   │
                  │    /app/logs  ──► EFS (logs)     │
                  │    /tmp/scm   ──► tmpfs (scratch)│
                  └──────────┬──────────────────────┘
                             │
              ┌──────────────┼──────────────────┐
              │              │                  │
              ▼              ▼                  ▼
        AWS Bedrock     PyPI / npm         Slack API
        (LLM analysis)  (registries)       (alerts)
```

## Prerequisites

- AWS CLI configured with admin-level access
- Docker installed locally (for building the image)
- A Slack bot token with `chat:write` scope

## Step-by-Step Deployment

### 1. Create an ECR Repository

```bash
aws ecr create-repository \
  --repository-name supply-chain-monitor \
  --region us-east-1
```

Note the repository URI from the output (e.g., `123456789.dkr.ecr.us-east-1.amazonaws.com/supply-chain-monitor`).

### 2. Build and Push the Docker Image

```bash
# Authenticate Docker to ECR
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin 123456789.dkr.ecr.us-east-1.amazonaws.com

# Build
docker build -t supply-chain-monitor .

# Tag
docker tag supply-chain-monitor:latest \
  123456789.dkr.ecr.us-east-1.amazonaws.com/supply-chain-monitor:latest

# Push
docker push \
  123456789.dkr.ecr.us-east-1.amazonaws.com/supply-chain-monitor:latest
```

### 3. Store Slack Credentials in Secrets Manager

The monitor needs Slack credentials for alerting. Store them as a JSON string in Secrets Manager — ECS will inject it as the `SLACK_CONFIG_JSON` environment variable, and `slack.py` reads it directly (no file needed).

```bash
aws secretsmanager create-secret \
  --name scm/slack-config \
  --region us-east-1 \
  --secret-string '{
    "url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
    "bot_token": "xoxb-your-bot-token-here",
    "channel": "C0123456789"
  }'
```

**Where to get these values:**

| Field | Where to find it |
|-------|-----------------|
| `url` | Slack App > Incoming Webhooks > Webhook URL |
| `bot_token` | Slack App > OAuth & Permissions > Bot User OAuth Token (starts with `xoxb-`) |
| `channel` | Right-click channel in Slack > View channel details > Channel ID at bottom (starts with `C`) |

**How it works in ECS:** The task definition's `secrets` block references this secret. ECS injects its value as the `SLACK_CONFIG_JSON` environment variable at container startup. The application checks for this env var first, falling back to `etc/slack.json` on disk for local development.

### 4. Create an EFS Filesystem

The monitor persists its polling position (`last_serial.yaml`) so it resumes where it left off after restarts. Without EFS, every task restart re-scans from the registry head, missing any releases during downtime.

```bash
# Create filesystem
aws efs create-file-system \
  --performance-mode generalPurpose \
  --throughput-mode bursting \
  --encrypted \
  --tags Key=Name,Value=scm-state \
  --region us-east-1

# Note the FileSystemId from output (e.g., fs-0123456789abcdef0)

# Create access point for state
aws efs create-access-point \
  --file-system-id fs-0123456789abcdef0 \
  --posix-user Uid=10001,Gid=10001 \
  --root-directory "Path=/scm-state,CreationInfo={OwnerUid=10001,OwnerGid=10001,Permissions=755}" \
  --region us-east-1

# Create access point for logs
aws efs create-access-point \
  --file-system-id fs-0123456789abcdef0 \
  --posix-user Uid=10001,Gid=10001 \
  --root-directory "Path=/scm-logs,CreationInfo={OwnerUid=10001,OwnerGid=10001,Permissions=755}" \
  --region us-east-1
```

Note both Access Point IDs from the output.

**Mount targets:** Create a mount target in each subnet your ECS tasks will run in:

```bash
aws efs create-mount-target \
  --file-system-id fs-0123456789abcdef0 \
  --subnet-id subnet-YOUR_SUBNET_ID \
  --security-groups sg-YOUR_EFS_SG \
  --region us-east-1
```

The EFS security group must allow inbound NFS (port 2049) from the ECS task security group.

### 5. Create IAM Roles

You need two roles. Policy templates are in `ecs-iam-policies.json`.

**Execution Role** (used by the ECS agent to pull images, write logs, read secrets):

```bash
# Create role with ECS trust policy
aws iam create-role \
  --role-name scm-ecs-execution-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "ecs-tasks.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

# Attach the managed ECS execution policy
aws iam attach-role-policy \
  --role-name scm-ecs-execution-role \
  --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy

# Add Secrets Manager access (for Slack config)
aws iam put-role-policy \
  --role-name scm-ecs-execution-role \
  --policy-name scm-secrets-access \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "arn:aws:secretsmanager:us-east-1:YOUR_ACCOUNT_ID:secret:scm/*"
    }]
  }'
```

**Task Role** (used by the running container — this is what grants Bedrock access):

```bash
# Create role
aws iam create-role \
  --role-name scm-ecs-task-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "ecs-tasks.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

# Grant Bedrock access (LLM analysis)
aws iam put-role-policy \
  --role-name scm-ecs-task-role \
  --policy-name scm-bedrock-access \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
      "Resource": "arn:aws:bedrock:*::foundation-model/anthropic.claude-*"
    }]
  }'

# Grant EFS access (state persistence)
aws iam put-role-policy \
  --role-name scm-ecs-task-role \
  --policy-name scm-efs-access \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite"],
      "Resource": "arn:aws:elasticfilesystem:us-east-1:YOUR_ACCOUNT_ID:file-system/fs-YOUR_EFS_ID"
    }]
  }'
```

**No API keys needed.** The `anthropic[bedrock]` SDK picks up credentials automatically from the ECS task role via the instance metadata service. No `AWS_ACCESS_KEY_ID` or `CURSOR_API_KEY` env vars required.

### 6. Create ECS Cluster

```bash
aws ecs create-cluster \
  --cluster-name supply-chain-monitor \
  --region us-east-1
```

### 7. Register the Task Definition

Edit `ecs-task-definition.json` and replace all `<PLACEHOLDER>` values:

| Placeholder | Replace with |
|-------------|-------------|
| `<ACCOUNT_ID>` | Your AWS account ID (e.g., `123456789012`) |
| `<REGION>` | Your region (e.g., `us-east-1`) |
| `<EFS_FILESYSTEM_ID>` | From step 4 (e.g., `fs-0123456789abcdef0`) |
| `<EFS_ACCESS_POINT_ID>` | State access point from step 4 |
| `<EFS_LOGS_ACCESS_POINT_ID>` | Logs access point from step 4 |

Then register it:

```bash
aws ecs register-task-definition \
  --cli-input-json file://deploy/ecs-task-definition.json \
  --region us-east-1
```

### 8. Create the ECS Service

```bash
aws ecs create-service \
  --cluster supply-chain-monitor \
  --service-name scm \
  --task-definition supply-chain-monitor \
  --desired-count 1 \
  --launch-type FARGATE \
  --network-configuration '{
    "awsvpcConfiguration": {
      "subnets": ["subnet-YOUR_SUBNET_1", "subnet-YOUR_SUBNET_2"],
      "securityGroups": ["sg-YOUR_TASK_SG"],
      "assignPublicIp": "ENABLED"
    }
  }' \
  --region us-east-1
```

**Networking notes:**
- The task needs **outbound internet access** (PyPI, npm, Bedrock, Slack). Either use a public subnet with `assignPublicIp: ENABLED`, or a private subnet with a NAT gateway.
- No inbound ports are needed — the monitor only makes outbound HTTPS connections.
- The task security group needs: outbound TCP 443 to `0.0.0.0/0`, outbound TCP 2049 to the EFS security group.

### 9. Verify It's Running

```bash
# Check service status
aws ecs describe-services \
  --cluster supply-chain-monitor \
  --services scm \
  --region us-east-1 \
  --query 'services[0].{status:status,running:runningCount,desired:desiredCount}'

# Tail logs
aws logs tail /ecs/supply-chain-monitor --follow --region us-east-1
```

You should see:
```
[INFO] Fetching top 15,000 packages from hugovk dataset...
[INFO] Watchlist loaded: 15,000 packages
[INFO] Fetching top 15,000 npm packages from download-counts dataset...
[INFO] [pypi] Starting serial: 35,542,068 — polling every 300s
[INFO] [npm] Starting seq: 42,817,503 — polling every 300s
```

## Configuration

All configuration is via environment variables or CLI arguments. Set env vars in the task definition's `environment` block.

| Env Var | CLI Flag | Default | Description |
|---------|----------|---------|-------------|
| `AWS_REGION` | `--aws-region` | `us-east-1` | AWS region for Bedrock |
| `ANTHROPIC_MODEL` | `--model` | `anthropic.claude-sonnet-4-20250514-v1:0` | Bedrock model ID |
| `SCM_MAX_DIFF_TOKENS` | `--max-diff-tokens` | `900000` | Max input tokens for diff truncation |
| `SLACK_CONFIG_JSON` | N/A | N/A | JSON string with Slack creds (see step 3) |
| — | `--top` | `15000` | Top N packages to watch per ecosystem |
| — | `--interval` | `300` | Poll interval in seconds |
| — | `--workers` | `4` | Concurrent analysis workers per ecosystem |
| — | `--slack` | off | Enable Slack alerts (set in CMD) |
| — | `--no-pypi` | off | Disable PyPI monitoring |
| — | `--no-npm` | off | Disable npm monitoring |

To change CLI arguments, update the `command` array in the task definition:

```json
"command": ["--slack", "--interval", "300", "--top", "5000"]
```

## Cost Breakdown

| Component | Monthly Cost |
|-----------|-------------|
| **Fargate** (0.25 vCPU, 1GB) | ~$10 |
| **EFS** (< 1MB stored) | ~$0.30 |
| **CloudWatch Logs** | ~$2-5 |
| **Bedrock** (Sonnet, --top 5000) | ~$200-300 |
| **Total** | ~$215-315/mo |

Bedrock is 95%+ of the cost. Reduce with `--top 1000` (~$80-100/mo total) or increase with `--top 15000` (~$600-700/mo total).

## Updating

```bash
# Build and push new image
docker build -t supply-chain-monitor .
docker tag supply-chain-monitor:latest YOUR_ECR_URI:latest
docker push YOUR_ECR_URI:latest

# Force new deployment (pulls latest image)
aws ecs update-service \
  --cluster supply-chain-monitor \
  --service scm \
  --force-new-deployment \
  --region us-east-1
```

## Troubleshooting

**Task keeps restarting:**
- Check CloudWatch logs: `aws logs tail /ecs/supply-chain-monitor --region us-east-1`
- Common cause: Bedrock model not enabled in your account. Go to AWS Console > Bedrock > Model access and enable Claude models.

**Health check failing:**
- The health check expects `last_serial.yaml` to be updated within 15 minutes. If the monitor can't reach PyPI/npm (network issue), the state file won't update and the health check fails.
- Check security group outbound rules allow HTTPS (443) to the internet.

**"Slack not configured" warning:**
- Verify the secret exists: `aws secretsmanager get-secret-value --secret-id scm/slack-config --region us-east-1`
- Verify the task definition `secrets` block references the correct ARN.
- The JSON must have `url`, `bot_token`, and `channel` fields.

**Bedrock throttling:**
- If you see `ThrottlingException` in logs, the SDK retries automatically (3 attempts with backoff). If it persists, request a quota increase in AWS Console > Service Quotas > Amazon Bedrock.
- Reduce `--workers` to lower concurrency, or use `--top` with a smaller value.

**Missed releases after restart:**
- The monitor resumes from the last saved serial/sequence in `last_serial.yaml` on EFS. If EFS is not mounted, it starts from the registry head and misses anything during downtime.
- For npm: if the saved sequence is more than 10,000 changes behind, it resets to head (gap protection).
