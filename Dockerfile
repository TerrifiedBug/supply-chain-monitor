# =============================================================================
# Supply Chain Monitor - Multi-stage Dockerfile
#
# Security design:
#   - Minimal base image (distroless-like Python slim)
#   - Non-root user with no shell access
#   - Application code is read-only (COPY, not mounted)
#   - Temp extraction directory is a dedicated tmpfs mount point
#   - Dropped all capabilities at runtime
#   - No new privileges flag enforced
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Build dependencies
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS builder

# Avoid bytecode + unbuffered output for deterministic builds
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

# Install dependencies into a prefix we can copy cleanly
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ---------------------------------------------------------------------------
# Stage 2: Runtime image
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS runtime

# --- Metadata ---
LABEL maintainer="Elastic DFIR <s1-dfir-dev@elastic.co>" \
      description="Supply chain security monitor for PyPI and npm" \
      org.opencontainers.image.source="https://github.com/elastic/supply-chain-monitor"

# --- System hardening ---
# Remove unnecessary system packages, shells where possible
# Install only what extraction needs: nothing beyond Python stdlib
RUN apt-get update && \
    apt-get upgrade -y && \
    # Remove setuid/setgid binaries to reduce privilege escalation surface
    find / -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /root/.cache

# --- Python environment ---
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Copy installed dependencies from builder
COPY --from=builder /install /usr/local

# --- Application user ---
# Create a dedicated non-root user with no login shell and no home directory
# UID 10001 is chosen to avoid collision with system UIDs
RUN groupadd --gid 10001 scm && \
    useradd --uid 10001 --gid scm --shell /usr/sbin/nologin --no-create-home scm

# --- Application layout ---
#   /app            - Application code (read-only at runtime via ro rootfs)
#   /app/state      - Persistent state volume (last_serial.yaml)
#   /app/logs       - Log output volume
#   /app/config     - Slack config volume (etc/slack.json)
#   /tmp/scm        - Temp extraction dir (tmpfs at runtime, size-limited)
WORKDIR /app

COPY --chown=root:root monitor.py pypi_monitor.py package_diff.py \
     analyze_diff.py slack.py top_pypi_packages.py ./

# Create directories the application expects.
# /tmp/scm is the extraction sandbox -- will be tmpfs-mounted at runtime.
# /app/state and /app/logs are volume mount points for persistence.
# /app/config/etc houses slack.json (bind-mounted or from secrets).
RUN mkdir -p /tmp/scm /app/state /app/logs /app/config/etc && \
    chown -R scm:scm /tmp/scm /app/state /app/logs /app/config

# --- Path compatibility symlinks ---
# monitor.py resolves paths relative to __file__ (which is /app/monitor.py):
#   - LAST_SERIAL_PATH = Path(__file__).resolve().parent / "last_serial.yaml"
#     -> /app/last_serial.yaml, but /app is read-only. Symlink to writable volume.
#   - LOG_DIR = Path(__file__).parent / "logs"
#     -> /app/logs, which is a volume mount -- works directly.
#   - slack.py reads os.path.dirname(__file__) + "/etc/slack.json"
#     -> /app/etc/slack.json, symlink to config volume mount.
RUN ln -s /app/state/last_serial.yaml /app/last_serial.yaml && \
    ln -s /app/config/etc /app/etc

# --- Volumes ---
# Declare expected mount points for documentation / runtime orchestration
VOLUME ["/app/state", "/app/logs", "/tmp/scm"]

# --- Environment defaults ---
# Override TMPDIR so all tempfile.mkdtemp calls land in our sandboxed tmpfs
ENV TMPDIR=/tmp/scm

# Bedrock configuration flows via env vars at runtime (NOT baked in):
#   AWS_REGION                      - AWS region for Bedrock (required)
#   ANTHROPIC_MODEL                 - Bedrock model ID (default: global.anthropic.claude-opus-4-6-v1)
#   AWS_BEARER_TOKEN_BEDROCK        - Bedrock bearer token auth
#   AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY - alternative auth
#   CLAUDE_CODE_USE_BEDROCK         - set to 1 for Bedrock mode

# --- Switch to non-root ---
USER 10001:10001

# --- Health check ---
# The monitor is a long-running daemon with no HTTP endpoint.
# Health is determined by process liveness. For orchestrators that need
# an explicit check, verify the process is running and has written state
# recently (within 2x the poll interval).
# The healthcheck verifies the state file exists and was updated recently
# (within 15 minutes = 900s, which is 3x the default 300s poll interval).
# This catches hangs where the process is alive but the poll loop is stuck.
HEALTHCHECK --interval=60s --timeout=5s --start-period=120s --retries=3 \
    CMD python -c "import os,time,sys; f='/app/state/last_serial.yaml'; sys.exit(0 if os.path.exists(f) and time.time()-os.path.getmtime(f)<900 else 1)"

# --- Entrypoint ---
# Default: continuous monitoring of both PyPI and npm with Slack enabled.
# Override CMD at runtime for different modes (--once, --no-npm, etc.)
ENTRYPOINT ["python", "monitor.py"]
CMD ["--slack", "--interval", "300"]
