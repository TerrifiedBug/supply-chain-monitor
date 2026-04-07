# Copyright 2026 Elastic N.V.
# Licensed under the MIT License. See LICENSE file in the project root for details.

"""
Analyze a package diff report for supply chain compromise using Claude on AWS Bedrock.

Takes a diff markdown string (output of package_diff.py) and returns a structured
verdict of "malicious" or "benign" with supporting analysis via tool_use.

Usage:
    python analyze_diff.py <diff_file>
    python analyze_diff.py telnyx_diff.md
    python analyze_diff.py telnyx_diff.md --model global.anthropic.claude-sonnet-4-6
    python analyze_diff.py telnyx_diff.md --json

Can also be chained with package_diff.py:
    python package_diff.py requests 2.31.0 2.32.0 -o diff.md && python analyze_diff.py diff.md
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from pathlib import Path

from anthropic import AnthropicBedrock

log = logging.getLogger("monitor.analyze")

DEFAULT_MODEL = os.environ.get(
    "ANTHROPIC_MODEL", "anthropic.claude-sonnet-4-20250514-v1:0"
)
DEFAULT_AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are a supply chain security analyst specializing in detecting malicious code \
injection in open-source package updates. You analyze diffs between consecutive \
versions of PyPI (Python) and npm (JavaScript/Node.js) packages.

Your task: Given a unified diff between two versions of a package, determine \
whether the changes contain evidence of a supply chain compromise — intentionally \
malicious code injected by an attacker who has gained control of a package release.

You are part of an automated monitoring system that watches the top 15,000 PyPI \
and npm packages. Your verdict determines whether a security alert is raised to \
human analysts. False negatives let attacks through. False positives cause alert \
fatigue. Both matter.

Analyze the diff systematically:

1. ORIENTATION: Identify the package, ecosystem, version transition, and the \
general nature of the update. Understand what the release is supposed to be doing.

2. ADDED FILES: Examine every newly added file. Malicious payloads are frequently \
introduced as new files unrelated to the package's purpose. Watch for:
   - New source files with generic or misleading names
   - Binary files or media files (steganography vectors)
   - Config files that register lifecycle hooks or entry points
   - Vendored/bundled code that obscures its origin

3. MODIFIED FILES: Assess whether modifications are consistent with the package's \
purpose. Look for injected code blocks stylistically inconsistent with surrounding code.

4. INDICATOR DETECTION — check for these attack patterns:

   CODE EXECUTION: eval(), exec(), compile(), Function(), child_process, subprocess, \
os.system, os.popen, dynamic import()/require()/__import__() with encoded paths.

   OBFUSCATION: base64/hex/XOR-encoded strings decoded at runtime, string \
concatenation to construct URLs/commands/code, compressed payloads decoded at \
runtime, meaningless variable names in otherwise clean code.

   NETWORK EXFILTRATION: HTTP requests to unrelated domains, DNS exfiltration, \
socket connections to hardcoded IPs, dynamically constructed URLs, requests sending \
env vars/tokens/SSH keys, webhook URLs (Discord, Slack, Telegram).

   FILESYSTEM/PERSISTENCE: Reading ~/.ssh/*, ~/.aws/*, ~/.npmrc, ~/.pypirc, \
/etc/passwd. Writing to crontab, systemd, .bashrc, .profile, registry run keys. \
Modifying other packages in site-packages/node_modules.

   PACKAGE METADATA: setup.py/pyproject.toml changes adding install-time code \
execution, package.json preinstall/install/postinstall scripts, entry points \
shadowing system commands, dependencies on suspicious packages.

   SUPPLY CHAIN SPECIFIC: CI/CD-only execution, anti-analysis checks, \
time-delayed execution, environment-conditional behavior, typosquatting.

5. CONTEXTUAL ASSESSMENT: Consider whether suspicious patterns have legitimate \
explanations for this specific package (networking libraries make HTTP requests, \
build tools run subprocess commands, etc.).

VERDICT CRITERIA:
- MALICIOUS: Only when you observe concrete indicators of intentional malicious \
behavior serving no legitimate purpose for the package.
- BENIGN: When changes are consistent with normal development, even if they \
contain patterns that could theoretically be misused.

When in doubt, lean toward BENIGN. Reserve MALICIOUS for cases where you can \
point to specific code that is clearly adversarial.

CONFIDENCE CALIBRATION:
- For MALICIOUS: 0.95-1.0 = unambiguous payload; 0.85-0.94 = strong indicators; \
0.70-0.84 = multiple suspicious patterns together. Below 0.70 = switch to BENIGN.
- For BENIGN: 0.95-1.0 = routine changes; 0.85-0.94 = warranted inspection but \
clearly legitimate; 0.70-0.84 = unusual but probably benign; 0.50-0.69 = genuinely \
uncertain, flag for human review.

You MUST call the supply_chain_verdict tool with your structured analysis.\
"""

# ---------------------------------------------------------------------------
# Tool definition for structured output
# ---------------------------------------------------------------------------

VERDICT_TOOL = {
    "name": "supply_chain_verdict",
    "description": (
        "Record the structured verdict for a supply chain diff analysis. "
        "Call this tool exactly once with your complete analysis."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "verdict": {
                "type": "string",
                "enum": ["malicious", "benign"],
                "description": "Whether the diff shows evidence of supply chain compromise.",
            },
            "confidence": {
                "type": "number",
                "description": "Confidence in your verdict from 0.0 to 1.0.",
            },
            "severity": {
                "type": "string",
                "enum": ["critical", "high", "medium", "low", "none"],
                "description": (
                    "Potential impact severity. Use 'none' only with benign verdicts."
                ),
            },
            "summary": {
                "type": "string",
                "description": (
                    "Concise explanation of the verdict. For malicious: describe the "
                    "attack vector and payload. For benign: describe the nature of "
                    "the changes."
                ),
            },
            "indicators": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "pattern": {
                            "type": "string",
                            "enum": [
                                "obfuscated_code",
                                "network_exfiltration",
                                "filesystem_access",
                                "process_execution",
                                "credential_theft",
                                "persistence_mechanism",
                                "lifecycle_hook_abuse",
                                "dynamic_code_execution",
                                "encoded_payload",
                                "steganography",
                                "typosquatting",
                                "dependency_injection",
                                "anti_analysis",
                                "data_staging",
                                "other",
                            ],
                            "description": "Category of suspicious pattern.",
                        },
                        "location": {
                            "type": "string",
                            "description": (
                                "File path and line range, e.g. 'setup.py:15-23'."
                            ),
                        },
                        "description": {
                            "type": "string",
                            "description": "What was found and why it is suspicious.",
                        },
                    },
                    "required": ["pattern", "location", "description"],
                },
                "description": "Suspicious indicators found. Empty array if benign.",
            },
        },
        "required": ["verdict", "confidence", "severity", "summary", "indicators"],
    },
}


# ---------------------------------------------------------------------------
# Diff filtering and truncation
# ---------------------------------------------------------------------------

# Approximate chars per token for a code/text mix
_CHARS_PER_TOKEN = 3.5
# Bedrock has a 1M token input limit.  Reserve headroom for system prompt + tool schema.
_MAX_INPUT_TOKENS = 900_000
_MAX_DIFF_CHARS = int(_MAX_INPUT_TOKENS * _CHARS_PER_TOKEN)  # ~3.15M chars

# Auto-generated files: massive diffs, almost zero signal for supply chain attacks
_LOW_SIGNAL_FILES = frozenset({
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "poetry.lock", "pipfile.lock", "composer.lock",
    "cargo.lock", "gemfile.lock", "go.sum",
})

_LOW_SIGNAL_SUFFIXES = (".min.js", ".min.css", ".bundle.js", ".js.map", ".css.map")

_LOW_SIGNAL_DIRS = (
    "vendor/", "vendored/", "third_party/", "third-party/",
    "node_modules/", "dist/", "build/", "_vendor/",
)

# Files most likely to contain supply chain attack vectors
_HIGH_SIGNAL_FILES = frozenset({
    "setup.py", "setup.cfg", "pyproject.toml",
    "package.json", "__init__.py", "__main__.py",
    ".npmrc", ".pypirc", "makefile",
    "conftest.py", "manage.py",
})

_HIGH_SIGNAL_PATTERNS = ("postinstall", "preinstall", "install.py", "install.js")


def _file_signal_priority(rel_path: str) -> int:
    """Classify a file by relevance to supply chain analysis.

    Returns 0 (high-signal), 1 (normal), or 2 (low-signal).
    """
    basename = rel_path.rsplit("/", 1)[-1] if "/" in rel_path else rel_path
    lower_path = rel_path.lower()
    lower_base = basename.lower()

    # Low signal
    if lower_base in _LOW_SIGNAL_FILES:
        return 2
    if any(lower_base.endswith(s) for s in _LOW_SIGNAL_SUFFIXES):
        return 2
    if any(d in lower_path for d in _LOW_SIGNAL_DIRS):
        return 2

    # High signal
    if lower_base in _HIGH_SIGNAL_FILES:
        return 0
    if any(p in lower_base for p in _HIGH_SIGNAL_PATTERNS):
        return 0

    return 1


def _prepare_diff(diff_text: str, max_chars: int = _MAX_DIFF_CHARS) -> tuple[str, bool]:
    """Filter and truncate a diff report to fit within the Bedrock token budget.

    Strategy (applied in order):
      1. Remove binary-only file entries (no LLM-useful content)
      2. Remove low-signal files (lock files, minified JS, vendored code)
      3. Prioritize high-signal files to the front (setup.py, package.json, …)
      4. Truncate at file boundaries if still over budget

    Returns ``(filtered_text, was_truncated)``.
    """
    if len(diff_text) <= max_chars:
        return diff_text, False

    # Locate the "## Changed Files" section
    marker = "## Changed Files"
    marker_idx = diff_text.find(marker)
    if marker_idx == -1:
        # No structured sections — hard truncate as a fallback
        return diff_text[:max_chars] + "\n\n[TRUNCATED: diff exceeded token budget]\n", True

    # Split header (everything up to and including the marker line) from body
    header_end = marker_idx + len(marker)
    while header_end < len(diff_text) and diff_text[header_end] in "\n\r":
        header_end += 1
    header = diff_text[:header_end]
    body = diff_text[header_end:]

    # Split body into per-file chunks at ``### ` `` markers
    chunks = re.split(r"(?=^### `)", body, flags=re.MULTILINE)
    chunks = [c for c in chunks if c.strip()]

    # Classify each chunk
    file_chunks: list[tuple[int, str, str]] = []
    skipped_binary = 0
    skipped_low_signal = 0

    for chunk in chunks:
        m = re.match(r"^### `(.+?)`", chunk)
        filename = m.group(1) if m else ""

        # Drop binary-only entries (no diff content for the LLM)
        if "*Binary file changed.*" in chunk and "```diff" not in chunk:
            skipped_binary += 1
            continue

        priority = _file_signal_priority(filename)

        # Always drop low-signal files when we need to trim
        if priority == 2:
            skipped_low_signal += 1
            continue

        file_chunks.append((priority, filename, chunk))

    # Sort: high-signal first (0), then normal (1), alphabetical within tier
    file_chunks.sort(key=lambda x: (x[0], x[1]))

    # Assemble within budget
    remaining = max_chars - len(header)
    included: list[str] = []
    omitted_size = 0

    for _priority, _filename, chunk in file_chunks:
        if len(chunk) <= remaining:
            included.append(chunk)
            remaining -= len(chunk)
        else:
            omitted_size += 1

    total_omitted = omitted_size + skipped_binary + skipped_low_signal
    parts = [header] + included

    if total_omitted > 0:
        notes = []
        if skipped_binary:
            notes.append(f"{skipped_binary} binary-only")
        if skipped_low_signal:
            notes.append(f"{skipped_low_signal} low-signal (lock/vendored/minified)")
        if omitted_size:
            notes.append(f"{omitted_size} exceeded token budget")
        parts.append(
            f"\n[TRUNCATED: {total_omitted} file(s) omitted — {', '.join(notes)}]\n"
        )

    return "".join(parts), True


# ---------------------------------------------------------------------------
# Client and analysis
# ---------------------------------------------------------------------------

def _create_client(aws_region: str | None = None) -> AnthropicBedrock:
    """Create a Bedrock client. Auth via standard AWS credential chain."""
    return AnthropicBedrock(
        aws_region=aws_region or DEFAULT_AWS_REGION,
        max_retries=3,
    )


def analyze_diff(
    diff_text: str,
    *,
    model: str | None = None,
    aws_region: str | None = None,
) -> tuple[str, str]:
    """Analyze a package diff for supply chain compromise via Bedrock.

    Returns (verdict, analysis) where verdict is 'malicious', 'benign',
    or 'error'/'unknown', and analysis is a human-readable summary.
    """
    client = _create_client(aws_region)

    # Pre-filter large diffs to stay within Bedrock's token limit
    original_len = len(diff_text)
    diff_text, was_truncated = _prepare_diff(diff_text)
    if was_truncated:
        log.warning(
            "Diff filtered/truncated to fit token budget: %d → %d chars "
            "(~%dk → ~%dk tokens)",
            original_len, len(diff_text),
            int(original_len / _CHARS_PER_TOKEN / 1000),
            int(len(diff_text) / _CHARS_PER_TOKEN / 1000),
        )

    use_model = model or DEFAULT_MODEL

    try:
        response = client.messages.create(
            model=use_model,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            tools=[VERDICT_TOOL],
            tool_choice={"type": "tool", "name": "supply_chain_verdict"},
            messages=[{"role": "user", "content": diff_text}],
        )
    except Exception as exc:
        # If the request failed due to input length, retry with a tighter budget.
        # The 3.5 chars/token estimate can be too generous for code-heavy diffs.
        if "too long" in str(exc).lower() or "too many" in str(exc).lower():
            tighter = int(len(diff_text) * 0.5)
            log.warning(
                "Input still too long after filtering (%d chars) — "
                "retrying with halved budget (%d chars)",
                len(diff_text), tighter,
            )
            diff_text, _ = _prepare_diff(diff_text, max_chars=tighter)
            response = client.messages.create(
                model=use_model,
                max_tokens=4096,
                system=SYSTEM_PROMPT,
                tools=[VERDICT_TOOL],
                tool_choice={"type": "tool", "name": "supply_chain_verdict"},
                messages=[{"role": "user", "content": diff_text}],
            )
        else:
            raise

    log.debug(
        "Bedrock usage: input=%d output=%d",
        response.usage.input_tokens,
        response.usage.output_tokens,
    )

    for block in response.content:
        if block.type == "tool_use" and block.name == "supply_chain_verdict":
            return _format_verdict(block.input)

    log.error("No tool_use block in response (stop_reason=%s)", response.stop_reason)
    return "unknown", "Model did not return a structured verdict."


def _format_verdict(data: dict) -> tuple[str, str]:
    """Format structured tool output into (verdict, analysis) strings."""
    verdict = data.get("verdict", "unknown")
    confidence = data.get("confidence", 0.0)
    severity = data.get("severity", "unknown")
    summary = data.get("summary", "")
    indicators = data.get("indicators", [])

    parts = [
        f"Confidence: {confidence:.0%} | Severity: {severity}",
        "",
        summary,
    ]

    if indicators:
        parts.append("")
        parts.append("Indicators:")
        for ind in indicators:
            pattern = ind.get("pattern", "unknown")
            location = ind.get("location", "?")
            desc = ind.get("description", "")
            parts.append(f"  [{pattern}] {location}: {desc}")

    return verdict, "\n".join(parts)


# ---------------------------------------------------------------------------
# Backward-compatible shims (used by standalone CLI path)
# ---------------------------------------------------------------------------

def parse_verdict(output: str) -> tuple[str, str]:
    """Extract verdict from freeform text. Kept for backward compatibility."""
    import re
    verdict = "unknown"
    match = re.search(r"[Vv]erdict:\s*(malicious|benign)", output, re.IGNORECASE)
    if match:
        verdict = match.group(1).lower()
    return verdict, output.strip()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Analyze a package diff for supply chain compromise via Claude on Bedrock",
    )
    parser.add_argument("diff_file", type=Path, help="Path to diff markdown file (from package_diff.py)")
    parser.add_argument(
        "--model", default=None,
        help=f"Bedrock model ID (default: {DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--aws-region", default=None,
        help=f"AWS region for Bedrock (default: {DEFAULT_AWS_REGION})",
    )
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output as JSON")
    args = parser.parse_args()

    if not args.diff_file.exists():
        parser.error(f"File not found: {args.diff_file}")

    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(message)s",
        level=logging.INFO,
    )

    diff_text = args.diff_file.read_text(encoding="utf-8")
    log.info("Analyzing %s (%d chars) via Bedrock...", args.diff_file.name, len(diff_text))

    try:
        verdict, analysis = analyze_diff(
            diff_text, model=args.model, aws_region=args.aws_region,
        )
    except Exception as exc:
        log.error("Analysis failed: %s", exc)
        sys.exit(2)

    if args.json_output:
        print(json.dumps({
            "file": str(args.diff_file),
            "verdict": verdict,
            "analysis": analysis,
        }, indent=2))
    else:
        print(f"\n{'='*60}")
        print(f"  FILE:    {args.diff_file.name}")
        print(f"  VERDICT: {verdict.upper()}")
        print(f"{'='*60}")
        print(f"\n{analysis}")

    sys.exit(0 if verdict == "benign" else 1 if verdict == "malicious" else 2)


if __name__ == "__main__":
    main()
