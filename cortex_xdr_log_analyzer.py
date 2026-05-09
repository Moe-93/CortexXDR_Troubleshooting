#!/usr/bin/env python3
"""
cortex_xdr_log_analyzer.py

Analyze Cortex XDR agent troubleshooting logs and generate a support-oriented
report with likely issue indicators, severity, evidence, timestamps, and next
actions.

This is a standalone local utility for support engineers. It does not require
external dependencies and does not upload logs anywhere.

Usage:
  python cortex_xdr_log_analyzer.py --input /path/to/log_or_folder
  python cortex_xdr_log_analyzer.py --input ./support_logs --output report.json --html report.html --csv findings.csv
  python cortex_xdr_log_analyzer.py --input /var/log/traps --since "2026-05-01" --verbose
  python cortex_xdr_log_analyzer.py --self-test
"""

from __future__ import annotations

import argparse
import csv
import gzip
import html
import json
import re
import sys
import tempfile
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, Iterator, List, Optional, Pattern, Sequence, Tuple


# -----------------------------
# Data model
# -----------------------------

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_PENALTY = {"critical": 22, "high": 14, "medium": 8, "low": 3, "info": 1}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    severity: str
    patterns: Sequence[str]
    explanation: str
    recommended_actions: Sequence[str]
    tags: Sequence[str] = field(default_factory=tuple)

    def compile(self) -> "CompiledRule":
        return CompiledRule(
            rule=self,
            compiled=[re.compile(pattern, re.IGNORECASE) for pattern in self.patterns],
        )


@dataclass(frozen=True)
class CompiledRule:
    rule: Rule
    compiled: Sequence[Pattern[str]]


@dataclass
class Evidence:
    file: str
    line: int
    timestamp: Optional[str]
    matched_text: str
    context_before: List[str]
    context_after: List[str]


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str
    explanation: str
    recommended_actions: List[str]
    occurrences: int = 0
    evidence: List[Evidence] = field(default_factory=list)
    files: List[str] = field(default_factory=list)
    first_timestamp: Optional[str] = None
    last_timestamp: Optional[str] = None


@dataclass
class SkippedFile:
    file: str
    reason: str


@dataclass
class Summary:
    total_files_scanned: int
    total_lines_scanned: int
    total_findings: int
    findings_by_severity: Dict[str, int]
    findings_by_category: Dict[str, int]
    health_score: int
    top_likely_root_causes: List[Dict[str, Any]]
    skipped_files: List[SkippedFile]


@dataclass
class Report:
    generated_at: str
    input_path: str
    since: Optional[str]
    summary: Summary
    findings: List[Finding]


# -----------------------------
# Rule engine
# -----------------------------

COMMON_ACTIONS: Dict[str, List[str]] = {
    "connectivity": [
        "Verify endpoint DNS resolution to the Cortex tenant, proxy FQDN, and any Broker VM FQDN.",
        "Validate outbound HTTPS allow-listing, proxy authentication, TLS inspection bypass, and firewall egress rules.",
        "Compare failures with network changes, VPN state, and Last Used Proxy / Last Seen values in the Cortex console.",
    ],
    "heartbeat": [
        "Run cytool status and, where operationally appropriate, trigger/validate agent check-in.",
        "Validate Last Seen in the Cortex console and allow for normal console status propagation delay.",
        "Correlate heartbeat failures with DNS, proxy, TLS, tenant reachability, and service restarts.",
    ],
    "service": [
        "Confirm Cortex XDR/Traps services are running and not repeatedly restarting.",
        "Review operating system service manager logs around the same timestamp.",
        "If repeated crashes are present, collect full support logs and check recent agent upgrades or OS/security-tool changes.",
    ],
    "install_upgrade": [
        "Confirm supported OS/kernel version, installer architecture, root/admin permissions, disk space, and package manager health.",
        "Review /var/log/traps-install.log on Linux and installer/service logs on Windows/macOS.",
        "If upgrade-related, verify download source, Broker/P2P availability, and recent agent version change history.",
    ],
    "content": [
        "Verify content download path: Cortex Server, Broker VM cache, or P2P source depending on policy.",
        "Check network reachability, proxy settings, and sufficient disk space.",
        "Confirm Last Content Update Time in endpoint details and compare with policy/content deployment time.",
    ],
    "policy": [
        "Run cytool status/policy-related checks where applicable and validate current policy in the Cortex console.",
        "Remember some agent configuration changes apply after heartbeat/check-in.",
        "Check endpoint group membership, license state, network location profile, and policy rule precedence.",
    ],
    "linux_libs": [
        "Verify OS/library compatibility and recent OS/package changes.",
        "Check installed glibc, libstdc++, and GLIBCXX symbol versions.",
        "Use a supported Linux distribution/kernel and avoid mixing unsupported runtime libraries.",
    ],
    "permission": [
        "Check mount options such as noexec, temporary extraction path, execute permissions, ownership, and root/admin privileges.",
        "Review endpoint security controls that may block execution, scripts, or installer extraction.",
        "Re-run with the correct administrative context after validating the path can execute binaries.",
    ],
    "driver": [
        "Verify supported OS/kernel and required modules/drivers.",
        "Check Secure Boot, kernel headers, driver signing, and kernel extension/system extension approval requirements.",
        "Collect OS kernel logs and Cortex support logs if the module repeatedly fails to load.",
    ],
    "macos": [
        "Verify system extension approval, network extension approval, full disk access, and MDM profile deployment.",
        "Check systemextensionsctl output and macOS privacy/security prompts or MDM payload status.",
        "Confirm the endpoint reports Fully Protected after approvals and heartbeat/check-in.",
    ],
    "broker": [
        "Confirm Broker VM is connected in Cortex XDR and the relevant applet/service is running.",
        "Validate agent proxy/cache port, local DNS record for the Broker FQDN, certificates, and firewall path.",
        "Check Broker VM logs, proxy applet logs, and whether agents can fall back to Cortex Server if allowed.",
    ],
}


RULES: List[Rule] = [
    Rule(
        "CXDR-SERVICE-STOPPED",
        "Agent service stopped/crashed/restart loop",
        "high",
        [
            r"\b(cortex xdr|traps|cyserver|pmd|cortex).*service.*\b(stopped|not running|failed|terminated|dead)\b",
            r"\bservice control manager\b.*\b(cortex|traps).*\bterminated unexpectedly\b",
            r"\b(systemd|launchd).*?\b(cortex|traps|pmd|cyserver).*?\b(failed|inactive|dead|stopped)\b",
        ],
        "The Cortex XDR/Traps service appears stopped, failed, or not running.",
        COMMON_ACTIONS["service"],
    ),
    Rule(
        "CXDR-SERVICE-RESTART-LOOP",
        "Agent service stopped/crashed/restart loop",
        "critical",
        [
            r"\b(restart loop|restarting too quickly|start request repeated too quickly|crash loop)\b",
            r"\b(cortex|traps|pmd|cyserver).*\b(crashed|segmentation fault|core dumped|fatal signal)\b",
        ],
        "The agent or supporting service appears to be crashing or restarting repeatedly.",
        COMMON_ACTIONS["service"],
    ),
    Rule(
        "CXDR-HEARTBEAT-FAILURE",
        "Agent not checking in / heartbeat failure",
        "high",
        [
            r"\b(heartbeat|check[- ]?in|checkin|keepalive)\b.*\b(fail|failed|failure|timeout|timed out|unable|not sent|missed)\b",
            r"\b(last seen|agent status).*?\b(stale|offline|disconnected|not connected)\b",
            r"\bfailed to (send|perform).*?(heartbeat|check[- ]?in)\b",
        ],
        "Agent heartbeat/check-in indicators suggest the endpoint may not be reporting correctly.",
        COMMON_ACTIONS["heartbeat"],
    ),
    Rule(
        "CXDR-DNS-FAILURE",
        "Connectivity failures",
        "high",
        [
            r"\b(dns|resolver|getaddrinfo|resolve|name resolution)\b.*\b(fail|failed|failure|error|timeout|not found|nxdomain|servfail)\b",
            r"\b(could not resolve|unable to resolve|temporary failure in name resolution|no such host)\b",
        ],
        "DNS resolution failures may prevent agent communication with Cortex, proxy, or Broker VM.",
        COMMON_ACTIONS["connectivity"],
        ("dns",),
    ),
    Rule(
        "CXDR-PROXY-FAILURE",
        "Connectivity failures",
        "high",
        [
            r"\bproxy\b.*\b(fail|failed|failure|error|unreachable|refused|auth|authentication|required|407|timeout|denied)\b",
            r"\b(connect via proxy|proxy tunnel|http proxy|squid)\b.*\b(fail|failed|error|denied|timeout)\b",
        ],
        "Proxy communication or authentication appears to be failing.",
        COMMON_ACTIONS["connectivity"],
        ("proxy",),
    ),
    Rule(
        "CXDR-TLS-CERT-FAILURE",
        "Connectivity failures",
        "high",
        [
            r"\b(tls|ssl|certificate|cert|x509|handshake)\b.*\b(fail|failed|failure|error|expired|invalid|untrusted|verify|verification|self.signed|unknown ca)\b",
            r"\b(ssl_connect|certificate verify failed|unable to get local issuer certificate|tls handshake timeout)\b",
        ],
        "TLS/certificate validation indicators suggest SSL inspection, trust-chain, or certificate issues.",
        COMMON_ACTIONS["connectivity"],
        ("tls", "certificate"),
    ),
    Rule(
        "CXDR-CONNECTION-TIMEOUT",
        "Connectivity failures",
        "medium",
        [
            r"\b(connection|connect|request|http|https|upload|download)\b.*\b(timeout|timed out|connection refused|connection reset|no route to host|network unreachable|503|502|504)\b",
            r"\b(curl|libcurl).*\b(error|timeout|couldn't connect|failed to connect)\b",
        ],
        "Network timeouts/refusals may affect registration, heartbeat, policy sync, or updates.",
        COMMON_ACTIONS["connectivity"],
    ),
    Rule(
        "CXDR-BROKER-VM-ISSUE",
        "Broker VM / proxy communication issues",
        "medium",
        [
            r"\b(broker vm|broker|tms_proxy|agent proxy|local agent settings|squid)\b.*\b(fail|failed|failure|unreachable|down|not connected|refused|timeout|certificate|cache miss)\b",
            r"\b(fail|failed|failure|unreachable|timeout|not available).*\b(broker vm|broker|tms_proxy|agent proxy|squid)\b",
            r"\b(broker).*\b(content|installer|upgrade|cache|download).*\b(fail|failed|not available)\b",
        ],
        "Broker VM or local agent proxy/cache communication indicators were found.",
        COMMON_ACTIONS["broker"],
    ),
    Rule(
        "CXDR-CONTENT-UPDATE-FAILURE",
        "Content update failure",
        "high",
        [
            r"\b(content|security content|cu|content update|update package)\b.*\b(fail|failed|failure|error|unable|download failed|install failed|rollback)\b",
            r"\b(last content update|content version).*\b(stale|outdated|missing|not updated)\b",
        ],
        "Content update failures can reduce endpoint protection coverage.",
        COMMON_ACTIONS["content"],
    ),
    Rule(
        "CXDR-INSTALL-UPGRADE-FAILURE",
        "Installation or upgrade failure",
        "high",
        [
            r"\b(install|installation|installer|setup|upgrade|update agent|package manager|rpm|dpkg|msi|pkg)\b.*\b(fail|failed|failure|error|rollback|aborted|cannot|unable)\b",
            r"\b(traps-install|cortex.*installer).*\b(error|failed|failure)\b",
        ],
        "Installation or upgrade failure indicators were detected.",
        COMMON_ACTIONS["install_upgrade"],
    ),
    Rule(
        "CXDR-PERMISSION-NOEXEC",
        "Permission denied / noexec / execution blocked",
        "high",
        [
            r"\b(permission denied|operation not permitted|access denied|eacces|eprem)\b",
            r"\b(noexec|text file busy|cannot execute|exec format error|blocked execution|execution blocked)\b",
            r"\b(root privileges|required administrator|must be run as root|requires elevation)\b",
        ],
        "The agent, installer, or Cytool may be blocked by permissions, noexec mount options, or privilege context.",
        COMMON_ACTIONS["permission"],
    ),
    Rule(
        "CXDR-LINUX-GLIBCXX",
        "Missing dependency errors",
        "critical",
        [
            r"\b(GLIBCXX|GLIBC|libstdc\+\+|libgcc_s|ld-linux|ldd)\b.*\b(not found|missing|version .* not found|cannot open shared object file|undefined symbol)\b",
            r"\berror while loading shared libraries\b",
        ],
        "Linux runtime dependency errors indicate likely OS/library compatibility or package changes.",
        COMMON_ACTIONS["linux_libs"],
    ),
    Rule(
        "CXDR-DRIVER-KERNEL-FAILURE",
        "Kernel module / driver load failure",
        "critical",
        [
            r"\b(kernel module|driver|kext|system extension|network extension|module load|insmod|modprobe)\b.*\b(fail|failed|failure|error|denied|not loaded|unsupported|invalid module format)\b",
            r"\b(secure boot|driver signature|kmod|dkms|kernel headers)\b.*\b(fail|failed|missing|unsupported|denied)\b",
        ],
        "Kernel/module/driver load failures can affect prevention and telemetry collection.",
        COMMON_ACTIONS["driver"],
    ),
    Rule(
        "CXDR-HIGH-RESOURCE-USAGE",
        "High CPU / high memory / resource quota warnings",
        "medium",
        [
            r"\b(high|excessive|spike|quota|limit|threshold)\b.*\b(cpu|memory|ram|rss|working set|resource)\b",
            r"\b(out of memory|oom killer|memory pressure|cpu usage.*[89][0-9]%|cpu usage.*100%)\b",
        ],
        "Resource pressure indicators suggest the agent or local system may be constrained.",
        [
            "Check whether CPU/memory pressure is from the Cortex process or another workload.",
            "Collect process snapshots around the timestamp and compare with scans, upgrades, content updates, or other EDR/AV activity.",
            "Review endpoint resource limits, exclusions, and recent workload changes before changing protection settings.",
        ],
    ),
    Rule(
        "CXDR-CYTOOL-ERROR",
        "Cytool execution errors",
        "medium",
        [
            r"\bcytool\b.*\b(fail|failed|failure|error|not recognized|not found|permission denied|access denied|unauthorized|timeout)\b",
            r"\b(cytool).*\b(exit code|return code)\s*[:=]\s*[1-9]\d*\b",
        ],
        "Cytool command errors were found. Cytool is used to query/manage the agent locally.",
        [
            "Run Cytool from an elevated/admin shell or root context where applicable.",
            "Confirm the expected Cytool path for the platform and agent version.",
            "If changing settings, remember some changes may require agent heartbeat/check-in before console state reflects them.",
        ],
    ),
    Rule(
        "CXDR-TAMPER-AUTH",
        "Tamper protection / uninstall password / authorization issues",
        "high",
        [
            r"\b(tamper|anti[- ]?tamper|uninstall password|authorization|authorized|auth token|passcode)\b.*\b(fail|failed|failure|denied|invalid|required|unauthorized|not authorized)\b",
            r"\b(uninstall|disable protection|stop service).*\b(password required|not authorized|tamper)\b",
        ],
        "Tamper protection or authorization controls are blocking a requested action.",
        [
            "Verify the uninstall/tamper workflow and required authorization from Cortex policy/console.",
            "Confirm the operator has the correct role permissions and endpoint is receiving current policy.",
            "Avoid force-removal unless directed by official support procedures.",
        ],
    ),
    Rule(
        "CXDR-POLICY-SYNC-FAILURE",
        "Policy sync failure",
        "medium",
        [
            r"\b(policy|configuration|profile|agent settings|security profile)\b.*\b(sync|apply|download|parse|update)\b.*\b(fail|failed|failure|error|stale|timeout)\b",
            r"\bfailed to apply policy\b|\bpolicy.*not applied\b",
        ],
        "Policy/configuration synchronization indicators were detected.",
        COMMON_ACTIONS["policy"],
    ),
    Rule(
        "CXDR-DB-CORRUPTION",
        "Database corruption / local persistent DB issues",
        "critical",
        [
            r"\b(database|db|sqlite|persistent db|local db|event db|cache db)\b.*\b(corrupt|corrupted|malformed|locked|ioerr|disk i/o error|cannot open|rebuild|recovery failed)\b",
            r"\bdatabase disk image is malformed\b",
        ],
        "Local persistent database/cache corruption indicators were detected.",
        [
            "Check disk health, free space, and filesystem errors.",
            "Collect full support logs before deleting or rebuilding local databases.",
            "Escalate with timestamps and evidence if corruption repeats after service restart or reinstall.",
        ],
    ),
    Rule(
        "CXDR-MALWARE-ENGINE-ERROR",
        "File scan / malware prevention engine errors",
        "high",
        [
            r"\b(malware|scan|scanner|prevention engine|wf|wildfire|local analysis|quarantine|file analysis)\b.*\b(fail|failed|failure|error|timeout|engine not ready|not initialized)\b",
            r"\bfailed to scan\b|\bscan engine.*unavailable\b",
        ],
        "Malware/file scan or prevention engine errors may reduce prevention coverage.",
        [
            "Confirm the endpoint protection profile and content version.",
            "Check content update health, engine initialization, disk space, and file access errors.",
            "Run a controlled malware scan action if appropriate and compare with endpoint logs.",
        ],
    ),
    Rule(
        "CXDR-MACOS-EXTENSION-FDA",
        "macOS system extension / network extension / full disk access issues",
        "high",
        [
            r"\b(system extension|network extension|full disk access|fda|mdm|privacy preferences|pppc|systemextensionsctl)\b.*\b(not approved|denied|missing|fail|failed|failure|required|blocked|disabled)\b",
            r"\bextension.*waiting for user approval\b|\bfull disk access.*required\b",
        ],
        "macOS approval/privacy controls appear to be blocking full agent functionality.",
        COMMON_ACTIONS["macos"],
    ),
]


COMPILED_RULES = [rule.compile() for rule in RULES]


# -----------------------------
# Timestamp parsing
# -----------------------------

TIMESTAMP_PATTERNS: Sequence[Tuple[Pattern[str], Sequence[str]]] = [
    (re.compile(r"\b(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"), ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S")),
    (re.compile(r"\b(\d{1,2}/\d{1,2}/\d{4}\s+\d{2}:\d{2}:\d{2})\b"), ("%m/%d/%Y %H:%M:%S",)),
    (re.compile(r"\b([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b"), ("%b %d %H:%M:%S",)),
]


def parse_since(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    candidates = [
        "%Y-%m-%d",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%m/%d/%Y",
        "%m/%d/%Y %H:%M:%S",
    ]
    for fmt in candidates:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    raise argparse.ArgumentTypeError(
        "--since must be one of: YYYY-MM-DD, YYYY-MM-DD HH:MM:SS, YYYY-MM-DDTHH:MM:SS, MM/DD/YYYY"
    )


def extract_timestamp(line: str, default_year: Optional[int] = None) -> Tuple[Optional[str], Optional[datetime]]:
    """Return (normalized timestamp string, datetime object) if a supported timestamp is found."""
    for regex, formats in TIMESTAMP_PATTERNS:
        match = regex.search(line)
        if not match:
            continue
        raw = match.group(1)
        for fmt in formats:
            try:
                parse_raw = raw.replace("T", " ")
                parse_fmt = fmt.replace("T", " ")
                if "%Y" not in fmt:
                    parse_raw = f"{default_year or datetime.now().year} {parse_raw}"
                    parse_fmt = f"%Y {parse_fmt}"
                dt = datetime.strptime(parse_raw, parse_fmt)
                return dt.isoformat(sep=" "), dt
            except ValueError:
                continue
    return None, None


# -----------------------------
# File scanning
# -----------------------------

SUPPORTED_SUFFIXES = {".log", ".txt", ".gz"}


def discover_files(input_path: Path) -> Tuple[List[Path], List[SkippedFile]]:
    skipped: List[SkippedFile] = []
    if not input_path.exists():
        raise FileNotFoundError(f"Input path does not exist: {input_path}")

    if input_path.is_file():
        if is_supported_file(input_path):
            return [input_path], skipped
        return [], [SkippedFile(str(input_path), "unsupported file extension")]

    files: List[Path] = []
    for path in input_path.rglob("*"):
        if not path.is_file():
            continue
        if is_supported_file(path):
            files.append(path)
        else:
            skipped.append(SkippedFile(str(path), "unsupported file extension"))
    return sorted(files), skipped


def is_supported_file(path: Path) -> bool:
    name = path.name.lower()
    return any(name.endswith(suffix) for suffix in SUPPORTED_SUFFIXES)


def open_text_file(path: Path) -> Iterator[str]:
    """Open plain text or gzip text logs. Replacement decoding avoids crashes on mixed encodings."""
    if path.name.lower().endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                yield line.rstrip("\n\r")
    else:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                yield line.rstrip("\n\r")


def line_passes_since(line_dt: Optional[datetime], since: Optional[datetime], state: Dict[str, bool]) -> bool:
    """Filter by --since only when a timestamp is available or after an in-scope timestamp was seen.

    For logs with sparse timestamps, once a timestamp is >= since, following untimestamped
    lines are included until another timestamp indicates otherwise.
    """
    if since is None:
        return True
    if line_dt is None:
        return state.get("include_unknown_after_seen", False)
    include = line_dt >= since
    state["include_unknown_after_seen"] = include
    return include


def analyze_file(
    path: Path,
    since: Optional[datetime],
    findings_map: Dict[str, Finding],
    max_evidence_per_rule: int,
    verbose: bool = False,
) -> int:
    lines_scanned = 0
    before: Deque[str] = deque(maxlen=3)
    pending_context: Deque[Tuple[Evidence, int]] = deque()
    since_state = {"include_unknown_after_seen": since is None}

    for line_number, line in enumerate(open_text_file(path), start=1):
        timestamp_str, line_dt = extract_timestamp(line)
        include_line = line_passes_since(line_dt, since, since_state)

        # Add this line as "after" context for earlier matches, even if current line is filtered.
        if pending_context:
            for evidence, remaining in list(pending_context):
                if remaining > 0:
                    evidence.context_after.append(line)
            pending_context = deque(
                (evidence, remaining - 1)
                for evidence, remaining in pending_context
                if remaining - 1 > 0
            )

        if not include_line:
            before.append(line)
            continue

        lines_scanned += 1
        for compiled_rule in COMPILED_RULES:
            if any(pattern.search(line) for pattern in compiled_rule.compiled):
                add_match(
                    findings_map=findings_map,
                    rule=compiled_rule.rule,
                    file_path=path,
                    line_number=line_number,
                    timestamp=timestamp_str,
                    line=line,
                    context_before=list(before),
                    pending_context=pending_context,
                    max_evidence_per_rule=max_evidence_per_rule,
                )

        before.append(line)

    return lines_scanned


def add_match(
    findings_map: Dict[str, Finding],
    rule: Rule,
    file_path: Path,
    line_number: int,
    timestamp: Optional[str],
    line: str,
    context_before: List[str],
    pending_context: Deque[Tuple[Evidence, int]],
    max_evidence_per_rule: int,
) -> None:
    key = rule.rule_id
    finding = findings_map.get(key)
    if finding is None:
        finding = Finding(
            rule_id=rule.rule_id,
            category=rule.category,
            severity=rule.severity,
            explanation=rule.explanation,
            recommended_actions=list(rule.recommended_actions),
        )
        findings_map[key] = finding

    finding.occurrences += 1
    file_str = str(file_path)
    if file_str not in finding.files:
        finding.files.append(file_str)

    if timestamp:
        if finding.first_timestamp is None or timestamp < finding.first_timestamp:
            finding.first_timestamp = timestamp
        if finding.last_timestamp is None or timestamp > finding.last_timestamp:
            finding.last_timestamp = timestamp

    # Deduplicate evidence by normalized text per rule; retain occurrence count separately.
    normalized = re.sub(r"\s+", " ", line.strip().lower())
    evidence_key = f"{file_str}:{line_number}:{normalized}"
    existing_keys = getattr(finding, "_evidence_keys", set())
    if evidence_key in existing_keys:
        return
    setattr(finding, "_evidence_keys", existing_keys)
    existing_keys.add(evidence_key)

    if len(finding.evidence) >= max_evidence_per_rule:
        return

    evidence = Evidence(
        file=file_str,
        line=line_number,
        timestamp=timestamp,
        matched_text=line.strip(),
        context_before=context_before[-3:],
        context_after=[],
    )
    finding.evidence.append(evidence)
    pending_context.append((evidence, 3))


# -----------------------------
# Scoring and report generation
# -----------------------------

def clean_finding_for_output(finding: Finding) -> Finding:
    if hasattr(finding, "_evidence_keys"):
        delattr(finding, "_evidence_keys")
    finding.files = sorted(finding.files)
    return finding


def score_health(findings: Sequence[Finding]) -> int:
    score = 100
    category_counts = Counter()
    for finding in findings:
        base = SEVERITY_PENALTY.get(finding.severity, 5)
        repeated_penalty = min(18, max(0, finding.occurrences - 1) * max(1, base // 4))
        score -= base + repeated_penalty
        category_counts[finding.category] += finding.occurrences

    # Extra impact for repeated critical operational categories.
    for category in (
        "Connectivity failures",
        "Agent not checking in / heartbeat failure",
        "Agent service stopped/crashed/restart loop",
    ):
        count = category_counts.get(category, 0)
        if count >= 5:
            score -= min(20, count // 2)

    return max(0, min(100, score))


def likely_root_causes(findings: Sequence[Finding]) -> List[Dict[str, Any]]:
    ranked = sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity, 9),
            -f.occurrences,
            f.category,
        ),
    )
    result: List[Dict[str, Any]] = []
    seen_categories = set()
    for finding in ranked:
        if finding.category in seen_categories:
            continue
        seen_categories.add(finding.category)
        result.append(
            {
                "label": f"Likely indicator: {finding.category}",
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "occurrences": finding.occurrences,
                "why": finding.explanation,
                "recommended_next_action": finding.recommended_actions[0] if finding.recommended_actions else "",
            }
        )
        if len(result) == 5:
            break
    return result


def build_report(
    input_path: Path,
    since_raw: Optional[str],
    files_scanned_count: int,
    lines_scanned: int,
    findings: List[Finding],
    skipped_files: List[SkippedFile],
) -> Report:
    findings_by_severity = Counter(f.severity for f in findings)
    findings_by_category = Counter(f.category for f in findings)
    summary = Summary(
        total_files_scanned=files_scanned_count,
        total_lines_scanned=lines_scanned,
        total_findings=sum(f.occurrences for f in findings),
        findings_by_severity=dict(sorted(findings_by_severity.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 9))),
        findings_by_category=dict(sorted(findings_by_category.items())),
        health_score=score_health(findings),
        top_likely_root_causes=likely_root_causes(findings),
        skipped_files=skipped_files,
    )
    return Report(
        generated_at=datetime.now().isoformat(timespec="seconds"),
        input_path=str(input_path),
        since=since_raw,
        summary=summary,
        findings=findings,
    )


def report_to_dict(report: Report) -> Dict[str, Any]:
    return asdict(report)


def write_json(report: Report, path: Path) -> None:
    path.write_text(json.dumps(report_to_dict(report), indent=2, ensure_ascii=False), encoding="utf-8")


def write_csv(report: Report, path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["severity", "category", "rule_id", "file", "line", "timestamp", "evidence", "recommendation"],
        )
        writer.writeheader()
        for finding in report.findings:
            recommendation = " | ".join(finding.recommended_actions)
            if finding.evidence:
                for evidence in finding.evidence:
                    writer.writerow(
                        {
                            "severity": finding.severity,
                            "category": finding.category,
                            "rule_id": finding.rule_id,
                            "file": evidence.file,
                            "line": evidence.line,
                            "timestamp": evidence.timestamp or "",
                            "evidence": evidence.matched_text,
                            "recommendation": recommendation,
                        }
                    )
            else:
                writer.writerow(
                    {
                        "severity": finding.severity,
                        "category": finding.category,
                        "rule_id": finding.rule_id,
                        "file": ",".join(finding.files),
                        "line": "",
                        "timestamp": "",
                        "evidence": f"{finding.occurrences} occurrence(s), evidence suppressed",
                        "recommendation": recommendation,
                    }
                )


def write_html(report: Report, path: Path) -> None:
    def esc(value: Any) -> str:
        return html.escape("" if value is None else str(value))

    severity_rows = "".join(
        f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>"
        for k, v in report.summary.findings_by_severity.items()
    ) or "<tr><td colspan='2'>None</td></tr>"

    root_causes = "".join(
        "<li><strong>{}</strong> [{} / {} occurrence(s)]<br>{}<br><em>Next:</em> {}</li>".format(
            esc(item["label"]),
            esc(item["severity"]),
            esc(item["occurrences"]),
            esc(item["why"]),
            esc(item["recommended_next_action"]),
        )
        for item in report.summary.top_likely_root_causes
    ) or "<li>No issue indicators detected.</li>"

    finding_rows: List[str] = []
    evidence_blocks: List[str] = []
    for finding in report.findings:
        finding_rows.append(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                esc(finding.severity),
                esc(finding.category),
                esc(finding.rule_id),
                esc(finding.occurrences),
                esc(", ".join(finding.files[:3]) + (" ..." if len(finding.files) > 3 else "")),
                esc(finding.explanation),
            )
        )
        for evidence in finding.evidence:
            context = "\n".join(evidence.context_before + ["> " + evidence.matched_text] + evidence.context_after)
            evidence_blocks.append(
                "<section class='evidence'><h3>{} - {}:{}</h3><p><strong>Timestamp:</strong> {}</p><pre>{}</pre><p><strong>Recommended actions:</strong> {}</p></section>".format(
                    esc(finding.rule_id),
                    esc(evidence.file),
                    esc(evidence.line),
                    esc(evidence.timestamp or "not found"),
                    esc(context),
                    esc(" | ".join(finding.recommended_actions)),
                )
            )

    skipped = "".join(
        f"<tr><td>{esc(item.file)}</td><td>{esc(item.reason)}</td></tr>"
        for item in report.summary.skipped_files
    ) or "<tr><td colspan='2'>None</td></tr>"

    html_doc = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Cortex XDR Log Analyzer Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; color: #222; }}
    h1, h2 {{ color: #17324d; }}
    table {{ border-collapse: collapse; width: 100%; margin: 12px 0 24px; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; vertical-align: top; }}
    th {{ background: #f2f5f8; text-align: left; }}
    pre {{ background: #f7f7f7; border: 1px solid #ddd; padding: 10px; overflow-x: auto; }}
    .score {{ font-size: 2em; font-weight: bold; }}
    .evidence {{ border-top: 1px solid #ddd; padding-top: 10px; }}
  </style>
</head>
<body>
  <h1>Cortex XDR Agent Troubleshooting Log Report</h1>
  <h2>Executive Summary</h2>
  <p><strong>Generated:</strong> {esc(report.generated_at)}</p>
  <p><strong>Input:</strong> {esc(report.input_path)}</p>
  <p><strong>Since filter:</strong> {esc(report.since or "not set")}</p>
  <p class="score">Health score: {esc(report.summary.health_score)}/100</p>
  <table>
    <tr><th>Files scanned</th><td>{esc(report.summary.total_files_scanned)}</td></tr>
    <tr><th>Lines scanned</th><td>{esc(report.summary.total_lines_scanned)}</td></tr>
    <tr><th>Total issue occurrences</th><td>{esc(report.summary.total_findings)}</td></tr>
  </table>

  <h2>Findings by Severity</h2>
  <table><tr><th>Severity</th><th>Count</th></tr>{severity_rows}</table>

  <h2>Top 5 Likely Root Cause Indicators</h2>
  <ol>{root_causes}</ol>

  <h2>Findings</h2>
  <table>
    <tr><th>Severity</th><th>Category</th><th>Rule ID</th><th>Occurrences</th><th>Files</th><th>Explanation</th></tr>
    {''.join(finding_rows) or "<tr><td colspan='6'>No issue indicators detected.</td></tr>"}
  </table>

  <h2>Evidence Snippets</h2>
  {''.join(evidence_blocks) or "<p>No evidence snippets available.</p>"}

  <h2>Skipped Files</h2>
  <table><tr><th>File</th><th>Reason</th></tr>{skipped}</table>
</body>
</html>
"""
    path.write_text(html_doc, encoding="utf-8")


# -----------------------------
# Console output
# -----------------------------

def print_console_summary(report: Report, verbose: bool = False) -> None:
    summary = report.summary
    print("\nCortex XDR Agent Log Analysis Summary")
    print("=" * 44)
    print(f"Input:              {report.input_path}")
    print(f"Generated:          {report.generated_at}")
    print(f"Files scanned:      {summary.total_files_scanned}")
    print(f"Lines scanned:      {summary.total_lines_scanned}")
    print(f"Findings:           {summary.total_findings}")
    print(f"Health score:       {summary.health_score}/100")
    if report.since:
        print(f"Since filter:       {report.since}")

    print("\nFindings by severity:")
    if summary.findings_by_severity:
        for severity, count in summary.findings_by_severity.items():
            print(f"  {severity:<8} {count}")
    else:
        print("  none")

    print("\nTop likely root cause indicators:")
    if summary.top_likely_root_causes:
        for index, item in enumerate(summary.top_likely_root_causes, start=1):
            print(f"  {index}. {item['severity'].upper()} {item['label']} ({item['occurrences']} occurrence(s), {item['rule_id']})")
            print(f"     Next: {item['recommended_next_action']}")
    else:
        print("  No issue indicators detected.")

    if verbose and report.findings:
        print("\nEvidence preview:")
        for finding in report.findings[:10]:
            print(f"\n- {finding.severity.upper()} {finding.rule_id}: {finding.explanation}")
            for evidence in finding.evidence[:2]:
                print(f"  {evidence.file}:{evidence.line} [{evidence.timestamp or 'no timestamp'}] {evidence.matched_text}")

    if summary.skipped_files:
        print(f"\nSkipped files: {len(summary.skipped_files)}")
        if verbose:
            for skipped in summary.skipped_files[:20]:
                print(f"  {skipped.file}: {skipped.reason}")


# -----------------------------
# Self-test
# -----------------------------

SAMPLE_LOG = """2026-05-08 13:22:10 Cortex XDR agent service stopped unexpectedly
2026-05-08 13:22:15 cytool status failed return code=1
2026-05-08 13:23:00 heartbeat failed: TLS certificate verify failed through proxy
2026-05-08 13:24:00 DNS resolver failed: temporary failure in name resolution
2026-05-08 13:25:00 Content update download failed from Broker VM cache
2026-05-08 13:26:00 error while loading shared libraries: libstdc++.so.6: version `GLIBCXX_3.4.26' not found
May  8 13:27:00 host system extension waiting for user approval; full disk access required
05/08/2026 13:28:00 policy sync failed timeout while applying agent settings
2026-05-08T13:29:00 database disk image is malformed in local persistent db
2026-05-08 13:30:00 kernel module load failed: invalid module format
"""


def run_self_test(verbose: bool = False) -> int:
    with tempfile.TemporaryDirectory(prefix="cxdr_log_analyzer_") as tmp:
        tmp_path = Path(tmp)
        plain = tmp_path / "agent.log"
        gz_path = tmp_path / "agent2.log.gz"
        plain.write_text(SAMPLE_LOG, encoding="utf-8")
        with gzip.open(gz_path, "wt", encoding="utf-8") as handle:
            handle.write(SAMPLE_LOG)

        report = analyze_input(
            input_path=tmp_path,
            since_raw=None,
            max_evidence_per_rule=10,
            verbose=verbose,
        )
        print_console_summary(report, verbose=True)

        expected_rules = {
            "CXDR-SERVICE-STOPPED",
            "CXDR-CYTOOL-ERROR",
            "CXDR-TLS-CERT-FAILURE",
            "CXDR-DNS-FAILURE",
            "CXDR-BROKER-VM-ISSUE",
            "CXDR-CONTENT-UPDATE-FAILURE",
            "CXDR-LINUX-GLIBCXX",
            "CXDR-MACOS-EXTENSION-FDA",
            "CXDR-POLICY-SYNC-FAILURE",
            "CXDR-DB-CORRUPTION",
            "CXDR-DRIVER-KERNEL-FAILURE",
        }
        actual_rules = {finding.rule_id for finding in report.findings}
        missing = sorted(expected_rules - actual_rules)
        if missing:
            print("\nSELF-TEST FAILED: missing detections: " + ", ".join(missing), file=sys.stderr)
            return 1

        print("\nSELF-TEST PASSED")
        return 0


# -----------------------------
# Main orchestration
# -----------------------------

def analyze_input(
    input_path: Path,
    since_raw: Optional[str],
    max_evidence_per_rule: int = 25,
    verbose: bool = False,
) -> Report:
    since_dt = parse_since(since_raw)
    files, skipped = discover_files(input_path)
    findings_map: Dict[str, Finding] = {}
    total_lines = 0
    scanned_files = 0

    for path in files:
        try:
            lines = analyze_file(
                path=path,
                since=since_dt,
                findings_map=findings_map,
                max_evidence_per_rule=max_evidence_per_rule,
                verbose=verbose,
            )
            total_lines += lines
            scanned_files += 1
        except PermissionError as exc:
            skipped.append(SkippedFile(str(path), f"permission denied: {exc}"))
        except OSError as exc:
            skipped.append(SkippedFile(str(path), f"read error: {exc}"))
        except UnicodeError as exc:
            skipped.append(SkippedFile(str(path), f"decode error: {exc}"))
        except Exception as exc:  # Last-resort protection for support bundles with odd files.
            skipped.append(SkippedFile(str(path), f"unexpected read/analyze error: {type(exc).__name__}: {exc}"))

    findings = [clean_finding_for_output(finding) for finding in findings_map.values()]
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.category, f.rule_id))
    return build_report(input_path, since_raw, scanned_files, total_lines, findings, skipped)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze Cortex XDR agent troubleshooting logs and report likely issue indicators."
    )
    parser.add_argument("--input", "-i", type=Path, help="Path to a log file or folder of logs.")
    parser.add_argument("--output", "-o", type=Path, help="Write JSON report to this path.")
    parser.add_argument("--html", type=Path, help="Write HTML report to this path.")
    parser.add_argument("--csv", type=Path, help="Write CSV findings to this path.")
    parser.add_argument("--since", help='Analyze lines after this date when timestamps are available, e.g. "2026-05-01".')
    parser.add_argument("--verbose", "-v", action="store_true", help="Print evidence preview and skipped file details.")
    parser.add_argument("--self-test", action="store_true", help="Create sample logs and demonstrate detections.")
    parser.add_argument("--max-evidence-per-rule", type=int, default=25, help="Maximum evidence snippets retained per rule.")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.max_evidence_per_rule <= 0:
        parser.error("--max-evidence-per-rule must be positive")

    if args.self_test:
        return run_self_test(verbose=args.verbose)

    if not args.input:
        parser.error("--input is required unless --self-test is used")

    try:
        report = analyze_input(
            input_path=args.input,
            since_raw=args.since,
            max_evidence_per_rule=args.max_evidence_per_rule,
            verbose=args.verbose,
        )
    except (FileNotFoundError, argparse.ArgumentTypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print_console_summary(report, verbose=args.verbose)

    try:
        if args.output:
            write_json(report, args.output)
            print(f"\nWrote JSON report: {args.output}")
        if args.csv:
            write_csv(report, args.csv)
            print(f"Wrote CSV findings: {args.csv}")
        if args.html:
            write_html(report, args.html)
            print(f"Wrote HTML report: {args.html}")
    except OSError as exc:
        print(f"ERROR: failed writing output: {exc}", file=sys.stderr)
        return 3

    # Exit code is informational. Findings are not treated as program failure.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
