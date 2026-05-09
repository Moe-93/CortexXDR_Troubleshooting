# Cortex XDR Log Analyzer

`cortex_xdr_log_analyzer.py` is a standalone Python 3 utility for support engineers analyzing Cortex XDR agent troubleshooting logs from Windows, Linux, and macOS endpoints.

It scans one log file or a recursive folder of logs, detects likely issue indicators, captures evidence with context, calculates a health score, and exports console, JSON, CSV, and HTML reports.

## Supported inputs

- Plain text logs: `.log`, `.txt`
- Compressed logs: `.gz`
- Recursive folder scanning

Common Cortex XDR troubleshooting sources include Linux installation and agent logs such as `/var/log/traps-install.log` and `/var/log/traps/`, macOS logs under `/Library/Logs/PaloAltoNetworks/Cortex XDR/`, and Windows service/installer/support log bundles.

## Usage

```bash
python cortex_xdr_log_analyzer.py --input /path/to/log_or_folder
```

Write JSON, CSV, and HTML outputs:

```bash
python cortex_xdr_log_analyzer.py \
  --input ./cortex_support_logs \
  --output report.json \
  --csv findings.csv \
  --html report.html \
  --verbose
```

Analyze only entries after a date when timestamps are available:

```bash
python cortex_xdr_log_analyzer.py --input ./logs --since "2026-05-01"
```

Run built-in sample detections:

```bash
python cortex_xdr_log_analyzer.py --self-test
```

## Windows examples

```powershell
python .\cortex_xdr_log_analyzer.py --input "C:\Temp\CortexSupportLogs" --output .\report.json --html .\report.html --csv .\findings.csv
python .\cortex_xdr_log_analyzer.py --input "C:\ProgramData\Palo Alto Networks\Traps\logs\pmd.log" --verbose
```

## Linux examples

```bash
python3 cortex_xdr_log_analyzer.py --input /var/log/traps-install.log --verbose
python3 cortex_xdr_log_analyzer.py --input /var/log/traps --since "2026-05-01" --output report.json
python3 cortex_xdr_log_analyzer.py --input ./support_bundle --html report.html --csv findings.csv
```

## macOS examples

```bash
python3 cortex_xdr_log_analyzer.py --input "/Library/Logs/PaloAltoNetworks/Cortex XDR/" --verbose
python3 cortex_xdr_log_analyzer.py --input ./CortexXDRSupportLogs --output report.json --html report.html
```

## Detected issue categories

- Agent service stopped, crashed, or restart loop
- Agent not checking in / heartbeat failure
- Connectivity failures: DNS, proxy, TLS, certificate, timeout, connection refused
- Broker VM / proxy communication issues
- Content update failure
- Installation or upgrade failure
- Permission denied / noexec / execution blocked
- Missing dependencies, especially Linux `GLIBC`, `GLIBCXX`, and `libstdc++`
- Kernel module / driver load failure
- High CPU / high memory / resource quota warnings
- Cytool execution errors
- Tamper protection / uninstall password / authorization issues
- Policy sync failure
- Database corruption / local persistent DB issues
- File scan / malware prevention engine errors
- macOS system extension / network extension / full disk access issues

## Rule engine

Rules live in the `RULES` list near the top of the script. Each rule includes:

```python
Rule(
    rule_id="CXDR-DNS-FAILURE",
    category="Connectivity failures",
    severity="high",
    patterns=[r"..."],
    explanation="...",
    recommended_actions=[...],
)
```

To add detections, add another `Rule` object with one or more case-insensitive regex patterns.

## Evidence model

For every match, the analyzer captures:

- File path
- Line number
- Timestamp, when a supported timestamp is found
- Matched line
- Three lines before and three lines after as context
- Occurrence counts per rule
- Deduplicated evidence snippets

Supported timestamps include:

- `YYYY-MM-DD HH:MM:SS`
- `YYYY-MM-DDTHH:MM:SS`
- `MM/DD/YYYY HH:MM:SS`
- Syslog style: `May 8 13:22:10`

## Health scoring

The score starts at 100. Deductions are weighted by severity, and repeated operational failures reduce the score further. Critical findings reduce the score more than low/info indicators. Repeated connectivity, heartbeat, and service failures receive additional penalty.

A low score does not prove a root cause. It means the logs contain multiple high-impact indicators that deserve support attention.

## Example JSON structure

```json
{
  "generated_at": "2026-05-08T13:45:00",
  "input_path": "./cortex_support_logs",
  "since": "2026-05-01",
  "summary": {
    "total_files_scanned": 12,
    "total_lines_scanned": 184322,
    "total_findings": 17,
    "findings_by_severity": {
      "critical": 1,
      "high": 5,
      "medium": 8,
      "low": 3
    },
    "findings_by_category": {
      "Connectivity failures": 4,
      "Content update failure": 2,
      "Policy sync failure": 1
    },
    "health_score": 54,
    "top_likely_root_causes": [
      {
        "label": "Likely indicator: Connectivity failures",
        "rule_id": "CXDR-TLS-CERT-FAILURE",
        "severity": "high",
        "occurrences": 3,
        "why": "TLS/certificate validation indicators suggest SSL inspection, trust-chain, or certificate issues.",
        "recommended_next_action": "Verify endpoint DNS resolution to the Cortex tenant, proxy FQDN, and any Broker VM FQDN."
      }
    ],
    "skipped_files": []
  },
  "findings": [
    {
      "rule_id": "CXDR-TLS-CERT-FAILURE",
      "category": "Connectivity failures",
      "severity": "high",
      "explanation": "TLS/certificate validation indicators suggest SSL inspection, trust-chain, or certificate issues.",
      "recommended_actions": [
        "Verify endpoint DNS resolution to the Cortex tenant, proxy FQDN, and any Broker VM FQDN.",
        "Validate outbound HTTPS allow-listing, proxy authentication, TLS inspection bypass, and firewall egress rules."
      ],
      "occurrences": 3,
      "evidence": [
        {
          "file": "agent.log",
          "line": 1204,
          "timestamp": "2026-05-08 13:22:10",
          "matched_text": "TLS certificate verify failed",
          "context_before": ["..."],
          "context_after": ["..."]
        }
      ],
      "files": ["agent.log"],
      "first_timestamp": "2026-05-08 13:22:10",
      "last_timestamp": "2026-05-08 13:25:10"
    }
  ]
}
```

## Operational notes

- Findings are labeled as likely indicators, not confirmed root cause.
- Cytool output and console Last Seen/Last Content Update values should be correlated with log timestamps.
- Some Cortex XDR agent changes may only be reflected after heartbeat/check-in.
- Unreadable files are skipped and recorded in the report rather than crashing the tool.
- The script does not hardcode one Cortex XDR agent version; rules are intentionally generic and extensible.
