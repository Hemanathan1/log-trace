"""
Threat Detector
Analyses parsed log entries and detects suspicious patterns:
- Brute force login attempts
- Port scan activity
- Error spikes
- Critical system events
- Suspicious IPs
"""

from collections import Counter, defaultdict


def detect_threats(entries: list, threshold: int = 5) -> dict:
    """
    Run all threat detection checks and return a results dict.
    """
    alerts = []

    # Counters
    failed_logins_by_ip = Counter()
    port_scans_by_ip    = Counter()
    errors_by_ip        = Counter()
    all_ips             = Counter()
    level_counts        = Counter()

    # Group entries by IP
    ip_messages = defaultdict(list)

    for entry in entries:
        ip  = entry["source_ip"]
        lvl = entry["level"]
        msg = entry["message"].lower()

        level_counts[lvl] += 1
        all_ips[ip] += 1
        ip_messages[ip].append(entry)

        # Failed logins
        if lvl == "FAILED" and "failed login" in msg:
            failed_logins_by_ip[ip] += 1

        # Port scans
        if lvl == "SCAN" or "port scan" in msg:
            port_scans_by_ip[ip] += 1

        # Errors
        if lvl == "ERROR":
            errors_by_ip[ip] += 1

    # ── Detection Rules ────────────────────────────────────────────────────

    # Rule 1: Brute Force — too many failed logins from same IP
    for ip, count in failed_logins_by_ip.items():
        if count >= threshold:
            severity = "CRITICAL" if count >= threshold * 2 else "WARNING"
            alerts.append({
                "type":     "Brute Force Attack",
                "severity": severity,
                "source_ip": ip,
                "detail":   f"{count} failed login attempts from {ip}",
                "count":    count,
            })

    # Rule 2: Port Scan — multiple port scan entries from same IP
    for ip, count in port_scans_by_ip.items():
        if count >= 3:
            alerts.append({
                "type":     "Port Scan Detected",
                "severity": "CRITICAL",
                "source_ip": ip,
                "detail":   f"{count} ports scanned from {ip}",
                "count":    count,
            })

    # Rule 3: Error Spike — too many errors from same IP
    for ip, count in errors_by_ip.items():
        if count >= 3:
            alerts.append({
                "type":     "Error Spike",
                "severity": "WARNING",
                "source_ip": ip,
                "detail":   f"{count} errors from {ip}",
                "count":    count,
            })

    # Rule 4: Critical log entries
    for entry in entries:
        if entry["level"] == "CRITICAL":
            alerts.append({
                "type":     "Critical System Event",
                "severity": "CRITICAL",
                "source_ip": entry["source_ip"],
                "detail":   entry["message"],
                "count":    1,
            })

    # Rule 5: Suspicious keywords in messages
    suspicious_keywords = ["exfiltration", "unauthorized", "malware", "intrusion", "exploit"]
    for entry in entries:
        for keyword in suspicious_keywords:
            if keyword in entry["message"].lower():
                alerts.append({
                    "type":     "Suspicious Activity",
                    "severity": "CRITICAL",
                    "source_ip": entry["source_ip"],
                    "detail":   f"Keyword '{keyword}' detected: {entry['message']}",
                    "count":    1,
                })

    # Sort alerts — CRITICAL first
    severity_order = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}
    alerts.sort(key=lambda a: severity_order.get(a["severity"], 99))

    return {
        "alerts":               alerts,
        "total_entries":        len(entries),
        "total_failed_logins":  sum(failed_logins_by_ip.values()),
        "total_errors":         sum(errors_by_ip.values()),
        "total_warnings":       level_counts.get("WARNING", 0),
        "critical_count":       sum(1 for a in alerts if a["severity"] == "CRITICAL"),
        "warning_count":        sum(1 for a in alerts if a["severity"] == "WARNING"),
        "top_ips":              dict(all_ips.most_common(10)),
        "level_counts":         dict(level_counts),
        "failed_logins_by_ip":  dict(failed_logins_by_ip),
        "entries":              entries,
    }
