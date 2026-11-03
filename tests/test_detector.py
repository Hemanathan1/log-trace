from core.detector import detect_threats


def make_entry(level, ip, message):
    """Build a minimal parsed log entry, the same shape parse_log() returns."""
    return {"source_ip": ip, "level": level, "message": message}


def failed_logins(ip, n):
    return [make_entry("FAILED", ip, "Failed login for root") for _ in range(n)]


def alerts_of_type(result, alert_type):
    return [a for a in result["alerts"] if a["type"] == alert_type]


def test_empty_input_gives_no_alerts():
    result = detect_threats([])
    assert result["alerts"] == []
    assert result["total_entries"] == 0


def test_brute_force_below_threshold_is_not_flagged():
    result = detect_threats(failed_logins("10.0.0.5", 4))
    assert alerts_of_type(result, "Brute Force Attack") == []


def test_brute_force_at_threshold_is_warning():
    result = detect_threats(failed_logins("10.0.0.5", 5))
    alerts = alerts_of_type(result, "Brute Force Attack")
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "WARNING"
    assert alerts[0]["source_ip"] == "10.0.0.5"
    assert alerts[0]["count"] == 5


def test_brute_force_at_double_threshold_is_critical():
    result = detect_threats(failed_logins("10.0.0.5", 10))
    alerts = alerts_of_type(result, "Brute Force Attack")
    assert alerts[0]["severity"] == "CRITICAL"


def test_brute_force_counts_each_ip_separately():
    entries = failed_logins("10.0.0.5", 3) + failed_logins("10.0.0.6", 3)
    result = detect_threats(entries)
    assert alerts_of_type(result, "Brute Force Attack") == []


def test_port_scan_detected_from_three_scan_entries():
    entries = [make_entry("SCAN", "10.0.0.9", "Probe on port %d" % p) for p in (22, 80, 443)]
    result = detect_threats(entries)
    alerts = alerts_of_type(result, "Port Scan Detected")
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "CRITICAL"
    assert alerts[0]["count"] == 3


def test_error_spike_detected_from_three_errors():
    entries = [make_entry("ERROR", "10.0.0.7", "Disk read failure") for _ in range(3)]
    result = detect_threats(entries)
    alerts = alerts_of_type(result, "Error Spike")
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "WARNING"


def test_critical_entry_creates_critical_system_event():
    result = detect_threats([make_entry("CRITICAL", "10.0.0.8", "Kernel panic")])
    alerts = alerts_of_type(result, "Critical System Event")
    assert len(alerts) == 1
    assert alerts[0]["detail"] == "Kernel panic"


def test_suspicious_keyword_is_flagged():
    result = detect_threats([make_entry("INFO", "10.0.0.4", "Possible data exfiltration")])
    alerts = alerts_of_type(result, "Suspicious Activity")
    assert len(alerts) == 1
    assert "exfiltration" in alerts[0]["detail"]


def test_critical_alerts_are_sorted_before_warnings():
    entries = failed_logins("10.0.0.5", 5) + [make_entry("CRITICAL", "10.0.0.8", "Kernel panic")]
    result = detect_threats(entries)
    assert result["alerts"][0]["severity"] == "CRITICAL"
    assert result["alerts"][-1]["severity"] == "WARNING"


def test_summary_counts_match_alerts():
    result = detect_threats(failed_logins("10.0.0.5", 5))
    assert result["total_entries"] == 5
    assert result["total_failed_logins"] == 5
    assert result["warning_count"] == 1
    assert result["critical_count"] == 0