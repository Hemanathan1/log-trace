"""
Log Parser
Reads and parses log files into structured entries.
Supports format: TIMESTAMP LEVEL SOURCE MESSAGE
"""

import re
from datetime import datetime


LOG_PATTERN = re.compile(
    r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(\w+)\s+([\d\.]+)\s+(.*)"
)


def parse_log(filepath: str) -> list:
    """
    Parse a log file into a list of structured entry dicts.
    Skips comment lines and blank lines.
    """
    entries = []

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()

                # Skip comments and blank lines
                if not line or line.startswith("#"):
                    continue

                match = LOG_PATTERN.match(line)
                if match:
                    timestamp_str, level, source_ip, message = match.groups()
                    try:
                        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        timestamp = None

                    entries.append({
                        "line":      line_num,
                        "timestamp": timestamp,
                        "timestamp_str": timestamp_str,
                        "level":     level.upper(),
                        "source_ip": source_ip,
                        "message":   message,
                        "raw":       line,
                    })
                else:
                    # Try to include unparsed lines with a warning
                    entries.append({
                        "line":      line_num,
                        "timestamp": None,
                        "timestamp_str": "",
                        "level":     "UNKNOWN",
                        "source_ip": "N/A",
                        "message":   line,
                        "raw":       line,
                    })

    except FileNotFoundError:
        print(f"❌ Log file not found: {filepath}")
        return []
    except Exception as e:
        print(f"❌ Error reading log file: {e}")
        return []

    return entries
