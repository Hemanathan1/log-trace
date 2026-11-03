# LogHawk

![CI](https://github.com/Hemanathan1/log-trace/actions/workflows/ci.yml/badge.svg)

LogHawk is a Python command-line tool that reads network and system log files, detects suspicious patterns, and generates a security report. An optional AI step uses the Gemini API to explain each alert in plain language.

![Demo](demo.png)

## Features

- Parses log lines into structured entries (timestamp, level, source IP, message)
- Five detection rules:
  - **Brute Force Attack:** repeated failed logins from one IP (WARNING at the threshold, CRITICAL at double the threshold)
  - **Port Scan Detected:** 3 or more scan entries from one IP
  - **Error Spike:** 3 or more errors from one IP
  - **Critical System Event:** any log entry with level CRITICAL
  - **Suspicious Activity:** keywords such as exfiltration, unauthorized, malware, intrusion, exploit
- Alerts sorted by severity (CRITICAL first)
- JSON and HTML reports saved in `reports/`
- Optional AI explanation of alerts with the Gemini API
- 16 automated tests, run on every push with GitHub Actions

The core tool has zero external dependencies (only the optional AI step needs `google-genai`). Requires Python 3.10 or newer.

## Quick start

```
python loghawk.py
```

Useful options:

| Option | Meaning |
|---|---|
| `--log <file>` | Log file to analyse |
| `--threshold <n>` | Failed-login count that triggers a brute-force alert (default 5) |
| `--format html` | Also produce an HTML report |

Reports are saved as `reports/loghawk_YYYYMMDD_HHMMSS.json` (and `.html`).

## Log format

One entry per line:

```
TIMESTAMP LEVEL SOURCE_IP MESSAGE
2026-10-30 14:00:01 FAILED 10.0.0.5 Failed login for root
```

Blank lines and lines starting with `#` are skipped. Lines that don't match the format are kept as `UNKNOWN` entries.

## AI explanation (optional)

`ai_explain.py` reads the latest report in `reports/`, sends all alerts to the Gemini API in one request, and prints an overall assessment plus an explanation and recommended actions for each alert. The result is also saved as `reports/loghawk_..._ai.json`. Sending all alerts together lets the model link alerts from the same IP into one incident.

```
pip install google-genai
$env:GEMINI_API_KEY="your-key"     # PowerShell; never commit your key
python loghawk.py
python ai_explain.py
```

The AI output is a suggestion for a person to verify. The rule-based alerts remain the source of truth, and the core tool works without this step.

## Tests

```
pip install pytest
python -m pytest -v
```

The tests cover the parser and all five detection rules. They run automatically on every push with GitHub Actions.

## Project structure

```
loghawk.py          entry point
ai_explain.py       optional Gemini explanation step
core/parser.py      parses log lines into entries
core/detector.py    detection rules
reports/reporter.py builds JSON and HTML reports
logs/sample.log     sample input
tests/              pytest tests
.github/workflows/  CI (runs the tests)
```

## Roadmap

- Add RAG over runbooks so the AI step can cite fix procedures
- Add an ML anomaly detector (scikit-learn) alongside the rules
- Add more detection rules and log formats