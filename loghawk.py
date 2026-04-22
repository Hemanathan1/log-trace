"""
LogHawk — Network Log Analyser
Reads log files, detects suspicious patterns, and generates security reports.
"""

import argparse
from core.parser import parse_log
from core.detector import detect_threats
from reports.reporter import generate_report


def main():
    parser = argparse.ArgumentParser(description="LogHawk — Network Log Analyser")
    parser.add_argument("--log",       default="logs/sample.log", help="Path to log file")
    parser.add_argument("--threshold", type=int, default=5,        help="Failed login attempts before flagging (default: 5)")
    parser.add_argument("--format",    choices=["html", "json", "both"], default="both")
    args = parser.parse_args()

    print("\n🦅 LogHawk — Network Log Analyser")
    print(f"   Log file  : {args.log}")
    print(f"   Threshold : {args.threshold} failed attempts")
    print(f"   Format    : {args.format}")
    print(f"\n🔍 Parsing log file...\n")

    # Step 1: Parse
    entries = parse_log(args.log)
    if not entries:
        print("❌ No log entries found. Check your log file path.")
        return

    print(f"✅ Parsed {len(entries)} log entries\n")

    # Step 2: Detect threats
    results = detect_threats(entries, threshold=args.threshold)

    # Step 3: Print to terminal
    print(f"{'='*55}")
    print(f"  THREAT DETECTION RESULTS")
    print(f"{'='*55}")

    if not results["alerts"]:
        print("  ✅ No threats detected!")
    else:
        for alert in results["alerts"]:
            icon = "🔴" if alert["severity"] == "CRITICAL" else "🟡"
            print(f"  {icon}  [{alert['severity']:<8}]  {alert['type']:<30}  {alert['detail']}")

    print(f"\n{'='*55}")
    print(f"  SUMMARY")
    print(f"{'='*55}")
    print(f"  Total entries   : {results['total_entries']}")
    print(f"  Failed logins   : {results['total_failed_logins']}")
    print(f"  Errors          : {results['total_errors']}")
    print(f"  Warnings        : {results['total_warnings']}")
    print(f"  Critical alerts : {results['critical_count']}")
    print(f"  Total alerts    : {len(results['alerts'])}")

    # Step 4: Generate report
    generate_report(results, fmt=args.format)
    print("\n✅ Done!\n")


if __name__ == "__main__":
    main()
