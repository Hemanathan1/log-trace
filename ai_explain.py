"""LogHawk AI: reads the latest LogHawk JSON report, asks Gemini to explain
the alerts, and saves the result next to the report as *_ai.json."""
import glob
import json
import os
import sys

from google import genai
from google.genai import types

MODEL = "gemini-2.5-flash"


def find_latest_report(folder="reports"):
    files = [f for f in glob.glob(os.path.join(folder, "loghawk_*.json"))
             if not f.endswith("_ai.json")]
    if not files:
        sys.exit("No LogHawk report found. Run python loghawk.py first.")
    return max(files, key=os.path.getmtime)


def build_prompt(alerts):
    numbered = []
    for i, a in enumerate(alerts):
        numbered.append(
            f'{i}: type={a["type"]}, severity={a["severity"]}, '
            f'ip={a["source_ip"]}, count={a["count"]}, detail={a["detail"]}'
        )
    alert_text = "\n".join(numbered)
    return f"""You are a security analyst. Below are alerts from a log analyzer.
Look at them together: the same IP address may appear in several alerts.

Return JSON with exactly these fields:
- "overall_assessment": 2-3 sentences describing what is happening overall
- "alerts": a list with one item per alert, in the same order, each with:
    - "index": the alert number given below
    - "explanation": one sentence
    - "recommended_actions": a list of up to 3 short strings

Alerts:
{alert_text}"""


def ask_gemini(prompt):
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        sys.exit("Set the GEMINI_API_KEY environment variable first.")
    client = genai.Client(api_key=api_key)
    response = client.models.generate_content(
        model=MODEL,
        contents=prompt,
        config=types.GenerateContentConfig(response_mime_type="application/json"),
    )
    return json.loads(response.text)


def main():
    report_path = find_latest_report()
    with open(report_path, encoding="utf-8") as f:
        report = json.load(f)
    alerts = report["alerts"]
    print(f"Report: {report_path} ({len(alerts)} alerts)")

    ai = ask_gemini(build_prompt(alerts))

    print("\nOVERALL:", ai["overall_assessment"])
    for item in ai["alerts"]:
        a = alerts[item["index"]]
        print(f'\n[{a["severity"]}] {a["type"]} - {a["source_ip"]}')
        print("  ", item["explanation"])
        for action in item["recommended_actions"]:
            print("   -", action)

    out_path = report_path.replace(".json", "_ai.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"source_report": report_path, "ai_analysis": ai}, f, indent=2)
    print(f"\nSaved: {out_path}")


if __name__ == "__main__":
    main()
