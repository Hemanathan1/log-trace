from datetime import datetime

from core.parser import parse_log


def write_log(tmp_path, text):
    path = tmp_path / "test.log"
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_parses_a_valid_line(tmp_path):
    path = write_log(tmp_path, "2026-10-30 14:00:01 FAILED 10.0.0.5 Failed login for root\n")
    entries = parse_log(path)
    assert len(entries) == 1
    entry = entries[0]
    assert entry["level"] == "FAILED"
    assert entry["source_ip"] == "10.0.0.5"
    assert entry["message"] == "Failed login for root"
    assert entry["timestamp"] == datetime(2026, 10, 30, 14, 0, 1)


def test_level_is_uppercased(tmp_path):
    path = write_log(tmp_path, "2026-10-30 14:00:02 error 10.0.0.6 Disk error\n")
    assert parse_log(path)[0]["level"] == "ERROR"


def test_skips_comments_and_blank_lines(tmp_path):
    text = "# a comment\n\n2026-10-30 14:00:01 INFO 10.0.0.5 hello\n"
    entries = parse_log(write_log(tmp_path, text))
    assert len(entries) == 1
    assert entries[0]["line"] == 3  # line numbers count the skipped lines


def test_unparseable_line_becomes_unknown_entry(tmp_path):
    entries = parse_log(write_log(tmp_path, "this is not a log line\n"))
    assert len(entries) == 1
    assert entries[0]["level"] == "UNKNOWN"
    assert entries[0]["source_ip"] == "N/A"
    assert entries[0]["message"] == "this is not a log line"


def test_invalid_timestamp_keeps_entry_with_none(tmp_path):
    entries = parse_log(write_log(tmp_path, "2026-13-45 99:99:99 INFO 10.0.0.5 odd time\n"))
    assert len(entries) == 1
    assert entries[0]["timestamp"] is None
    assert entries[0]["level"] == "INFO"