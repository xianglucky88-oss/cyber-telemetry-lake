import sqlite3

from cyber_telemetry.pipeline import run_pipeline


def test_correlates_events_by_principal(tmp_path):
    result = run_pipeline([
        {"event_id": "1", "occurred_at": "2026-01-01T00:00:00Z", "source": "dns", "principal": "A", "asset": "x", "event_type": "lookup", "severity": "low"},
        {"event_id": "2", "occurred_at": "2026-01-01T00:05:00Z", "source": "endpoint", "principal": "A", "asset": "x", "event_type": "exec", "severity": "high"},
    ], tmp_path / "cyber.sqlite3")
    assert result == {"accepted": 2, "rejected": 0, "duplicates": 0, "incidents": 1}
    with sqlite3.connect(tmp_path / "cyber.sqlite3") as conn:
        assert conn.execute("select max_severity from incidents").fetchone()[0] == "high"
