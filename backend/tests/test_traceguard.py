"""Core behaviour tests. Fixtures are small, deterministic CSVs with known outcomes."""
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.analyzer import LogValidationError, analyze_csv
from app.main import app
from app.sample_data import demo_csv

HEADER = "timestamp,username,source_ip,event_type,status\n"
T0 = datetime(2025, 3, 10, 10, 0, 0, tzinfo=timezone.utc)


def row(offset_s: int, user: str, ip: str, etype="login", status="failure", base=T0) -> str:
    ts = (base + timedelta(seconds=offset_s)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"{ts},{user},{ip},{etype},{status}\n"


def run(*rows: str):
    return analyze_csv((HEADER + "".join(rows)).encode(), "test.csv")


def rules_of(result) -> set[str]:
    return {f.rule_id for f in result.findings}


# ---- detection ----
def test_normal_activity_has_no_findings():
    rows = []
    for i, user in enumerate(["alice", "bob", "carol", "dave"]):
        ip = f"10.0.0.{i + 1}"
        rows += [row(i * 600, user, ip, "login", "success"), row(i * 600 + 3600, user, ip, "logout", "success")]
    rows.append(row(60, "alice", "10.0.0.1", "login", "failure"))  # a single typo
    rows.append(row(1200, "bob", "10.0.0.2", "login", "failure"))
    r = run(*rows)
    assert r.findings == [] and r.incidents == []
    assert r.summary.suspicious_events == 0


def test_demo_data_has_no_high_incident_from_benign_baseline_only():
    r = analyze_csv(demo_csv().encode(), "demo", is_demo=True)
    benign_users = {"carol", "grace", "ivan", "liam", "noah", "karl"}
    for inc in r.incidents:
        assert not (set(inc.usernames) <= benign_users and inc.severity in ("HIGH", "CRITICAL"))


def test_repeated_ip_failures_trigger_r001_only_when_threshold_met():
    below = run(*[row(i * 30, f"user{i % 1}", "203.0.113.5") for i in range(4)])
    assert "R001" not in rules_of(below)
    hit = run(*[row(i * 30, "alice", "203.0.113.5") for i in range(6)])
    f = next(f for f in hit.findings if f.rule_id == "R001")
    assert f.source_ips == ["203.0.113.5"] and len(f.event_ids) == 6
    assert "6 failed login attempts" in f.explanation


def test_failures_outside_window_do_not_trigger():
    spread = run(*[row(i * 300, "alice", "203.0.113.5") for i in range(6)])  # 5 min apart => 4 fit in 10 min
    assert "R001" not in rules_of(spread) and "R002" not in rules_of(spread)


def test_success_after_failures_creates_r003_with_same_ip_factor():
    rows = [row(i * 20, "admin", "198.51.100.9") for i in range(6)]
    rows.append(row(180, "admin", "198.51.100.9", "login", "success"))
    r = run(*rows)
    f = next(f for f in r.findings if f.rule_id == "R003")
    assert f.usernames == ["admin"] and len(f.event_ids) == 7
    assert any(sf.factor == "Success from a failing IP" for sf in f.score_factors)
    assert f.severity in ("MEDIUM", "HIGH")


def test_two_failures_then_success_is_not_flagged():
    r = run(row(0, "bob", "10.0.0.2"), row(30, "bob", "10.0.0.2"), row(60, "bob", "10.0.0.2", "login", "success"))
    assert r.findings == []


def test_multiple_usernames_from_one_ip_trigger_r005():
    r = run(*[row(i * 40, u, "198.51.100.77") for i, u in enumerate(["a", "b", "c", "d", "e"])])
    f = next(f for f in r.findings if f.rule_id == "R005")
    assert f.usernames == ["a", "b", "c", "d", "e"]


def test_unusual_hours_login_flagged_as_low():
    base = datetime(2025, 3, 10, 2, 30, tzinfo=timezone.utc)
    r = run(row(0, "dana", "192.0.2.7", "login", "success", base=base),
            row(0, "dana", "10.0.0.9", "login", "success", base=base + timedelta(hours=10)))
    f = next(f for f in r.findings if f.rule_id == "R004")
    assert f.severity == "LOW" and f.risk_score == 25  # base 15 + unfamiliar IP 10
    assert "not evidence of compromise" in f.explanation


# ---- scoring & correlation ----
def attack_rows():
    rows = [row(i * 15, "admin", "203.0.113.45") for i in range(40)]
    rows.append(row(700, "admin", "203.0.113.45", "login", "success"))
    rows += [row(i * 10, f"user{i}", "203.0.113.45") for i in range(30)]
    return rows


def test_scores_are_bounded_and_events_not_double_counted():
    r = run(*attack_rows())
    for f in r.findings:
        assert 0 <= f.risk_score <= 100
    for inc in r.incidents:
        assert 0 <= inc.risk_score <= 100
        flagged = {e for f in r.findings if f.incident_id == inc.id for e in f.event_ids}
        assert inc.event_count == len(flagged)  # union of events, not a sum across rules
        assert sum(f.points for f in inc.score_factors) >= inc.risk_score


def test_related_findings_group_into_one_incident():
    rows = [row(i * 20, "admin", "203.0.113.45") for i in range(6)]
    rows.append(row(200, "admin", "203.0.113.45", "login", "success"))
    r = run(*rows)
    assert {f.rule_id for f in r.findings} >= {"R001", "R002", "R003"}
    assert len(r.incidents) == 1
    inc = r.incidents[0]
    assert inc.usernames == ["admin"] and inc.source_ips == ["203.0.113.45"]
    assert [e.timestamp for e in inc.timeline] == sorted(e.timestamp for e in inc.timeline)


def test_unrelated_findings_stay_separate_incidents():
    rows = [row(i * 20, "admin", "203.0.113.45") for i in range(6)]
    later = T0 + timedelta(hours=5)
    rows += [row(i * 20, "svc", "198.51.100.1", base=later) for i in range(6)]
    r = run(*rows)
    assert len(r.incidents) == 2


def test_same_ip_far_apart_in_time_is_not_merged():
    rows = [row(i * 20, "u1", "203.0.113.45") for i in range(6)]
    rows += [row(i * 20, "u1", "203.0.113.45", base=T0 + timedelta(hours=3)) for i in range(6)]
    assert len(run(*rows).incidents) == 2


# ---- validation ----
def test_missing_columns_error_is_helpful():
    with pytest.raises(LogValidationError) as e:
        analyze_csv(b"time,user,ip\n2025-01-01,a,1.1.1.1\n", "x.csv")
    assert "Missing required column" in e.value.message and "timestamp" in e.value.message


def test_all_rows_invalid_is_rejected_with_row_reasons():
    with pytest.raises(LogValidationError) as e:
        analyze_csv((HEADER + "not-a-date,alice,999.1.1.1,login,success\n").encode(), "x.csv")
    assert any("row 2" in d for d in e.value.details)


def test_bad_rows_are_skipped_not_fatal():
    r = run(row(0, "alice", "10.0.0.1", "login", "success"), "garbage,,,,\n",
            row(5, "bob", "10.0.0.2", "login", "success"), row(5, "bob", "10.0.0.2", "login", "success"))
    assert r.summary.total_events == 2
    assert r.summary.rows_skipped == 1 and r.summary.duplicates_removed == 1


def test_empty_inputs_do_not_crash():
    r = analyze_csv(HEADER.encode(), "headers-only.csv")
    assert r.summary.total_events == 0 and r.incidents == []
    with pytest.raises(LogValidationError):
        analyze_csv(b"", "empty.csv")


def test_naive_timestamps_are_treated_as_utc_with_warning():
    r = analyze_csv((HEADER + "2025-03-10 10:00:00,alice,10.0.0.1,login,success\n").encode(), "n.csv")
    assert r.events[0].timestamp.tzinfo is not None
    assert any("no timezone" in w for w in r.summary.warnings)


# ---- API ----
def test_api_demo_flow_and_report():
    c = TestClient(app)
    assert c.get("/api/health").json()["status"] == "ok"
    res = c.post("/api/analyze/demo")
    assert res.status_code == 200
    body = res.json()
    assert body["is_demo"] is True and body["summary"]["incidents_count"] >= 1
    rep = c.get(f"/api/analysis/{body['analysis_id']}/report")
    assert rep.status_code == 200
    report = rep.json()
    assert report["data_source"]["synthetic_demo_data"] is True
    assert len(report["findings"]) == body["summary"]["findings_count"]
    assert c.get("/api/analysis/doesnotexist").status_code == 404
    assert len(c.get("/api/rules").json()["rules"]) == 5


def test_api_rejects_bad_upload():
    c = TestClient(app)
    res = c.post("/api/analyze", files={"file": ("bad.csv", b"a,b\n1,2\n", "text/csv")})
    assert res.status_code == 422
    assert "Missing required column" in res.json()["detail"]["message"]
    res = c.post("/api/analyze", files={"file": ("empty.csv", b"", "text/csv")})
    assert res.status_code == 400
