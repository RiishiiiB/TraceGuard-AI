"""Deterministic SYNTHETIC authentication log used for demonstrations.

Contains a benign baseline plus four scripted scenarios. Attacker IPs use
RFC 5737 documentation ranges, so nothing here refers to real hosts.
"""
import csv
import io
import random
from datetime import datetime, timedelta, timezone

DAY = datetime(2025, 3, 10, tzinfo=timezone.utc)

BASELINE_USERS = {
    "alice": "10.10.1.21", "bob": "10.10.1.34", "carol": "10.10.1.47", "dave": "10.10.2.12",
    "erin": "10.10.2.28", "frank": "10.10.3.5", "grace": "10.10.3.19", "heidi": "10.10.4.8",
    "ivan": "10.10.4.22", "judy": "10.10.5.31", "karl": "10.10.5.40", "liam": "10.10.6.3",
    "mia": "10.10.6.18", "noah": "10.10.7.9", "admin": "10.10.0.5", "finance_lead": "10.10.6.14",
    "svc_backup": "10.10.0.50",
}


def _at(hour: int, minute: int = 0, second: int = 0) -> datetime:
    return DAY + timedelta(hours=hour, minutes=minute, seconds=second)


def generate_rows() -> list[tuple[datetime, str, str, str, str]]:
    rng = random.Random(2025)
    rows = []

    def add(ts, user, ip, etype, status):
        rows.append((ts, user, ip, etype, status))

    # 1) Benign baseline: working-hours sessions, occasional single/double typos, a few resets.
    for user, ip in BASELINE_USERS.items():
        for _ in range(rng.randint(2, 4)):
            start = _at(rng.randint(8, 17), rng.randint(0, 59), rng.randint(0, 59))
            if rng.random() < 0.2:
                for k in range(rng.randint(1, 2)):
                    add(start - timedelta(seconds=40 * (k + 1)), user, ip, "login", "failure")
            add(start, user, ip, "login", "success")
            add(start + timedelta(minutes=rng.randint(15, 120)), user, ip, "logout", "success")
    add(_at(9, 41, 12), "dave", BASELINE_USERS["dave"], "password_reset", "success")
    add(_at(15, 5, 3), "mia", BASELINE_USERS["mia"], "password_reset", "success")
    # near-miss: 3 failures then success (below the R003 threshold of 5)
    for k in range(3):
        add(_at(11, 52, 10 * k), "bob", BASELINE_USERS["bob"], "login", "failure")
    add(_at(11, 53, 30), "bob", BASELINE_USERS["bob"], "login", "success")

    # 2) Brute force on admin that ends in a successful login and a password reset.
    atk = "203.0.113.45"
    for k in range(18):
        add(_at(14, 2, 10) + timedelta(seconds=20 * k + rng.randint(0, 6)), "admin", atk, "login", "failure")
    add(_at(14, 9, 5), "admin", atk, "login", "success")
    add(_at(14, 12, 30), "admin", atk, "password_reset", "success")

    # 3) Password spraying: one IP, many accounts, 1-2 attempts each, no success.
    spray_ip = "198.51.100.77"
    targets = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "judy"]
    t = _at(10, 30, 0)
    for user in targets:
        add(t, user, spray_ip, "login", "failure")
        t += timedelta(seconds=rng.randint(35, 70))
    for user in targets[:4]:
        add(t, user, spray_ip, "login", "failure")
        t += timedelta(seconds=rng.randint(30, 60))

    # 4) Off-hours login by finance_lead from an IP never seen in working hours.
    add(_at(2, 47, 12), "finance_lead", "192.0.2.88", "login", "success")
    add(_at(3, 5, 41), "finance_lead", "192.0.2.88", "logout", "success")

    # 5) Distributed attempts against svc_backup: 6 failures from three different IPs.
    for k, ip in enumerate(["203.0.113.10", "203.0.113.11", "203.0.113.12"] * 2):
        add(_at(16, 20, 0) + timedelta(seconds=70 * k + rng.randint(0, 10)), "svc_backup", ip, "login", "failure")

    rows.sort(key=lambda r: (r[0], r[1]))
    return rows


def demo_csv() -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["timestamp", "username", "source_ip", "event_type", "status"])
    for ts, user, ip, etype, status in generate_rows():
        w.writerow([ts.strftime("%Y-%m-%dT%H:%M:%SZ"), user, ip, etype, status])
    return buf.getvalue()


if __name__ == "__main__":  # python -m app.sample_data > sample.csv
    print(demo_csv(), end="")
