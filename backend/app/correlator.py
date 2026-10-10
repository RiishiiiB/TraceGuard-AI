"""Incident correlation (simple, documented heuristic).

Two findings are linked when BOTH hold:
  1. they share at least one source IP OR at least one username, and
  2. their [first_seen, last_seen] intervals overlap or are <= incident_gap_min apart.
Links are transitive (union-find). Each connected group becomes one incident.
"""
from datetime import timedelta

from . import scoring
from .config import CONFIG, DetectionConfig
from .detector import _fmt
from .schemas import Event, Finding, Incident

_STEPS = {
    "R001": "Check firewall / VPN / server logs for the offending IP(s) and consider blocking or rate-limiting them.",
    "R002": "Confirm with the account owner whether the failed attempts were expected; consider a temporary lockout or MFA enforcement.",
    "R003": "Treat the account as potentially compromised until verified: confirm the login with its owner, reset the credential and review session and activity logs after the success.",
    "R004": "Ask the account owner whether the off-hours login was expected (shift, travel, on-call) and compare with their usual source IPs.",
    "R005": "Review every targeted account for later successful logins, enforce MFA, and check whether the source IP appears elsewhere in your logs.",
}
_FINAL_STEP = "Preserve the relevant log lines (see the evidence timeline) and record the outcome of the investigation."


def _gap_ok(a: Finding, b: Finding, gap: timedelta) -> bool:
    return max(a.first_seen, b.first_seen) - min(a.last_seen, b.last_seen) <= gap


def _linked(a: Finding, b: Finding, gap: timedelta) -> bool:
    return bool((set(a.source_ips) & set(b.source_ips)) or (set(a.usernames) & set(b.usernames))) and _gap_ok(a, b, gap)


def _interpretation(rules: set[str]) -> str:
    if "R003" in rules and rules & {"R001", "R002"}:
        return ("This sequence is consistent with a password-guessing attempt that may have succeeded; "
                "the account should be treated as potentially compromised until verified.")
    if "R005" in rules:
        return "This pattern is consistent with password spraying across several accounts; no proof of compromise is implied."
    if rules & {"R001", "R002"}:
        return "This pattern is consistent with automated password guessing; no successful login was linked to it in this window."
    if "R003" in rules:
        return "A login succeeded after repeated failures; this may be a legitimate user or a successful guess."
    return "This is an out-of-pattern activity indicator that may well be benign."


def _basis(findings: list[Finding]) -> list[str]:
    if len(findings) == 1:
        return ["Single finding; no other related findings within the correlation window."]
    ips: dict[str, int] = {}
    users: dict[str, int] = {}
    for f in findings:
        for ip in f.source_ips:
            ips[ip] = ips.get(ip, 0) + 1
        for u in f.usernames:
            users[u] = users.get(u, 0) + 1
    basis = [f"Shared source IP {ip} (in {n} findings)" for ip, n in sorted(ips.items()) if n > 1]
    basis += [f"Shared account '{u}' (in {n} findings)" for u, n in sorted(users.items()) if n > 1]
    return basis


def correlate(findings: list[Finding], events_by_id: dict[str, Event],
              cfg: DetectionConfig = CONFIG) -> list[Incident]:
    """Group findings into incidents. Findings must already have ids."""
    gap = timedelta(minutes=cfg.incident_gap_min)
    parent = list(range(len(findings)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i in range(len(findings)):
        for j in range(i + 1, len(findings)):
            if _linked(findings[i], findings[j], gap):
                parent[find(j)] = find(i)

    groups: dict[int, list[Finding]] = {}
    for i, f in enumerate(findings):
        groups.setdefault(find(i), []).append(f)

    ordered = sorted(groups.values(), key=lambda g: (min(f.first_seen for f in g), g[0].id))
    incidents = []
    for n, group in enumerate(ordered, start=1):
        inc_id = f"INC-{n:03d}"
        group = sorted(group, key=lambda f: (f.first_seen, f.id))
        event_ids = sorted({eid for f in group for eid in f.event_ids})  # unique: no double counting
        flagged = set(event_ids)
        users = sorted({u for f in group for u in f.usernames})
        ips = sorted({ip for f in group for ip in f.source_ips})
        start = min(f.first_seen for f in group) - gap
        end = max(f.last_seen for f in group) + gap
        # Unflagged "context" events (e.g. a password reset right after a success) help the analyst;
        # they appear in the timeline but are not counted in event_count or the score.
        context = [e for e in events_by_id.values()
                   if e.id not in flagged and start <= e.timestamp <= end
                   and (e.source_ip in ips or e.username in users)]
        timeline = sorted([events_by_id[i] for i in event_ids] + context, key=lambda e: (e.timestamp, e.id))
        rules = sorted({f.rule_id for f in group})
        top = max(group, key=lambda f: (f.risk_score, f.id))
        factors = scoring.score_incident(top.id, top.risk_score, len(rules), len(event_ids), len(users))
        score = scoring.total(factors)
        summary = (
            f"{len(group)} finding(s) from {len(rules)} rule(s) ({', '.join(rules)}) involve {len(users)} account(s) "
            f"and {len(ips)} source IP(s) between {_fmt(min(f.first_seen for f in group))} and "
            f"{_fmt(max(f.last_seen for f in group))}, covering {len(event_ids)} unique event(s). "
            + "Observed: " + "; ".join(f"{f.title} [{f.rule_id}]" for f in group) + ". "
            + _interpretation(set(rules))
        )
        steps = [_STEPS[r] for r in rules] + [_FINAL_STEP]
        for f in group:
            f.incident_id = inc_id
        incidents.append(Incident(
            id=inc_id, severity=scoring.severity_for(score), risk_score=score,
            first_seen=min(f.first_seen for f in group), last_seen=max(f.last_seen for f in group),
            usernames=users, source_ips=ips, rule_ids=rules, finding_ids=[f.id for f in group],
            event_count=len(event_ids), finding_count=len(group), summary=summary,
            correlation_basis=_basis(group), score_factors=factors, suggested_steps=steps, timeline=timeline,
        ))
    return incidents

