"""Deterministic, explainable detection rules (R001-R005).

Every finding's text is assembled from the values actually observed in the data.
Only `login` events are used for failure/success rules; other event types are kept
for context in the timeline.
"""
from collections import defaultdict
from datetime import datetime, timedelta

from . import scoring
from .config import CONFIG, DetectionConfig
from .schemas import Event, EvidenceItem, Finding, RuleInfo, ScoreFactor

RULE_NAMES = {
    "R001": "Repeated failed logins from one IP",
    "R002": "Repeated failed logins against one account",
    "R003": "Successful login after repeated failures",
    "R004": "Login at unusual hours",
    "R005": "One IP failing against many accounts",
}

CAVEATS = {
    "R001": "Could also be a misconfigured service, an expired shared credential, or a user behind a shared NAT mistyping passwords.",
    "R002": "Could also be a user who forgot their password or an application using a stale saved credential.",
    "R003": "Could also be a legitimate user who mistyped their password several times before getting it right.",
    "R004": "Could also be shift work, travel, on-call duty or a scheduled job; time of day alone does not prove compromise.",
    "R005": "Could also be several legitimate users sharing one NAT/proxy address during a password change or outage.",
}


# ---------- helpers ----------
def _fmt(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S UTC")


def _dur(a: datetime, b: datetime) -> str:
    secs = int((b - a).total_seconds())
    if secs < 60:
        return f"{secs} s"
    mins, s = divmod(secs, 60)
    if mins < 60:
        return f"{mins} min {s:02d} s"
    h, m = divmod(mins, 60)
    return f"{h} h {m:02d} min"


def _join(items, limit: int = 6) -> str:
    items = sorted(set(items))
    if len(items) > limit:
        return ", ".join(items[:limit]) + f" (+{len(items) - limit} more)"
    return ", ".join(items)


def _bursts(evs: list[Event], triggered, window: timedelta) -> list[list[Event]]:
    """Find bursts in time-sorted events.

    A burst starts at event i when the window [ts_i, ts_i + window] satisfies
    `triggered`; it then extends while each following event is within `window`
    of the previous one. Bursts do not overlap, so one attack yields one finding.
    """
    out, i, n = [], 0, len(evs)
    while i < n:
        j = i
        while j + 1 < n and evs[j + 1].timestamp - evs[i].timestamp <= window:
            j += 1
        if triggered(evs[i:j + 1]):
            k = j
            while k + 1 < n and evs[k + 1].timestamp - evs[k].timestamp <= window:
                k += 1
            out.append(evs[i:k + 1])
            i = k + 1
        else:
            i += 1
    return out


def _is_failed_login(e: Event) -> bool:
    return e.event_type == "login" and e.status == "failure"


def _is_success_login(e: Event) -> bool:
    return e.event_type == "login" and e.status == "success"


def _make(rule_id: str, evs: list[Event], units: int, threshold: int, title: str, explanation: str,
          evidence: list[tuple[str, str]], extra: list[ScoreFactor] | None = None) -> Finding:
    factors = scoring.finding_factors(rule_id, units, threshold, extra)
    score = scoring.total(factors)
    evs = sorted(evs, key=lambda e: (e.timestamp, e.id))
    return Finding(
        id="", rule_id=rule_id, rule_name=RULE_NAMES[rule_id], severity=scoring.severity_for(score),
        risk_score=score, title=title, explanation=explanation, caveat=CAVEATS[rule_id],
        usernames=sorted({e.username for e in evs}), source_ips=sorted({e.source_ip for e in evs}),
        first_seen=evs[0].timestamp, last_seen=evs[-1].timestamp, event_ids=[e.id for e in evs],
        evidence=[EvidenceItem(label=k, value=v) for k, v in evidence], score_factors=factors,
    )


# ---------- rules ----------
def _r001_ip_failures(events: list[Event], cfg: DetectionConfig) -> list[Finding]:
    by_ip: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if _is_failed_login(e):
            by_ip[e.source_ip].append(e)
    window = timedelta(minutes=cfg.ip_failure_window_min)
    out = []
    for ip in sorted(by_ip):
        for burst in _bursts(by_ip[ip], lambda w: len(w) >= cfg.ip_failure_threshold, window):
            n, a, b = len(burst), burst[0].timestamp, burst[-1].timestamp
            users = {e.username for e in burst}
            out.append(_make(
                "R001", burst, n, cfg.ip_failure_threshold,
                f"{n} failed logins from {ip} in {_dur(a, b)}",
                f"{ip} produced {n} failed login attempts between {_fmt(a)} and {_fmt(b)} "
                f"({_dur(a, b)}), targeting {len(users)} account(s): {_join(users)}. "
                f"The rule triggers at {cfg.ip_failure_threshold} or more failures within "
                f"{cfg.ip_failure_window_min} minutes.",
                [("Failed attempts", str(n)), ("Time span", _dur(a, b)), ("Accounts targeted", _join(users)),
                 ("Threshold", f">= {cfg.ip_failure_threshold} failures in {cfg.ip_failure_window_min} min")],
            ))
    return out


def _r002_user_failures(events: list[Event], cfg: DetectionConfig) -> list[Finding]:
    by_user: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if _is_failed_login(e):
            by_user[e.username].append(e)
    window = timedelta(minutes=cfg.user_failure_window_min)
    out = []
    for user in sorted(by_user):
        for burst in _bursts(by_user[user], lambda w: len(w) >= cfg.user_failure_threshold, window):
            n, a, b = len(burst), burst[0].timestamp, burst[-1].timestamp
            ips = {e.source_ip for e in burst}
            extra = []
            if len(ips) >= scoring.R002_DISTRIBUTED_MIN_IPS:
                extra.append(ScoreFactor(
                    factor="Distributed sources", points=scoring.R002_DISTRIBUTED_BONUS,
                    note=f"failures came from {len(ips)} distinct IPs"))
            out.append(_make(
                "R002", burst, n, cfg.user_failure_threshold,
                f"{n} failed logins against '{user}' from {len(ips)} IP(s)",
                f"Account '{user}' received {n} failed login attempts between {_fmt(a)} and {_fmt(b)} "
                f"({_dur(a, b)}) from {len(ips)} source IP(s): {_join(ips)}. "
                f"The rule triggers at {cfg.user_failure_threshold} or more failures within "
                f"{cfg.user_failure_window_min} minutes.",
                [("Failed attempts", str(n)), ("Time span", _dur(a, b)), ("Source IPs", _join(ips)),
                 ("Threshold", f">= {cfg.user_failure_threshold} failures in {cfg.user_failure_window_min} min")],
                extra,
            ))
    return out


def _r003_success_after_failures(events: list[Event], cfg: DetectionConfig) -> list[Finding]:
    by_user: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if _is_failed_login(e) or _is_success_login(e):
            by_user[e.username].append(e)
    window = timedelta(minutes=cfg.success_after_failures_window_min)
    out = []
    for user in sorted(by_user):
        recent: list[Event] = []
        for e in by_user[user]:
            if _is_failed_login(e):
                recent.append(e)
                continue
            fails = [f for f in recent if e.timestamp - f.timestamp <= window]
            recent = []  # any success resets the failure streak
            if len(fails) < cfg.success_after_failures_min:
                continue
            fail_ips = {f.source_ip for f in fails}
            same_ip = e.source_ip in fail_ips
            gap = _dur(fails[-1].timestamp, e.timestamp)
            extra = [ScoreFactor(
                factor="Success from a failing IP" if same_ip else "Success from a different IP",
                points=scoring.R003_SAME_IP_BONUS if same_ip else scoring.R003_OTHER_IP_BONUS,
                note=(f"{e.source_ip} was also among the failing sources" if same_ip
                      else f"{e.source_ip} was not among the failing sources"))]
            out.append(_make(
                "R003", fails + [e], len(fails), cfg.success_after_failures_min,
                f"Successful login for '{user}' after {len(fails)} failures",
                f"'{user}' logged in successfully from {e.source_ip} at {_fmt(e.timestamp)}, {gap} after the last of "
                f"{len(fails)} failed attempts (from {_join(fail_ips)}) within the preceding "
                f"{cfg.success_after_failures_window_min} minutes. "
                + ("The successful login came from an IP that had also been failing. " if same_ip else
                   "The successful login came from an IP that was not among the failing sources. ")
                + f"The rule triggers at {cfg.success_after_failures_min} or more failures before a success.",
                [("Failures before success", str(len(fails))), ("Failure sources", _join(fail_ips)),
                 ("Success source", e.source_ip), ("Same IP as failures", "Yes" if same_ip else "No"),
                 ("Last failure to success", gap),
                 ("Threshold", f">= {cfg.success_after_failures_min} failures in {cfg.success_after_failures_window_min} min")],
                extra,
            ))
    return out


def _unusual(hour: int, cfg: DetectionConfig) -> bool:
    s, e = cfg.unusual_hour_start, cfg.unusual_hour_end
    return s <= hour < e if s <= e else (hour >= s or hour < e)


def _r004_unusual_hours(events: list[Event], cfg: DetectionConfig) -> list[Finding]:
    normal_ips: dict[str, set[str]] = defaultdict(set)
    for e in events:
        if not _unusual(e.timestamp.hour, cfg):
            normal_ips[e.username].add(e.source_ip)
    groups: dict[tuple[str, str, str], list[Event]] = defaultdict(list)
    for e in events:
        if _is_success_login(e) and _unusual(e.timestamp.hour, cfg):
            groups[(e.username, e.source_ip, e.timestamp.strftime("%Y-%m-%d"))].append(e)
    window_txt = f"{cfg.unusual_hour_start:02d}:00-{cfg.unusual_hour_end:02d}:00 UTC"
    out = []
    for (user, ip, day) in sorted(groups):
        evs = groups[(user, ip, day)]
        n, a, b = len(evs), evs[0].timestamp, evs[-1].timestamp
        baseline = normal_ips[user]
        unfamiliar = bool(baseline) and ip not in baseline
        extra = []
        if unfamiliar:
            extra.append(ScoreFactor(
                factor="Unfamiliar source IP", points=scoring.R004_UNFAMILIAR_IP_BONUS,
                note=f"{ip} never appears for '{user}' outside unusual hours in this dataset"))
        familiarity = (f"{ip} does not appear for '{user}' outside unusual hours in this dataset. " if unfamiliar
                       else (f"{ip} also appears for '{user}' during normal hours. " if baseline
                             else f"There is no normal-hours baseline for '{user}' in this dataset. "))
        out.append(_make(
            "R004", evs, n, 1,
            f"Login by '{user}' at {a.strftime('%H:%M')} UTC from {ip}",
            f"'{user}' had {n} successful login(s) from {ip} between {a.strftime('%H:%M')} and "
            f"{b.strftime('%H:%M')} UTC on {day}, inside the configured unusual-hours window ({window_txt}). "
            f"{familiarity}This is an out-of-pattern indicator, not evidence of compromise.",
            [("Successful logins", str(n)), ("Time (UTC)", f"{a.strftime('%H:%M:%S')} - {b.strftime('%H:%M:%S')}"),
             ("Unusual window", window_txt), ("IP seen in normal hours", "No" if unfamiliar else ("Yes" if baseline else "No baseline"))],
            extra,
        ))
    return out


def _r005_multi_user(events: list[Event], cfg: DetectionConfig) -> list[Finding]:
    by_ip: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if _is_failed_login(e):
            by_ip[e.source_ip].append(e)
    window = timedelta(minutes=cfg.multi_user_window_min)
    out = []
    for ip in sorted(by_ip):
        trig = lambda w: len({e.username for e in w}) >= cfg.multi_user_threshold  # noqa: E731
        for burst in _bursts(by_ip[ip], trig, window):
            users = {e.username for e in burst}
            n, a, b = len(burst), burst[0].timestamp, burst[-1].timestamp
            out.append(_make(
                "R005", burst, len(users), cfg.multi_user_threshold,
                f"{ip} failed against {len(users)} different accounts",
                f"{ip} had failed logins against {len(users)} distinct accounts ({_join(users)}) between "
                f"{_fmt(a)} and {_fmt(b)} ({_dur(a, b)}), {n} failed attempts in total. "
                f"The rule triggers at {cfg.multi_user_threshold} or more distinct accounts within "
                f"{cfg.multi_user_window_min} minutes.",
                [("Distinct accounts", str(len(users))), ("Failed attempts", str(n)), ("Time span", _dur(a, b)),
                 ("Accounts", _join(users)),
                 ("Threshold", f">= {cfg.multi_user_threshold} accounts in {cfg.multi_user_window_min} min")],
            ))
    return out


def detect(events: list[Event], cfg: DetectionConfig = CONFIG) -> list[Finding]:
    """Run all rules over time-sorted events. Finding ids are assigned later."""
    findings: list[Finding] = []
    for rule in (_r001_ip_failures, _r002_user_failures, _r003_success_after_failures,
                 _r004_unusual_hours, _r005_multi_user):
        findings.extend(rule(events, cfg))
    return findings


def rule_catalog(cfg: DetectionConfig = CONFIG) -> list[RuleInfo]:
    s = scoring.RULE_BASE
    return [
        RuleInfo(id="R001", name=RULE_NAMES["R001"], base_score=s["R001"],
                 description="Many failed logins originating from the same source IP in a short time.",
                 logic=f"Group failed `login` events by source_ip. Fire when {cfg.ip_failure_threshold}+ failures fall within "
                       f"{cfg.ip_failure_window_min} minutes; a continuing burst is merged into one finding.",
                 parameters={"threshold": cfg.ip_failure_threshold, "window_minutes": cfg.ip_failure_window_min},
                 benign_causes=CAVEATS["R001"]),
        RuleInfo(id="R002", name=RULE_NAMES["R002"], base_score=s["R002"],
                 description="Many failed logins against the same username, from one or several IPs.",
                 logic=f"Group failed `login` events by username. Fire when {cfg.user_failure_threshold}+ failures fall within "
                       f"{cfg.user_failure_window_min} minutes. +{scoring.R002_DISTRIBUTED_BONUS} if {scoring.R002_DISTRIBUTED_MIN_IPS}+ distinct IPs.",
                 parameters={"threshold": cfg.user_failure_threshold, "window_minutes": cfg.user_failure_window_min},
                 benign_causes=CAVEATS["R002"]),
        RuleInfo(id="R003", name=RULE_NAMES["R003"], base_score=s["R003"],
                 description="A successful login for an account that just had repeated failed attempts.",
                 logic=f"For each username, count failed logins in the {cfg.success_after_failures_window_min} minutes before a "
                       f"successful login. Fire when there are {cfg.success_after_failures_min}+ failures. "
                       f"+{scoring.R003_SAME_IP_BONUS} if the success IP also failed, +{scoring.R003_OTHER_IP_BONUS} otherwise.",
                 parameters={"min_failures": cfg.success_after_failures_min, "window_minutes": cfg.success_after_failures_window_min},
                 benign_causes=CAVEATS["R003"]),
        RuleInfo(id="R004", name=RULE_NAMES["R004"], base_score=s["R004"],
                 description="Successful logins during hours configured as unusual for this organisation.",
                 logic=f"Flag successful `login` events whose UTC hour is in [{cfg.unusual_hour_start:02d}:00, "
                       f"{cfg.unusual_hour_end:02d}:00). One finding per username, IP and day. "
                       f"+{scoring.R004_UNFAMILIAR_IP_BONUS} if the IP is not seen for that user in normal hours.",
                 parameters={"start_hour_utc": cfg.unusual_hour_start, "end_hour_utc": cfg.unusual_hour_end},
                 benign_causes=CAVEATS["R004"]),
        RuleInfo(id="R005", name=RULE_NAMES["R005"], base_score=s["R005"],
                 description="A single source IP failing to log in as many different usernames (password-spraying pattern).",
                 logic=f"Group failed `login` events by source_ip. Fire when {cfg.multi_user_threshold}+ distinct usernames "
                       f"appear within {cfg.multi_user_window_min} minutes.",
                 parameters={"distinct_users": cfg.multi_user_threshold, "window_minutes": cfg.multi_user_window_min},
                 benign_causes=CAVEATS["R005"]),
    ]
