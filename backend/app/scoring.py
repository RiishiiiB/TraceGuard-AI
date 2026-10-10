"""Transparent 0-100 heuristic risk scoring.

This is a hand-tuned heuristic, NOT a calibrated probability of compromise.

Finding score  = rule base score + volume bonus + rule-specific modifiers, capped at 100.
Incident score = highest finding score
                 + corroboration (+5 per additional distinct rule, cap +15)
                 + event volume  (+1 per 10 UNIQUE flagged events, cap +10)
                 + accounts      (+1 per additional affected account, cap +10)
                 capped at 100.

Incident factors count unique event ids, so one event matched by several rules
is never counted twice. Severity bands: 0-29 LOW, 30-54 MEDIUM, 55-79 HIGH, 80-100 CRITICAL.
"""
from .schemas import ScoreFactor

RULE_BASE = {"R001": 25, "R002": 25, "R003": 35, "R004": 15, "R005": 30}

VOLUME_STEP = 2
VOLUME_CAP = 20
R002_DISTRIBUTED_BONUS = 10
R002_DISTRIBUTED_MIN_IPS = 3
R003_SAME_IP_BONUS = 15
R003_OTHER_IP_BONUS = 5
R004_UNFAMILIAR_IP_BONUS = 10

CORROBORATION_STEP, CORROBORATION_CAP = 5, 15
EVENT_VOLUME_PER, EVENT_VOLUME_CAP = 10, 10
ACCOUNT_STEP, ACCOUNT_CAP = 1, 10

SEVERITY_BANDS = [(80, "CRITICAL"), (55, "HIGH"), (30, "MEDIUM"), (0, "LOW")]

SCORING_MODEL = {
    "disclaimer": "The score is a transparent heuristic for prioritising investigation. "
    "It is not a calibrated probability that an account or host is compromised.",
    "scale": "0-100, capped",
    "severity_bands": [{"min_score": m, "severity": s} for m, s in SEVERITY_BANDS],
    "finding_factors": [
        {"factor": "Rule base score", "detail": ", ".join(f"{k}={v}" for k, v in RULE_BASE.items())},
        {"factor": "Volume bonus", "detail": f"+{VOLUME_STEP} per unit above the rule threshold, cap +{VOLUME_CAP}"},
        {"factor": "R002 distributed sources", "detail": f"+{R002_DISTRIBUTED_BONUS} when failures come from {R002_DISTRIBUTED_MIN_IPS}+ distinct IPs"},
        {"factor": "R003 same source IP", "detail": f"+{R003_SAME_IP_BONUS} if the success came from an IP that also failed, +{R003_OTHER_IP_BONUS} otherwise"},
        {"factor": "R004 unfamiliar IP", "detail": f"+{R004_UNFAMILIAR_IP_BONUS} if the IP never appears for that user outside unusual hours"},
    ],
    "incident_factors": [
        {"factor": "Highest finding score", "detail": "starting point for the incident"},
        {"factor": "Corroboration", "detail": f"+{CORROBORATION_STEP} per additional distinct rule, cap +{CORROBORATION_CAP}"},
        {"factor": "Event volume", "detail": f"+1 per {EVENT_VOLUME_PER} unique flagged events, cap +{EVENT_VOLUME_CAP}"},
        {"factor": "Accounts affected", "detail": f"+{ACCOUNT_STEP} per additional account, cap +{ACCOUNT_CAP}"},
    ],
}


def clamp_score(value: int) -> int:
    return max(0, min(100, int(value)))


def severity_for(score: int) -> str:
    for minimum, label in SEVERITY_BANDS:
        if score >= minimum:
            return label
    return "LOW"


def finding_factors(rule_id: str, units: int, threshold: int, extra: list[ScoreFactor] | None = None) -> list[ScoreFactor]:
    factors = [ScoreFactor(factor="Rule base score", points=RULE_BASE[rule_id], note=f"{rule_id} base severity")]
    over = max(0, units - threshold)
    bonus = min(VOLUME_CAP, VOLUME_STEP * over)
    if bonus:
        factors.append(ScoreFactor(
            factor="Volume above threshold", points=bonus,
            note=f"{over} above threshold of {threshold} x {VOLUME_STEP}, capped at {VOLUME_CAP}",
        ))
    factors.extend(extra or [])
    return factors


def total(factors: list[ScoreFactor]) -> int:
    return clamp_score(sum(f.points for f in factors))


def score_incident(top_finding_id: str, top_score: int, distinct_rules: int,
                   unique_events: int, accounts: int) -> list[ScoreFactor]:
    factors = [ScoreFactor(factor="Highest finding score", points=top_score, note=f"from {top_finding_id}")]
    corroboration = min(CORROBORATION_CAP, CORROBORATION_STEP * max(0, distinct_rules - 1))
    if corroboration:
        factors.append(ScoreFactor(
            factor="Corroborating rules", points=corroboration,
            note=f"{distinct_rules} distinct rules fired on related activity",
        ))
    volume = min(EVENT_VOLUME_CAP, unique_events // EVENT_VOLUME_PER)
    if volume:
        factors.append(ScoreFactor(
            factor="Event volume", points=volume,
            note=f"{unique_events} unique flagged events (each event counted once)",
        ))
    extra_accounts = max(0, accounts - 1)
    account_pts = min(ACCOUNT_CAP, ACCOUNT_STEP * extra_accounts)
    if account_pts:
        factors.append(ScoreFactor(
            factor="Accounts affected", points=account_pts,
            note=f"{accounts} accounts involved",
        ))
    return factors
