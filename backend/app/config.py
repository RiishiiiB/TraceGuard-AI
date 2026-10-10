"""Central, tweakable detection configuration.

All thresholds / windows used by the rules and the correlator live here so they
can be explained in one place (and overridden in tests).
"""
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class DetectionConfig:
    # R001 - repeated failed logins from one source IP
    ip_failure_threshold: int = 5
    ip_failure_window_min: int = 10
    # R002 - repeated failed logins against one username
    user_failure_threshold: int = 5
    user_failure_window_min: int = 10
    # R003 - successful login after repeated failures (same username)
    success_after_failures_min: int = 5
    success_after_failures_window_min: int = 15
    # R004 - unusual hours (UTC). Start inclusive, end exclusive. Wraps midnight if start > end.
    unusual_hour_start: int = 0
    unusual_hour_end: int = 6
    # R005 - one source IP failing against many usernames
    multi_user_threshold: int = 4
    multi_user_window_min: int = 15
    # Incident correlation: findings are linked if they share an IP or username
    # and their time ranges are no more than this many minutes apart.
    incident_gap_min: int = 30
    # Upload limits
    max_upload_bytes: int = 5 * 1024 * 1024
    max_rows: int = 20_000

    def as_dict(self) -> dict:
        return asdict(self)


CONFIG = DetectionConfig()
