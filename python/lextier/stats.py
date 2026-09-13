"""Reviewer statistics arithmetic (spec §13.1) — parity with
src/core/stats.ts. Descriptive thresholds only; output never feeds back into
enforcement."""


def _lower_median(srt):
    return srt[(len(srt) - 1) // 2]


def _window_stats(w):
    n = len(w)
    if n == 0:
        return {"decisions": 0, "approved": 0, "rejected": 0,
                "approval_bps": None, "median_latency_ms": None, "subsecond_bps": None}
    approved = sum(1 for d in w if d["approved"])
    lat = sorted(d["latency_ms"] for d in w)
    sub = sum(1 for d in w if d["latency_ms"] < 1000)
    return {
        "decisions": n,
        "approved": approved,
        "rejected": n - approved,
        "approval_bps": (10000 * approved) // n,
        "median_latency_ms": _lower_median(lat),
        "subsecond_bps": (10000 * sub) // n,
    }


def compute_reviewer_stats(from_ms: int, to_ms: int, decisions, roster):
    """decisions: [{reviewer, received_ms, seq, approved, latency_ms}];
    roster: current policy reviewers. Returns one record per reviewer in the
    roster ∪ interval-observed union, sorted ascending by PrincipalId."""
    in_interval = [d for d in decisions if from_ms <= d["received_ms"] < to_ms]
    observed = {d["reviewer"] for d in in_interval}
    reviewers = sorted(set(roster) | observed)

    out = []
    for reviewer in reviewers:
        mine = sorted((d for d in in_interval if d["reviewer"] == reviewer),
                      key=lambda d: (d["received_ms"], d["seq"]))
        newest40 = mine[-40:]
        current = newest40[-20:]
        prior = newest40[:max(0, len(newest40) - 20)][-20:]

        cur = _window_stats(current)
        pri = _window_stats(prior) if len(prior) == 20 else None

        if cur["decisions"] < 20:
            flag = "INSUFFICIENT_DATA"
        elif cur["approval_bps"] >= 9500 and cur["median_latency_ms"] < 1000:
            flag = "HIGH_APPROVAL_FAST"
        elif (pri is not None
              and cur["approval_bps"] - pri["approval_bps"] >= 1000
              and 2 * cur["median_latency_ms"] <= pri["median_latency_ms"]):
            flag = "RISING_APPROVAL_FALLING_LATENCY"
        else:
            flag = "NONE"

        out.append({
            "reviewer": reviewer,
            "decisions": cur["decisions"],
            "approved": cur["approved"],
            "rejected": cur["rejected"],
            "approval_bps": cur["approval_bps"],
            "median_latency_ms": cur["median_latency_ms"],
            "subsecond_bps": cur["subsecond_bps"],
            "prior_approval_bps": pri["approval_bps"] if pri else None,
            "prior_median_latency_ms": pri["median_latency_ms"] if pri else None,
            "flag": flag,
        })
    return out
