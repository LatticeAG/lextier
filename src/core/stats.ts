/**
 * Reviewer statistics arithmetic (spec §13.1). Descriptive thresholds only —
 * output never feeds back into enforcement.
 */

export interface DecisionPoint {
  reviewer: string;
  received_ms: number;
  seq: number;          // audit sequence of the DECISION_RECORDED event
  approved: boolean;    // approve or release
  latency_ms: number;   // received_ms - first_view_ms
}

export interface ReviewerStats {
  reviewer: string;
  decisions: number;
  approved: number;
  rejected: number;
  approval_bps: number | null;
  median_latency_ms: number | null;
  subsecond_bps: number | null;
  prior_approval_bps: number | null;
  prior_median_latency_ms: number | null;
  flag: "INSUFFICIENT_DATA" | "NONE" | "HIGH_APPROVAL_FAST" | "RISING_APPROVAL_FALLING_LATENCY";
}

export interface StatsInput {
  from_ms: number;
  to_ms: number;
  /** Committed accepted decisions (any seq source), all reviewers. */
  decisions: DecisionPoint[];
  /** Current policy roster (for union with interval-observed reviewers). */
  roster: string[];
}

function lowerMedian(sorted: number[]): number {
  return sorted[Math.floor((sorted.length - 1) / 2)]!;
}

function windowStats(w: DecisionPoint[]): {
  decisions: number; approved: number; rejected: number;
  approval_bps: number | null; median_latency_ms: number | null; subsecond_bps: number | null;
} {
  const n = w.length;
  if (n === 0) {
    return { decisions: 0, approved: 0, rejected: 0, approval_bps: null, median_latency_ms: null, subsecond_bps: null };
  }
  const approved = w.filter((d) => d.approved).length;
  const lat = w.map((d) => d.latency_ms).sort((a, b) => a - b);
  const sub = w.filter((d) => d.latency_ms < 1000).length;
  return {
    decisions: n,
    approved,
    rejected: n - approved,
    approval_bps: Math.floor((10000 * approved) / n),
    median_latency_ms: lowerMedian(lat),
    subsecond_bps: Math.floor((10000 * sub) / n),
  };
}

export function computeReviewerStats(input: StatsInput): ReviewerStats[] {
  const inInterval = input.decisions.filter(
    (d) => d.received_ms >= input.from_ms && d.received_ms < input.to_ms,
  );
  const observed = new Set(inInterval.map((d) => d.reviewer));
  const union = new Set([...input.roster, ...observed]);
  const reviewers = [...union].sort();

  const out: ReviewerStats[] = [];
  for (const reviewer of reviewers) {
    const mine = inInterval
      .filter((d) => d.reviewer === reviewer)
      .sort((a, b) => a.received_ms - b.received_ms || a.seq - b.seq);
    const newest40 = mine.slice(-40);
    const current = newest40.slice(-20);
    const prior = newest40.slice(0, Math.max(0, newest40.length - 20)).slice(-20);

    const cur = windowStats(current);
    const hasPrior = prior.length === 20;
    const pri = hasPrior ? windowStats(prior) : null;

    let flag: ReviewerStats["flag"];
    if (cur.decisions < 20) {
      flag = "INSUFFICIENT_DATA";
    } else if (cur.approval_bps! >= 9500 && cur.median_latency_ms! < 1000) {
      flag = "HIGH_APPROVAL_FAST";
    } else if (
      pri !== null &&
      cur.approval_bps! - pri.approval_bps! >= 1000 &&
      2 * cur.median_latency_ms! <= pri.median_latency_ms!
    ) {
      flag = "RISING_APPROVAL_FALLING_LATENCY";
    } else {
      flag = "NONE";
    }

    out.push({
      reviewer,
      decisions: cur.decisions,
      approved: cur.approved,
      rejected: cur.rejected,
      approval_bps: cur.approval_bps,
      median_latency_ms: cur.median_latency_ms,
      subsecond_bps: cur.subsecond_bps,
      prior_approval_bps: pri ? pri.approval_bps : null,
      prior_median_latency_ms: pri ? pri.median_latency_ms : null,
      flag,
    });
  }
  return out;
}
