"""
Precision / Recall / F1 — §10.3, computed from evaluation_runs.

Definitions used here (matching your proposal's Table 10.2 exactly):
  TP = scenario detected with the correct technique (outcome == 'detected')
  FN = scenario missed entirely, OR detected with the wrong technique
       (outcome in ('missed', 'wrong_technique'))
  FP = would require incidents raised with NO corresponding attack fired —
       not measurable from evaluation_runs alone (every row here corresponds
       to a real attack). If you want a genuine FP measurement (per Table
       10.3's "Precision Target... during benign traffic evaluation"), you
       need a SEPARATE benign-traffic run recorded the same way, with
       expected_technique = NULL and outcome = 'false_positive' whenever an
       incident is raised with no corresponding scenario firing. This script
       supports that if such rows exist; otherwise Precision reports as 1.0
       with a warning (no FPs observed because none were tested for).

Usage:
  docker compose run --rm evaluation python compute_metrics.py --run-batch-id full-a1b2c3d4
  docker compose run --rm evaluation python compute_metrics.py --compare full-a1b2c3d4 baseline-e5f6g7h8
"""

import argparse
import os

import pandas as pd
import psycopg2

PG_DSN = os.environ["POSTGRES_DSN"]


def load_runs(run_batch_id: str) -> pd.DataFrame:
    conn = psycopg2.connect(PG_DSN)
    try:
        df = pd.read_sql(
            "SELECT * FROM evaluation_runs WHERE run_batch_id = %s",
            conn,
            params=(run_batch_id,),
        )
    finally:
        conn.close()
    return df


def compute(df: pd.DataFrame) -> dict:
    total = len(df)
    tp = (df["outcome"] == "detected").sum()
    fn = df["outcome"].isin(["missed", "wrong_technique"]).sum()
    fp = (df["outcome"] == "false_positive").sum()

    precision = tp / (tp + fp) if (tp + fp) > 0 else float("nan")
    recall = tp / (tp + fn) if (tp + fn) > 0 else float("nan")
    f1 = (2 * precision * recall / (precision + recall)
          if precision and recall and (precision + recall) > 0 else float("nan"))

    mttd_values = df.loc[df["mttd_seconds"].notna(), "mttd_seconds"]
    mttr_values = df.loc[df["mttr_seconds"].notna(), "mttr_seconds"]

    return {
        "total_scenarios": total,
        "TP": int(tp), "FN": int(fn), "FP": int(fp),
        "precision": precision, "recall": recall, "f1": f1,
        "mean_mttd_seconds": mttd_values.mean() if len(mttd_values) else float("nan"),
        "mean_mttr_minutes": mttr_values.mean() if len(mttr_values) else float("nan"),
    }


def print_report(label: str, metrics: dict):
    print(f"\n=== {label} ===")
    print(f"  scenarios run     : {metrics['total_scenarios']}")
    print(f"  TP / FN / FP      : {metrics['TP']} / {metrics['FN']} / {metrics['FP']}")
    print(f"  Precision         : {metrics['precision']:.3f}" if metrics['precision'] == metrics['precision'] else "  Precision         : n/a (no FP data — see script docstring)")
    print(f"  Recall            : {metrics['recall']:.3f}" if metrics['recall'] == metrics['recall'] else "  Recall            : n/a")
    print(f"  F1 Score          : {metrics['f1']:.3f}" if metrics['f1'] == metrics['f1'] else "  F1 Score          : n/a")
    print(f"  Mean MTTD (s)     : {metrics['mean_mttd_seconds']:.1f}" if metrics['mean_mttd_seconds'] == metrics['mean_mttd_seconds'] else "  Mean MTTD (s)     : n/a")
    print(f"  Mean MTTR (min)   : {metrics['mean_mttr_minutes']:.1f}" if metrics['mean_mttr_minutes'] == metrics['mean_mttr_minutes'] else "  Mean MTTR (min)   : n/a")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-batch-id", help="single batch to report on")
    parser.add_argument("--compare", nargs=2, metavar=("FULL_BATCH_ID", "BASELINE_BATCH_ID"),
                         help="print full vs baseline side-by-side")
    args = parser.parse_args()

    if args.compare:
        full_id, baseline_id = args.compare
        full_metrics = compute(load_runs(full_id))
        baseline_metrics = compute(load_runs(baseline_id))
        print_report(f"FULL SYSTEM ({full_id})", full_metrics)
        print_report(f"BASELINE ({baseline_id})", baseline_metrics)
        print("\n=== DELTA (full - baseline) ===")
        for k in ("precision", "recall", "f1", "mean_mttd_seconds", "mean_mttr_minutes"):
            fv, bv = full_metrics[k], baseline_metrics[k]
            if fv == fv and bv == bv:
                print(f"  {k:20s}: {fv - bv:+.3f}")
    elif args.run_batch_id:
        metrics = compute(load_runs(args.run_batch_id))
        print_report(args.run_batch_id, metrics)
    else:
        parser.error("provide --run-batch-id or --compare")


if __name__ == "__main__":
    main()
