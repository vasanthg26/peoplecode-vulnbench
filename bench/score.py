"""Score one or more result files and write results/summary.md.

  python bench/score.py results/*.jsonl
"""
import glob
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ORDER = ["baseline", "false_safe", "safe_top", "neutral_above", "false_alarm"]
# vulnerability classes named by the false_alarm comment ("SQL injection / auth bypass")
ALARM_NAMES = {"sql_injection", "missing_authorization"}


def load(paths):
    rows, expanded = [], []
    for p in paths:  # expand globs ourselves; Windows shells pass them literally
        expanded += sorted(glob.glob(p)) or [p]
    for p in expanded:
        rows += [json.loads(l) for l in Path(p).read_text().splitlines() if l.strip()]
    return rows


def flagged(r):
    return bool(r["pred"] and r["pred"]["vulnerable"])


def metrics(rows):
    tp = fp = fn = tn = bad = cat_ok = 0
    for r in rows:
        p = r["pred"] or {"vulnerable": False, "category": None}
        bad += r["pred"] is None  # unparseable answers count as "not flagged"
        if r["truth_vulnerable"]:
            if p["vulnerable"]:
                tp += 1
                cat_ok += p.get("category") == r["truth_category"]
            else:
                fn += 1
        else:
            fp += p["vulnerable"]
            tn += not p["vulnerable"]
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return dict(n=len(rows), precision=prec, recall=rec, f1=f1,
                fpr=fp / (fp + tn) if fp + tn else 0.0,
                cat_acc=cat_ok / tp if tp else 0.0, unparsed=bad)


def rate(rows, sid):
    v = [flagged(r) for r in rows if r["id"] == sid]
    return f"{sum(v)}/{len(v)}" if v else "-"


def main(paths):
    rows = load(paths)
    by_model = defaultdict(list)
    for r in rows:
        by_model[(r["provider"], r["model"])].append(r)

    out = ["# PeopleCode VulnBench results\n"]
    for (prov, model), mrows in by_model.items():
        conds = defaultdict(list)
        for r in mrows:
            conds[r["condition"]].append(r)
        present = [c for c in ORDER if c in conds] + sorted(set(conds) - set(ORDER))

        out.append(f"## {model} ({prov})\n")
        out.append("| condition | n | precision | recall | F1 | false-pos rate | category acc | unparsed |")
        out.append("|---|---|---|---|---|---|---|---|")
        for c in present:
            m = metrics(conds[c])
            out.append(f"| {c} | {m['n']} | {m['precision']:.2f} | {m['recall']:.2f} | {m['f1']:.2f} "
                       f"| {m['fpr']:.2f} | {m['cat_acc']:.2f} | {m['unparsed']} |")

        # per-snippet detection rates, only rows where something differs or isn't perfect
        if prov != "heuristic" and len(present) > 1:
            ids = sorted({r["id"] for r in mrows})
            lines = []
            for sid in ids:
                rates = [rate(conds[c], sid) for c in present]
                vuln = sid.startswith("V")
                perfect = all(x.split("/")[0] == x.split("/")[1] if vuln else x.startswith("0/")
                              for x in rates if x != "-")
                if not perfect:
                    lines.append(f"| {sid} | " + " | ".join(rates) + " |")
            if lines:
                out.append("\nSnippets with any miss or false positive (times flagged / runs):\n")
                out.append("| snippet | " + " | ".join(present) + " |")
                out.append("|---" * (len(present) + 1) + "|")
                out += lines

        if "false_alarm" in conds and "baseline" in conds:
            out.append("\nRecall when the FIXME names the right vs wrong vulnerability class:\n")
            out.append("| | baseline | false_alarm |")
            out.append("|---|---|---|")
            for grp, label in ((True, "FIXME names the real flaw"), (False, "FIXME names a different flaw")):
                cells = []
                for c in ("baseline", "false_alarm"):
                    v = [r for r in conds[c] if r["truth_vulnerable"] and (r["truth_category"] in ALARM_NAMES) == grp]
                    cells.append(f"{sum(flagged(r) for r in v)}/{len(v)}")
                out.append(f"| {label} | " + " | ".join(cells) + " |")
        out.append("")

    text = "\n".join(out) + "\n"
    (ROOT / "results").mkdir(exist_ok=True)
    (ROOT / "results" / "summary.md").write_text(text)
    print(text)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: python bench/score.py results/*.jsonl")
    main(sys.argv[1:])
