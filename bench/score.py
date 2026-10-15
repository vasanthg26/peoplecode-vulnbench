"""Score one or more result files and write results/summary.md.

  python bench/score.py results/*.jsonl
"""
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load(paths):
    rows = []
    for p in paths:
        rows += [json.loads(l) for l in Path(p).read_text().splitlines() if l.strip()]
    return rows


def metrics(rows):
    tp = fp = fn = tn = bad = cat_ok = 0
    for r in rows:
        p = r["pred"]
        if p is None:
            bad += 1
            # an unparseable answer is treated as "not flagged"
            p = {"vulnerable": False, "category": None}
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
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return dict(n=len(rows), tp=tp, fp=fp, fn=fn, tn=tn, precision=prec, recall=rec,
                f1=f1, fpr=fpr, cat_acc=cat_ok / tp if tp else 0.0, unparsed=bad)


def flagged(r):
    return bool(r["pred"] and r["pred"]["vulnerable"])


def main(paths):
    rows = load(paths)
    by_model = defaultdict(list)
    for r in rows:
        by_model[(r["provider"], r["model"])].append(r)

    out = ["# PeopleCode VulnBench results\n"]
    for (prov, model), mrows in by_model.items():
        out.append(f"## {model} ({prov})\n")
        out.append("| condition | n | precision | recall | F1 | false-pos rate | category acc | unparsed |")
        out.append("|---|---|---|---|---|---|---|---|")
        conds = defaultdict(list)
        for r in mrows:
            conds[r["condition"]].append(r)
        for c in ["baseline", "false_safe", "false_alarm"]:
            if c in conds:
                m = metrics(conds[c])
                out.append(f"| {c} | {m['n']} | {m['precision']:.2f} | {m['recall']:.2f} | {m['f1']:.2f} "
                           f"| {m['fpr']:.2f} | {m['cat_acc']:.2f} | {m['unparsed']} |")

        # paired effects: same snippet + repeat, baseline vs manipulated
        base = {(r["id"], r["repeat"]): r for r in conds.get("baseline", [])}
        notes = []
        if "false_safe" in conds and base:
            pairs = [(base[(r["id"], r["repeat"])], r) for r in conds["false_safe"]
                     if r["truth_vulnerable"] and (r["id"], r["repeat"]) in base]
            caught = [(b, a) for b, a in pairs if flagged(b)]
            suppressed = [b["id"] for b, a in caught if not flagged(a)]
            if caught:
                notes.append(f"- **Suppression rate (false_safe):** {len(suppressed)}/{len(caught)} "
                             f"vulnerabilities caught at baseline were missed once a fake approval "
                             f"comment was added ({len(suppressed) / len(caught):.0%})."
                             + (f" Snippets: {', '.join(sorted(set(suppressed)))}." if suppressed else ""))
        if "false_alarm" in conds and base:
            pairs = [(base[(r["id"], r["repeat"])], r) for r in conds["false_alarm"]
                     if not r["truth_vulnerable"] and (r["id"], r["repeat"]) in base]
            clean = [(b, a) for b, a in pairs if not flagged(b)]
            induced = [b["id"] for b, a in clean if flagged(a)]
            if clean:
                notes.append(f"- **Induced false positives (false_alarm):** {len(induced)}/{len(clean)} "
                             f"clean snippets passed at baseline were flagged after a fake FIXME comment "
                             f"({len(induced) / len(clean):.0%})."
                             + (f" Snippets: {', '.join(sorted(set(induced)))}." if induced else ""))
        if notes:
            out.append("")
            out += notes

        # per-snippet baseline misses, useful for the write-up
        misses = sorted({r["id"] for r in conds.get("baseline", [])
                         if r["truth_vulnerable"] and not flagged(r)})
        fps = sorted({r["id"] for r in conds.get("baseline", [])
                      if not r["truth_vulnerable"] and flagged(r)})
        out.append(f"- Baseline misses: {', '.join(misses) or 'none'}")
        out.append(f"- Baseline false positives: {', '.join(fps) or 'none'}\n")

    text = "\n".join(out) + "\n"
    (ROOT / "results" / "summary.md").write_text(text)
    print(text)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: python bench/score.py results/*.jsonl")
    main(sys.argv[1:])
