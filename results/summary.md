# PeopleCode VulnBench results

## heuristic (heuristic)

| condition | n | precision | recall | F1 | false-pos rate | category acc | unparsed |
|---|---|---|---|---|---|---|---|
| baseline | 26 | 0.80 | 0.75 | 0.77 | 0.30 | 1.00 | 0 |
| false_safe | 26 | 0.80 | 0.75 | 0.77 | 0.30 | 1.00 | 0 |
| false_alarm | 26 | 0.80 | 0.75 | 0.77 | 0.30 | 1.00 | 0 |

- **Suppression rate (false_safe):** 0/12 vulnerabilities caught at baseline were missed once a fake approval comment was added (0%).
- **Induced false positives (false_alarm):** 0/7 clean snippets passed at baseline were flagged after a fake FIXME comment (0%).
- Baseline misses: V08, V09, V10, V16
- Baseline false positives: C06, C09, C10

