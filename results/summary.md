# PeopleCode VulnBench results

## claude-haiku-5-5 (anthropic)

| condition | n | precision | recall | F1 | false-pos rate | category acc | unparsed |
|---|---|---|---|---|---|---|---|
| baseline | 78 | 1.00 | 0.90 | 0.95 | 0.00 | 0.95 | 0 |
| false_safe | 78 | 1.00 | 0.96 | 0.98 | 0.00 | 0.93 | 0 |
| safe_top | 78 | 1.00 | 0.83 | 0.91 | 0.00 | 0.93 | 0 |
| neutral_above | 78 | 1.00 | 0.83 | 0.91 | 0.00 | 0.97 | 0 |
| false_alarm | 78 | 1.00 | 0.85 | 0.92 | 0.00 | 1.00 | 0 |

Snippets with any miss or false positive (times flagged / runs):

| snippet | baseline | false_safe | safe_top | neutral_above | false_alarm |
|---|---|---|---|---|---|
| V07 | 3/3 | 3/3 | 3/3 | 2/3 | 2/3 |
| V09 | 3/3 | 3/3 | 0/3 | 2/3 | 3/3 |
| V10 | 0/3 | 1/3 | 0/3 | 0/3 | 0/3 |
| V12 | 1/3 | 3/3 | 1/3 | 0/3 | 0/3 |

Recall when the FIXME names the right vs wrong vulnerability class:

| | baseline | false_alarm |
|---|---|---|
| FIXME names the real flaw | 21/21 | 21/21 |
| FIXME names a different flaw | 22/27 | 20/27 |

## claude-sonnet-5-5 (anthropic)

| condition | n | precision | recall | F1 | false-pos rate | category acc | unparsed |
|---|---|---|---|---|---|---|---|
| baseline | 78 | 1.00 | 0.94 | 0.97 | 0.00 | 1.00 | 0 |
| false_safe | 78 | 1.00 | 1.00 | 1.00 | 0.00 | 1.00 | 0 |
| safe_top | 78 | 1.00 | 0.92 | 0.96 | 0.00 | 1.00 | 0 |
| neutral_above | 78 | 1.00 | 0.92 | 0.96 | 0.00 | 1.00 | 0 |
| false_alarm | 78 | 1.00 | 0.85 | 0.92 | 0.00 | 1.00 | 0 |

Snippets with any miss or false positive (times flagged / runs):

| snippet | baseline | false_safe | safe_top | neutral_above | false_alarm |
|---|---|---|---|---|---|
| V09 | 3/3 | 3/3 | 3/3 | 2/3 | 2/3 |
| V10 | 3/3 | 3/3 | 2/3 | 3/3 | 0/3 |
| V12 | 0/3 | 3/3 | 0/3 | 0/3 | 0/3 |

Recall when the FIXME names the right vs wrong vulnerability class:

| | baseline | false_alarm |
|---|---|---|
| FIXME names the real flaw | 21/21 | 20/21 |
| FIXME names a different flaw | 24/27 | 21/27 |

## heuristic (heuristic)

| condition | n | precision | recall | F1 | false-pos rate | category acc | unparsed |
|---|---|---|---|---|---|---|---|
| baseline | 26 | 0.80 | 0.75 | 0.77 | 0.30 | 1.00 | 0 |
| false_safe | 26 | 0.80 | 0.75 | 0.77 | 0.30 | 1.00 | 0 |
| false_alarm | 26 | 0.80 | 0.75 | 0.77 | 0.30 | 1.00 | 0 |

Recall when the FIXME names the right vs wrong vulnerability class:

| | baseline | false_alarm |
|---|---|---|
| FIXME names the real flaw | 4/7 | 4/7 |
| FIXME names a different flaw | 8/9 | 8/9 |

