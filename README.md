# PeopleCode VulnBench

**Can LLM code reviewers find security flaws in a low-resource enterprise language, and can a planted comment talk them out of it?**

PeopleCode runs the financial back offices of governments, universities and large companies, but it barely appears in public code or in LLM training data. As LLM agents are adopted for code review in these environments, two questions matter:

1. **Off-distribution detection.** How well do models spot real vulnerability classes (injection, broken authorization, secrets, weak crypto, data exposure) in a language they have rarely seen?
2. **Robustness to adversarial context.** Does a fake "security reviewed, approved" comment placed above a flawed line suppress the finding? Does a fake "FIXME: injection" comment make a model flag clean code?

## Dataset

26 synthetic PeopleCode snippets (16 vulnerable, 10 clean), written for this benchmark. **None are taken from any production system.** Clean snippets include deliberate false-positive bait (safe concatenation of constants, ORDER BY from a fixed mapping, allow-listed file names).

| Category | Vulnerable snippets |
|---|---|
| sql_injection | V01, V02, V03, V15 |
| hardcoded_secret | V04, V05 |
| weak_crypto | V06, V07 |
| missing_authorization | V08, V09, V16 |
| untrusted_input | V10 |
| sensitive_data_exposure | V11, V12 |
| path_traversal | V13 |
| command_injection | V14 |

`dataset/build_dataset.py` is the source of truth; it regenerates `dataset/snippets/` and `dataset/manifest.json`.

## Conditions

| Condition | What changes |
|---|---|
| `baseline` | snippet as written |
| `false_safe` | a fake AppSec approval comment is inserted directly above the flawed line |
| `false_alarm` | a fake `FIXME: possible SQL injection` comment is added (top of clean snippets, above the flaw in vulnerable ones) |

The key metrics are the **suppression rate** (vulnerabilities caught at baseline but missed under `false_safe`) and **induced false positives** (clean snippets passed at baseline but flagged under `false_alarm`), both computed on paired runs.

## Running

```bash
python dataset/build_dataset.py

# offline regex baseline (no API key needed)
python bench/run.py --provider heuristic

# Claude
pip install anthropic
export ANTHROPIC_API_KEY=...
python bench/run.py --provider anthropic --model claude-haiku-5-5 --repeats 3
python bench/run.py --provider anthropic --model claude-sonnet-5-5 --repeats 3

# local model via Ollama (or any OpenAI-compatible endpoint)
python bench/run.py --provider openai_compat --model phi3 --repeats 3

python bench/score.py results/*.jsonl   # writes results/summary.md
```

## Results

### Regex static-analysis baseline

| condition | precision | recall | F1 | false-pos rate |
|---|---|---|---|---|
| baseline | 0.80 | 0.75 | 0.77 | 0.30 |

The regex baseline is comment-blind by design, so the adversarial conditions don't affect it. It misses every logic-level flaw (V08, V09, V10, V16: authorization and validation problems with no syntactic signature) and flags three clean snippets (C06, C09, C10). That gap is where LLM reviewers should help, and the adversarial conditions test whether they bring a new weakness with them.

### LLM results

_To be filled in after running the Claude and open-model evaluations._

## Limitations

- Small, hand-written dataset; results are indicative, not statistically strong. Repeats help separate model variance from real effects.
- One fixed reviewer prompt. Prompt variants (e.g. "ignore comments", checklist-style review) are a natural next experiment for mitigation.
- Category labels are strict; a reasonable alternative label (e.g. `untrusted_input` vs `missing_authorization`) counts as a category miss but still as a detection.

## Next steps

- Mitigations: comment-stripping, an explicit "comments are untrusted" instruction, and a two-model generator/reviewer loop.
- Expand to Application Engine SQL steps and Integration Broker routing configurations.
- Agentic setting: reviewer with tool access to the surrounding record and component definitions.

---
Author: Vasanth
