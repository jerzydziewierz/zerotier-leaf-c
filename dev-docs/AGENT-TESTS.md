# Agent tests

Checks that an agent does by procedure, because no build step or prover does them. Each has a stable ID (`AT-n`), says when to do it, how, and what counts as a pass. Report the result with the numbers; a finding is corrected in the document, or in the code if the document is right, or it goes to Grey as a numbered question.

## AT-1. Documents of `zerotier-leaf-c` agree with each other and with the code

When: before each push of `zerotier-leaf-c` that changes a `.md` file, `src/`, `include/`, `proofs/run.sh` or a result that the documents cite; at handover; when Grey asks.

Scope: every tracked `.md` file of the repository (`git ls-files '*.md'`): today `README.md`, `README-MORE.md`, `CHECKLIST.md`, `reports/PROOFS.md`, `reports/PROTOCOL.md`.

Truth sources, in this order: the code (`src/`, `include/ztl/`, `zephyr/`, `tools/`, `tests/`); the runner (`proofs/run.sh`: steps, default list, list of deliberate errors); the result files of the last full run on that code (`proofs/out-*.txt`). A figure that has no truth source of this kind (board measurements, long CBMC runs on another host) must name its run in the text.

Steps:

1. Make sure that the result files belong to the code: `git status` clean in `src/`, `include/`, `proofs/`, and the default run (`proofs/on-remote.sh start`, then `wait`) ended with exit status 0 after the last change there. ⚠️ `wait` of another run (for example `mutate` on a second host) writes its own `proofs/out-run.txt`; the per-step files stay.
2. Mechanical part: `python3 scripts/leaf_docs_check.py` (workspace root; no prover). It checks that every YAML block parses, that links and heading anchors resolve, that paths in backticks exist, that every cited entry ID is defined, and that the figures of the last run and of the runner (goal totals and goals per unit, smoke tests, vector and protocol checks, code sizes, deliberate errors and tool runs) are in the text; and that every deliberate error in `proofs/run.sh` still changes its source file (a pattern that no longer matches is an error that no run tries; a partial mutation run does not show it). Pass: "no finding".
3. Reading part, by a reader that did not write the text (a fresh agent, read only; give it the scope, the truth sources and the list below, not your own opinion of the state). It reads all files completely and reports each contradiction with file, line, claim, truth and source. Look for:
   - the same fact with two values in two places (goal counts, sizes, counts of tests, vectors, loops, functions, errors, timing and protocol constants, versions);
   - a statement of what a contract says or does not say, against the real `requires` / `assigns` / `ensures`;
   - "no contract", "not tested", "has not run", "not yet", "🌱 next" that the code or a later entry contradicts;
   - names of functions, files, macros, runner steps and environment variables that do not exist;
   - an ID that resolves, but to an entry that says something else;
   - a status icon that does not match its own text;
   - `reports/PROTOCOL.md` against what `src/leaf.c` sends and accepts.
4. Check every reported contradiction against the files before any change (a reviewer can be wrong). Correct the documents; if the document states the intent and the code is wrong, that is a bug: fix it with a test, or write a bug report.
5. Run step 2 again after the corrections.

Pass: step 2 without a finding, and no open contradiction from step 3. Limits: the mechanical part knows only the figures listed in the script; the reading part is a review, not a proof, and its yield depends on the reader. Public-repository rules are a separate check (no lab identifiers, no tool names, also in unpushed commits: workspace memory Z-m-50).
