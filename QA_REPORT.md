# SecPatch-DAG QA Report

## Current verification — 18 November 2026

The current checkout passed 140 tests with PostgreSQL 16.2 and built the React production bundle. Migration head is 0003_advisory_check. Optimization compares Greedy, DP and CP-SAT. Maintenance study handles two windows. The graph order view lists cycle-blocked packages separately. The following dated entries document earlier milestones. See [README](README.md) and the [course report](docs/SecPatch-DAA-Report.pdf).


Date: 2026-11-08
Base commit: `23ec874` (Exclude generated TypeScript metadata)

## What was tested

| Area | How |
|---|---|
| Python test suite | `pytest -q` (unit, API, SQLite persistence) |
| PostgreSQL suite | `tests/test_postgresql_*.py` against a fresh PostgreSQL 16 `secpatch_test` database |
| Headless pipeline | Every `diagnostic_datasets` scenario through `ingest_osv` → `approve_candidates` → `run_analysis`, both solvers, windows 0 / 30 / ⅓ total / full total |
| Optimality claims | CP-SAT objective cross-checked against an independent 0/1-knapsack DP on 15 scenario/window pairs (all matched) |
| Graph | All five graphs in `dependency_graph_test_plan.json` (SCC and cycle counts all matched), plus 5,000-node chains |
| Persisted API | Full workflow over HTTP for every scenario: project → environment → assets → inventory → OSV → persisted plans (CP-SAT and greedy) |
| Invalid inputs | Every file in `invalid_inputs/` plus extra cases: string durations, unknown prerequisites, huge numbers, bad IDs |
| Version matching | Multi-branch OSV ranges, unsorted events, `last_affected`, prerelease ordering, multi-package records, name/case variants |
| Dashboard | Headless Chrome: select workspace, upload inventory, OSV and estimates files, run comparison, refresh page, re-run, history, demo workspace, 390px mobile layout |

## Defects found and fixed

Severity: **Critical** = wrong security answer. **High** = a crash or a wrong plan in a normal workflow. **Medium** = a crash on bad input or a setup problem. **Low** = minor.

| # | Severity | Defect | Fix |
|---|---|---|---|
| 1 | Critical | OSV ranges with several `introduced`/`fixed` pairs (separate release branches) were evaluated left to right without sorting. A later `introduced` overwrote the earlier result, so e.g. version 1.2 in `[1.0,1.5) ∪ [2.0,2.3)` was reported **unaffected**. | `version_in_range` rewritten to the OSV-spec algorithm: sort events, walk them, and return the specific fix that closes the installed version's range. |
| 2 | Critical | OSV records listing more than one package used only the first package. The ranges of every package were merged onto it and the other packages were never matched (missed vulnerabilities). | `_parse_record` now yields one record per affected package, with only that package's ranges. |
| 3 | Critical | A range with only `{"fixed": ...}` (no `introduced`; invalid per OSV) made every version look **unaffected**, with no warning (`invalid_inputs/osv_invalid_events.json`). | Now reported as `unknown` with a `range_missing_introduced` issue and a `malformed_range_events` ingestion issue. |
| 4 | High | Package matching was exact-string. `Django` vs `django`, `PyYAML` vs `pyyaml`, `pypi` vs `PyPI` never matched (missed vulnerabilities). | Matching uses PEP 503 name normalization for PyPI and case-insensitive ecosystems. Candidates keep the installed spelling, so persistence finds the stored row. |
| 5 | High | Any record with two fix versions was marked `conflicting_fixed_versions` and could never be planned, even when the installed version clearly sits in one branch. | Each installation gets the fix for its own branch. |
| 6 | High | npm prerelease ordering compared strings, so `1.0.0-rc.10 < 1.0.0-rc.2`. | Implemented SemVer 2.0 §11 identifier comparison. |
| 7 | High | `/persisted-plans` (the path the dashboard uses) skipped all estimate validation: float benefits were accepted and persisted (`estimate_float_benefit.json` returned 200), string durations crashed with 503, and unknown prerequisites crashed with 503 (KeyError). | Persisted actions now go through `Dataset.from_dict`, the same validation as the CLI. All of these return 422. |
| 8 | High | `/persisted-plans` did not check applicability or the fixed version itself. It relied only on `unresolved_issues`. | Same rule as `approve_candidates`: affected, has a fix, no issues. The response now includes `estimate_review` listing ignored estimates and the reason. |
| 9 | High | Dashboard: after a page refresh or environment switch, the candidate list was gone. "Run comparison" then sent a placeholder key (`asset-api:OSV-DEMO-2026-0001`) and returned an empty plan without an error. | New `GET /api/v1/environments/{id}/candidates`. The dashboard reloads candidates on environment select and shows an error instead of a fake key. |
| 10 | High | Dashboard applied one duration/benefit to every candidate, so dataset estimate files could not be used and greedy vs CP-SAT could not differ in the UI. | Added an "Estimates file" upload on the Optimization page (e.g. `approved_estimates.json`) and a numeric window input (the slider stopped at 240). |
| 11 | Medium | The backend and Alembic never read `.env` (only the tests did). Following the README, `alembic upgrade head` connected as the placeholder `secpatch` user and failed. | `database_url()` loads the project-root `.env`; real environment variables still take precedence. |
| 12 | Medium | A new SQLAlchemy engine (and connection pool) was created for every API request. | One cached engine per URL. |
| 13 | Medium | An asset with several installed versions of a package could have its candidate linked to the wrong (unaffected) version row, and two affected versions produced duplicate candidate keys. | Matching uses `version_key`, and one candidate/action per asset+vulnerability with the highest required fix. |
| 14 | Medium | Persisted analysis loaded **all** dependency edges in the database. One edge involving a package from another environment made every analysis in every other environment fail ("unknown package"). | Edges are filtered to the environment's packages. |
| 15 | Medium | Recursive prerequisite checks hit `RecursionError` on chains of about 1,000 actions, and Tarjan was recursive too. | Greedy closure, cycle check and Tarjan SCC are iterative. |
| 16 | Medium | Huge numbers (e.g. a window of 2⁶³) crashed CP-SAT with a TypeError. There was also no solver time limit. | Durations, benefits and window are capped at 10⁹. CP-SAT has a 30 s limit and still reports FEASIBLE/UNKNOWN honestly. |
| 17 | Low | Creating an environment for a non-existent project returned 503 instead of 404. | Returns 404. |
| 18 | Low | `mandatory: "false"` (a string) was treated as `true`. | Must be a JSON boolean. |
| 19 | Low | `test_baseline_inventory_preserves_multiple_packages_per_asset` looked for the dataset outside the repo, so it was always skipped. | Points to `diagnostic_datasets/`. It runs and passes now. |
| 20 | Low | `/favicon.ico` 404 in the browser console. | Inline empty favicon. |
| 21 | Medium | `tests/postgresql_support.py` caught `pytest.SkipTest`, which does not exist in pytest 9. Any connection failure crashed all 6 PostgreSQL tests with `AttributeError` instead of skipping with a reason, and a wrong-database failure was converted into a silent skip. | Catches `pytest.skip.Exception` / `pytest.fail.Exception`. Connection failures skip with a message; a wrong database fails loudly. |
| 22 | Medium | Dashboard: "Run comparison" did nothing at all when no project/environment was selected, and any error appeared only in the banner at the top of the page, out of view when the user was scrolled down on the Optimization page. Found during user testing. | Shows "Select a project and an environment…" and scrolls to the error banner whenever an error occurs. |
| 23 | Low | Dashboard schedule timeline used raw minutes as CSS percentages, so with windows over 100 minutes the bars ran past the track and covered the action names. Deferred lists with ~90 IDs flooded the result cards. Found during user testing. | Bars are scaled to the maintenance window; deferred lists show a count and the first 8 IDs. |
| 24 | Low | Dependency graph: edges ended at node centres, so arrowheads were hidden under the target node and direction was unreadable; cycle members were labelled "blocked downstream" instead of "SCC / cycle"; the demo workspace had no cycle, so Tarjan could not be shown in the UI. Found during user testing. | Edges are clipped to node borders (two-way edges offset), solid lines as the legend says, cycle label takes priority, and the demo adds a `billing ↔ ledger` cycle that blocks `payments`. |
| 25 | High | The same external identifier could be registered twice in one environment (found by registering `asset-api-prod` twice in the UI). Inventory is matched to assets by that identifier, so every later import became ambiguous. | Registration and rename reject duplicate identifiers (and duplicate asset names) with 409 and a clear message. |
| 26 | Medium | Reusing a project, environment or asset name returned 503 with the raw SQL statement and constraint names in the message, shown to the user in the dashboard (information disclosure). | Duplicates are checked first and return 409 with a plain message; any remaining database uniqueness error is mapped to a generic 409 without SQL. |
| 27 | Medium | Importing OSV before inventory silently produced 0 candidates with no explanation. | The dashboard explains that inventory must be imported first. |
| 28 | Low | Uploading a non-JSON file showed a raw JavaScript parser error. | Shows "<file> is not a valid JSON file". |
| 29 | Low | When creating a project/environment/asset failed, the error banner was drawn behind the form's overlay, so the user could not see why. | Error banner is sticky at the top and drawn above overlays. |
| 30 | High | After creating an environment, the environment dropdown was never refreshed: it kept showing "Select environment" with no options, so new environments could not be seen or switched to until the project was re-selected. Found during user testing. | The environment list is reloaded after creation; the new environment is shown selected. |
| 31 | Low | "+ New environment" was disabled without any explanation when no project was selected, yet still highlighted on hover, so it looked broken. Found during user testing. | The button explains "Select or create a project first. Every environment belongs to a project." |

`tests/test_qa_regressions.py` adds 26 tests for these defects. 17 of them fail on the original commit; the other 7 lock in behaviour that was already correct.

## Results after fixes

- Python suite: **102 passed**, 0 skipped (was 63 passed, 1 skipped)
- PostgreSQL suite: **6 passed**
- Frontend production build: passed
- Core CLI (`small.json`, CP-SAT, 120 min): OPTIMAL, valid; ingestion CLI objective 90 (unchanged)
- Baseline dataset: 10 inventory rows, 6 candidates (5 affected, 1 unknown), 5 actions, as the manifest expects
- All six scenarios produce identical candidate counts through the CLI and the HTTP API
- CP-SAT matched the independent DP optimum in 15/15 checks; greedy is never above it
- Dashboard with `baseline/approved_estimates.json`, 60 min: greedy 149 (FEASIBLE, not proven) vs CP-SAT 162 (OPTIMAL, proven), the same as headless
- No horizontal overflow at 390 px

## Known limitations (not changed)

- Greedy and the Smith-ratio scheduler are heuristics by design.
- (Resolved 2026-11-17: dependency edges can now be imported from the dashboard, and re-importing the same OSV file was confirmed not to duplicate candidates. See the last section.)

## User-style UI test (added 2026-11-08)

A full browser run using only the dashboard (forms, uploads, buttons), including common mistakes: running with nothing selected, empty and duplicate names, inventory before assets, OSV before inventory, a non-JSON file, a duplicate asset identifier, importing the same inventory twice, an estimates file with a decimal benefit, window 0, the baseline plan (149 vs 162), all three exports, overview, history, refresh and re-run, the graph tab and switching projects. Defects 25-29 were found this way; after the fixes every step behaves as expected and the page logs no errors.

## Added: dynamic-programming optimizer (2026-11-08)

The CCP requires two course paradigms. The project implemented greedy
selection and Smith's (greedy) ordering, and used CP-SAT, an external solver,
for exact answers; the dynamic-programming knapsack from the original proposal
was missing. `dp_optimize` (`core/optimization.py`) adds it:

- 0/1 knapsack DP with backtracking (no prerequisites), O(n·W).
- Tree knapsack DP when prerequisites form a forest, O(n·W²).
- Mandatory actions are forced first; blocked actions and their dependents are excluded.
- General prerequisite graphs, or tables beyond the size caps, return `NOT_APPLICABLE` instead of a wrong answer.

It is available as method `dynamic_programming` in the API, CLI and dashboard
(the comparison now shows Greedy, Dynamic programming and CP-SAT). It matched
brute force on 1,220 random instances and matched CP-SAT on every diagnostic
dataset (baseline 162, non_optimized 573, large_inventory 2775, outliers 162,
dirty 81, adversarial 389, small.json 370).

## Added: greedy as a ½-approximation (2026-11-08)

Plain ratio greedy has no quality guarantee (window 100, A = 1 min / 2, B = 100
min / 100: it returns 2 instead of 100). `greedy_optimize` now also checks the
single most valuable action that fits (with its prerequisites) and keeps the
better plan. For knapsack without prerequisites or mandatory actions this is a
proven ½-approximation: OPT ≤ fractional OPT ≤ greedy prefix + next item ≤
greedy + best single, so max(greedy, best single) ≥ OPT / 2. Demo numbers are
unchanged (baseline 149, non_optimized 518, large_inventory 2775); baseline at
30 minutes improves from 68 to 81. Verified against brute force on 600 random
instances (`tests/test_dynamic_programming.py`).

## Added: edit servers from the dashboard (2026-11-08)

The backend already supported `PATCH /api/v1/assets/{id}`, but the dashboard
had no way to call it. Each server card now has an **Edit** button that opens
the registration form pre-filled (name, external identifier, operating
system). Duplicate identifiers are rejected as on registration; inventory and
candidates stay linked to the server after an identifier change. Deletion is
intentionally not offered: all foreign keys are `RESTRICT` to preserve the
audit trail of past analyses.

## Added: input validation audit (2026-11-17)

Every API field was probed with blank, whitespace-only, oversized, wrong-type and control-character values, plus very large bodies and lists. Scripts: `validate_probe*.py` (QA workspace). Regression tests: `tests/test_input_validation.py`.

| # | Severity | Problem found | Fix |
|---|---|---|---|
| 32 | High | Inventory rows with a version over 200 characters, an ecosystem over 80, a numeric version or a NUL byte caused a 500 or dropped the connection. | Every inventory field is checked before it reaches the database. The import is all-or-nothing and names the first bad row ("Inventory entry 3 (srv-web): version must be at most 200 characters"). |
| 33 | High | A NUL byte in a project name, or a server identifier/OS longer than the column, returned a 503 whose text included the SQL statement (information disclosure). | Names, identifiers and OS are validated (length, blank, control characters). Database errors are logged on the server and the client gets a generic message. A catch-all handler returns "Something went wrong on the server" instead of a stack trace. |
| 34 | High | OSV records with an ID over 255 characters or a range version over 200 crashed the import with a 500. | A bad ID skips that record with a `malformed_record` issue. A bad range version drops that range (`malformed_range_events`), and the candidate goes to REVIEW rather than guessing a fix. |
| 35 | Medium | Whitespace-only names were accepted, and "Bank " was a different project from "Bank". | Names and identifiers are trimmed and must not be blank, so near-duplicates now hit the existing duplicate check (409). |
| 36 | Medium | A blank external identifier was accepted, and several servers could share it. Inventory is matched by this identifier. | The identifier may be omitted but never blank. |
| 37 | Medium | A 2 MB description and 3 MB of server metadata were stored. | Description is capped at 2,000 characters; metadata at 10 KB of JSON. |
| 38 | Medium | 20,000 OSV records took over 120 s and tied up the server (denial of service); 50,000+ inventory rows and a 1 MB estimate key were accepted. | Limits: 5,000 OSV records, 20,000 inventory rows, 10,000 estimates, 600-character estimate keys, 25 MB request body (413). |
| 39 | Medium | CSV exports wrote cell values as they were. A package or action ID starting with `=`, `+`, `-` or `@` would run as a formula when the file is opened in Excel (CSV injection). | Such cells are prefixed with `'` so spreadsheets show them as text. |
| 40 | Low | When the server rejected a form field, the error banner showed "[object Object]". | Field errors are shown as readable text, e.g. "Project name cannot be blank". Form inputs also have `maxLength` matching the server limits. |
| 41 | Low | Editing a server and clearing the OS field did not clear it; edits also resent every field. | Edits send only the fields that changed, and an empty OS clears the stored value. |

Checked and already correct: malformed JSON, `packages`/`vulns` not a list, an unknown solver method, decimal window values, invalid UUIDs, and `<script>` in names (React shows it as text, so no XSS). OSV `summary` text is never stored, so its size is limited only by the request cap.

Results: 126 tests pass (24 new). The user-style browser test still passes end to end (baseline, 60-minute window: 149 / 162 / 162).

## Added: delete, dependency import and clearer labels (2026-11-17)

These came from preparing the demonstration: each was something an examiner could reasonably try and find missing or confusing.

| # | Problem | Change |
|---|---|---|
| 42 | Projects, environments and servers could not be deleted at all. | Delete buttons (with a confirmation dialog) on each server card and in the sidebar. Deleting is a soft delete: the row gets `archived_at`, is renamed so its name and identifier can be reused, and disappears from every list, import and new analysis. Saved plans keep their foreign keys, so History stays complete (audit trail). Deleting a project or environment also hides what is inside it. |
| 43 | Package dependencies had no import path, so the Dependency graph tab always showed 0 edges for a real workspace. Dependency edges were also global, so a test cycle in one workspace would have blocked patches in every other one. | "Import dependencies" button on the Dependency graph tab (`POST /api/v1/dependencies`, `GET /api/v1/environments/{id}/graph`). Edges are stored per environment (migration `0002`). An import replaces the environment's edges, packages are matched like inventory (case, PEP 503), and unknown packages reject the whole file. Sample files: `baseline/dependencies.json` (no cycle: 149 / 162 / 162), `baseline/dependencies_with_cycle.json` (requests and urllib3 form one SCC, both patches are blocked: 94 / 94 / 94), and `adversarial_graph/dependencies.json` (chain, fan-out, two disjoint cycles, a 3-node SCC, a self-loop). |
| 44 | The greedy card showed "FEASIBLE / NOT PROVEN" next to "OPTIMAL", which looked like an error. | Greedy shows "APPROXIMATION" with the guarantee "≥ ½ of the best value". Exact methods show "EXACT, proven optimal". |
| 45 | The window slider stopped at 240 while the number box accepted any value; the API accepted up to 10⁹ minutes, which makes the DP table (actions × window) needlessly large. | Slider and box both go from 0 to 1,440 minutes (24 h); the dashboard API rejects more (the CLI is unchanged). |

Re-importing the same OSV file was retested: the candidate count stays the same (6 stays 6 for the baseline). A regression test now covers it.

Results: 132 tests pass (6 new); PostgreSQL suite passes after `alembic upgrade head`; full browser walkthrough and a new browser test of delete, dependency import, labels and window limits pass with no page errors.

**Existing databases must be migrated once:** `alembic upgrade head`.
