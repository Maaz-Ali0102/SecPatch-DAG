# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

SecPatch-DAG is a vulnerability remediation planning tool (academic DAA project): offline OSV ingestion → installed-package matching → remediation candidates → dependency-graph analysis (Tarjan SCC + Kahn topo sort) → patch selection under a maintenance-window budget (Greedy / DP knapsack / OR-Tools CP-SAT) → prerequisite-aware scheduling → PostgreSQL persistence → React dashboard. It plans only; it never installs patches.

## Commands (Windows / PowerShell, Python ≥ 3.12)

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1; pip install -r requirements.txt
.\.venv\Scripts\alembic.exe upgrade head          # apply migrations (needs DATABASE_URL)
uvicorn backend.main:app --reload                 # API on :8000, Swagger at /docs
cd frontend; npm ci; npm run dev                  # dashboard on :5173
cd frontend; npm run build                        # tsc -b && vite build (the only frontend check)
```

Tests (pytest, `pythonpath = ["."]`, `testpaths = ["tests"]`):

```powershell
.\.venv\Scripts\python.exe -m pytest -q                                   # full suite
.\.venv\Scripts\python.exe -m pytest -q tests\test_optimization.py        # one file
.\.venv\Scripts\python.exe -m pytest -q tests\test_core.py -k "name"      # one test
```

PostgreSQL tests (`test_postgresql_*.py`, via `tests/postgresql_support.py`) read `DATABASE_URL` from env or `.env`; they **skip** if unset/unreachable and **fail** unless the connected database is named `secpatch_test`.

Headless runs (no DB):

```powershell
python -m core.cli --input datasets\samples\small.json --window 120 --method cp_sat --output result.json
python -m core.ingestion.cli --osv datasets\samples\osv_offline.json --inventory datasets\samples\inventory_offline.json --estimates datasets\samples\approved_estimates.json --window 30 --output out.json
python -m core.cep          # two-window CEP experiment (datasets/cep/worked.json, windows 18 13 → benefits 82/78/71)
python load_dataset.py <dataset> <window>   # loads a diagnostic_datasets scenario through the running API
```

## Architecture

Layered; dependencies point inward:

- `core/` — pure, DB-free engine. `models.py` (PatchAction etc.), `graph.py` (Tarjan SCC, Kahn on the condensation, cycle-blocked nodes), `optimization.py` (`greedy_optimize`, `dp_optimize`, `cp_sat_optimize`), `scheduling.py` (Smith's ratio rule over ready actions), `validation.py` (plan checks), `engine.py` (`run_analysis` ties these together), `maintenance.py` (exact two-window assignment; each patch goes wholly to one window), `cep.py`.
- `core/ingestion/` — OSV + inventory parsing, version matching (`versioning.py`: PyPI/PEP 440 and npm strict SemVer only; anything else becomes an ingestion issue/unknown applicability, never a fabricated match), `limits.py` for input size caps.
- `infrastructure/database/` — SQLAlchemy models, session, repositories. Schema changes need an Alembic migration in `migrations/versions/` (head: `0003_advisory_check`).
- `application/persistence.py` — orchestration between API and DB/core (persisted plans, analysis runs, estimate review).
- `backend/main.py` — FastAPI app, all `/api/v1/...` routes and request validation.
- `frontend/src/` — React + Vite + TS dashboard (`main.tsx`, `MaintenanceStudy.tsx`); uses real API responses, no mock metrics.

Invariants the code and tests rely on:

- Only CP-SAT status `OPTIMAL` sets `optimality_proven = true`; greedy always reports `FEASIBLE`. Don't overclaim optimality.
- DP handles independent actions (0/1 knapsack) and forest-shaped prerequisites (tree knapsack); for general prerequisite graphs (an action with ≥2 prerequisites) it returns `NOT_APPLICABLE` and CP-SAT is used. `tests/test_dynamic_programming.py` cross-checks DP vs brute force and CP-SAT.
- Greedy's ½-approximation (better of ratio plan and best single item) holds only for plain knapsack.
- Packages in a cyclic SCC are reported as blocked, not scheduled.
- Estimate keys are `<asset external_identifier>:<OSV id>`; `duration_minutes` positive int, `benefit` non-negative int. Missing/invalid estimates produce no actions (reported in `estimate_review`).
- Dependency imports (`{"dependencies":[{"from":"PyPI:a","to":"PyPI:b"}]}`, `from` depends on `to`) replace the environment's edges.

## Data

- `datasets/` — small samples and the CEP fixture.
- `diagnostic_datasets/` — supplied immutable QA scenarios. **Do not edit these files**; add separate fixtures if new cases are needed.
- `.env` holds `DATABASE_URL` (see `.env.example`); never commit it.
- `PROJECT_STATUS.md`, `QA_REPORT.md`, and `docs/` hold project status/report material.
