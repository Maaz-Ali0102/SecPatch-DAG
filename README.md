# SecPatch-DAG

SecPatch-DAG is a vulnerability remediation planning platform for teams that
need an explainable, dependency-aware answer to a practical question:

> Which security fixes can be completed in a constrained maintenance window,
> in what order, and with what evidence?

It combines real offline OSV vulnerability ingestion, installed-package
matching, remediation-action generation, dependency-graph analysis,
dependency-aware scheduling, Greedy and CP-SAT optimization, PostgreSQL
persistence, and a React operations dashboard.

SecPatch-DAG is a planning and decision-support system. It does not install
patches or modify production machines.

## Product workflow

```text
Project + environment
        |
        v
Asset registration
        |
        v
Installed inventory ingestion
        |
        v
OSV vulnerability ingestion
        |
        v
Applicability matching
        |
        v
Remediation candidates
        |
        v
Approved estimates -> PatchAction objects
        |
        v
Dependency graph + SCC analysis
        |
        v
Greedy / CP-SAT optimization
        |
        v
Prerequisite-aware schedule and validation
        |
        v
Persisted plan, history, and exports
```

## What the algorithms do

### Tarjan strongly connected components

Tarjan's algorithm identifies cycles in the package dependency graph in
`O(V + E)` time and `O(V)` auxiliary space. Cyclic strongly connected
components are surfaced as reviewable graph states, and packages blocked by a
cycle are marked as blocked rather than silently scheduled.

### Topological sorting

Kahn's algorithm produces a prerequisite-first order when the dependency graph
is acyclic. If cycles prevent a valid ordering, the API reports that condition
instead of inventing an order.

### Precedence-greedy

The greedy optimizer selects feasible actions according to deterministic
priority/benefit rules while respecting prerequisites and the maintenance
window. It reports `FEASIBLE`; it never claims that its result is globally
optimal.

### CP-SAT

The CP-SAT model solves the precedence-constrained selection problem using
integer durations, benefits, prerequisite relationships, mandatory-action
constraints, and the maintenance-window limit. `OPTIMAL` is the only solver
status that sets `optimality_proven` to `true`; `FEASIBLE`, `INFEASIBLE`, and
unknown states are represented honestly.

## Architecture

```text
React + Vite dashboard
          |
          v
FastAPI validation and API contracts
          |
          v
Application persistence/orchestration
       /                 \
      v                   v
Headless Python core   SQLAlchemy + Alembic
                      PostgreSQL 18
```

The `core` package is independent of FastAPI, React, and PostgreSQL. It can be
run through the CLI and tested directly without database services.

Important separation rules:

- Package dependency edges use `dependent -> prerequisite`.
- Package dependencies and patch-action prerequisites are different relations.
- Inventory identity is `asset_id + ecosystem + package name + version`.
- Missing inventory versions remain unknown; the system does not guess.
- Only an affected candidate with a fixed version, no unresolved issues, and
  an explicitly supplied valid estimate becomes a `PatchAction`.
- Historical analysis runs persist immutable input and result snapshots.

## Repository layout

```text
core/                         Headless models, ingestion, graph, scheduling,
                              validation, optimization, and CLI
application/                  Persistence and orchestration services
backend/                      FastAPI application and API endpoints
infrastructure/database/      SQLAlchemy models, repositories, and sessions
migrations/                   Alembic migrations
frontend/                     React/Vite dashboard
datasets/samples/              Small offline demonstration fixtures
diagnostic_datasets/           Immutable diagnostic scenarios and manifests
tests/                        Unit, API, persistence, and PostgreSQL tests
```

## Input contracts

### Inventory JSON

Upload a JSON object with a top-level `packages` array. The `asset_id` must
match the registered asset's external identifier.

```json
{
  "packages": [
    {
      "asset_id": "asset-api-prod",
      "ecosystem": "PyPI",
      "name": "requests",
      "version": "2.27.0"
    }
  ]
}
```

Multiple packages and multiple versions per asset are supported. Exact
duplicates are rejected. Omit `version` only when the installed version is
genuinely unknown.

### OSV JSON

Upload a JSON object with a top-level `vulns` array using the OSV structure:

```json
{
  "vulns": [
    {
      "id": "OSV-EXAMPLE-0001",
      "affected": [
        {
          "package": {
            "ecosystem": "PyPI",
            "name": "requests"
          },
          "ranges": [
            {
              "type": "ECOSYSTEM",
              "events": [
                { "introduced": "2.0.0" },
                { "fixed": "2.28.0" }
              ]
            }
          ]
        }
      ]
    }
  ]
}
```

Supported version schemes are conservative: PyPI/PEP 440 and npm/strict
SemVer. Unsupported or malformed versions become structured ingestion issues
and unknown applicability rather than fabricated matches.

### Estimate input

Estimate keys must use the candidate key:

```text
<asset external_identifier>:<OSV vulnerability id>
```

For example:

```json
{
  "asset-api-prod:OSV-EXAMPLE-0001": {
    "duration_minutes": 22,
    "benefit": 68,
    "priority": 68,
    "risk": "medium"
  }
}
```

`duration_minutes` must be a positive integer and `benefit` must be a
non-negative integer. Missing or invalid estimates do not create fabricated
actions.

## Running locally

### Backend and database

Create a virtual environment and install Python dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Copy `.env.example` to `.env` and set a local PostgreSQL connection string.
`.env` is ignored and must never be committed.

Apply migrations:

```powershell
.\.venv\Scripts\alembic.exe upgrade head
```

Start the API:

```powershell
uvicorn backend.main:app --reload
```

Swagger UI is available at `http://127.0.0.1:8000/docs`.

### Frontend

In another terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open `http://127.0.0.1:5173`.

## Dashboard workflow

1. Create or select a project.
2. Create or select an environment.
3. Register assets with external identifiers.
4. Import inventory JSON.
5. Import OSV JSON and review candidates/issues.
6. Open the dependency graph after dependency data is available.
7. Enter the maintenance window and estimate values.
8. Run the Greedy/CP-SAT comparison.
9. Review selected, deferred, blocked, and scheduled actions.
10. Inspect analysis history and export JSON/CSV results.

The dashboard uses real API responses. It does not replace backend results with
mock metrics.

## CLI usage

Run the headless core without PostgreSQL:

```powershell
.\.venv\Scripts\python.exe -m core.cli `
  --input datasets\samples\small.json `
  --window 120 `
  --method cp_sat `
  --output result.json
```

Run offline vulnerability ingestion:

```powershell
.\.venv\Scripts\python.exe -m core.ingestion.cli `
  --osv datasets\samples\osv_offline.json `
  --inventory datasets\samples\inventory_offline.json `
  --estimates datasets\samples\approved_estimates.json `
  --window 30 `
  --output ingestion-result.json
```

## Testing and verification

Run the complete Python suite:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Run PostgreSQL-backed tests:

```powershell
.\.venv\Scripts\python.exe -m pytest -q `
  tests\test_postgresql_integration.py `
  tests\test_postgresql_api.py
```

Build the frontend:

```powershell
cd frontend
npm run build
```

Current verification baseline:

- Full Python suite: 64 passed
- PostgreSQL integration/API suite: 6 passed
- Frontend production build: passed
- Supplied baseline diagnostic dataset: 10 inventory rows, 6 vulnerability
  candidates, 5 eligible candidates, and 5 generated actions
- Greedy reports `FEASIBLE` without an optimality claim
- CP-SAT reports `OPTIMAL` with proven optimality on the verified baseline run

## Diagnostic datasets

The `diagnostic_datasets/` directory contains the supplied immutable diagnostic
scenarios, manifests, invalid-input cases, estimates, and graph test plan.
They are included for reproducible academic and QA verification. Do not edit
the original scenario files; create separate supplementary fixtures when
additional testing is required.

## Persistence and API surface

The main persisted endpoints are:

- `POST/PATCH /api/v1/projects`
- `POST/PATCH /api/v1/environments`
- `POST /api/v1/assets`
- `POST /api/v1/inventory`
- `GET /api/v1/assets/{asset_id}/inventory`
- `POST /api/v1/vulnerabilities/import`
- `POST /api/v1/persisted-plans`
- `GET /api/v1/projects/{project_id}/analysis-runs`
- `GET /api/v1/analysis-runs/{run_id}`

PostgreSQL stores projects, environments, assets, packages, installed
inventory, vulnerabilities, remediation candidates, analysis runs, patch
actions, prerequisites, patch plans, and normalized schedule rows. JSONB
snapshots preserve historical input and result evidence.

## Scope and limitations

- This is a local academic demonstration and planning product.
- Authentication, authorization, multi-tenancy, and remote deployment are out
  of scope.
- Dependency-edge creation is currently an internal/database workflow rather
  than a complete user-facing import flow.
- Estimate files are supported by the headless ingestion CLI; the dashboard
  currently provides estimate controls rather than a separate estimate-file
  upload screen.
- The product proposes remediation plans; it does not install patches.

## License

This repository is prepared as an academic software project. Add the
institution-approved license before redistributing it publicly.
